// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Facebook
 * Copyright 2020 Google LLC.
 */

#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <net/sock.h>
#include <uapi/linux/sock_diag.h>
#include <uapi/linux/btf.h>
#include <linux/bpf_lsm.h>
#include <linux/btf_ids.h>
#include <linux/fdtable.h>
#include <linux/rcupdate_trace.h>

DEFINE_BPF_STORAGE_CACHE(inode_cache);

static DEFINE_PER_CPU(int, bpf_inode_storage_busy);

static void bpf_inode_storage_lock(void)
{
	migrate_disable();
	this_cpu_inc(bpf_inode_storage_busy);
}

static void bpf_inode_storage_unlock(void)
{
	this_cpu_dec(bpf_inode_storage_busy);
	migrate_enable();
}

static bool bpf_inode_storage_trylock(void)
{
	migrate_disable();
	if (unlikely(this_cpu_inc_return(bpf_inode_storage_busy) != 1)) {
		this_cpu_dec(bpf_inode_storage_busy);
		migrate_enable();
		return false;
	}
	return true;
}

static struct bpf_local_storage __rcu **inode_storage_ptr(void *owner)
{
	struct inode *inode = owner;

	return &inode->i_bpf_storage;
}

static struct bpf_local_storage_data *inode_storage_lookup(struct inode *inode,
							   struct bpf_map *map,
							   bool cacheit_lockit)
{
	struct bpf_local_storage *inode_storage;
	struct bpf_local_storage_map *smap;

	inode_storage =
		rcu_dereference_check(inode->i_bpf_storage, bpf_rcu_lock_held());
	if (!inode_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(inode_storage, smap, cacheit_lockit);
}

void bpf_inode_storage_free(struct inode *inode)
{
	struct bpf_local_storage *local_storage;

	rcu_read_lock();

	local_storage = rcu_dereference(inode->i_bpf_storage);
	if (!local_storage) {
		rcu_read_unlock();
		return;
	}

	bpf_inode_storage_lock();
	bpf_local_storage_destroy(local_storage);
	bpf_inode_storage_unlock();
	rcu_read_unlock();
}

static void *bpf_fd_inode_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	CLASS(fd_raw, f)(*(int *)key);

	if (fd_empty(f))
		return ERR_PTR(-EBADF);

	bpf_inode_storage_lock();
	sdata = inode_storage_lookup(file_inode(fd_file(f)), map, true);
	bpf_inode_storage_unlock();
	return sdata ? sdata->data : NULL;
}

static long bpf_fd_inode_storage_update_elem(struct bpf_map *map, void *key,
					     void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	CLASS(fd_raw, f)(*(int *)key);

	if (fd_empty(f))
		return -EBADF;
	if (!inode_storage_ptr(file_inode(fd_file(f))))
		return -EBADF;

	bpf_inode_storage_lock();
	sdata = bpf_local_storage_update(file_inode(fd_file(f)),
					 (struct bpf_local_storage_map *)map,
					 value, map_flags, GFP_ATOMIC);
	bpf_inode_storage_unlock();
	return PTR_ERR_OR_ZERO(sdata);
}

static int inode_storage_delete(struct inode *inode, struct bpf_map *map,
				bool nobusy)
{
	struct bpf_local_storage_data *sdata;

	sdata = inode_storage_lookup(inode, map, false);
	if (!sdata)
		return -ENOENT;

	if (!nobusy)
		return -EBUSY;

	bpf_selem_unlink(SELEM(sdata), false);

	return 0;
}

static long bpf_fd_inode_storage_delete_elem(struct bpf_map *map, void *key)
{
	int err;

	CLASS(fd_raw, f)(*(int *)key);

	if (fd_empty(f))
		return -EBADF;
	bpf_inode_storage_lock();
	err = inode_storage_delete(file_inode(fd_file(f)), map, true);
	bpf_inode_storage_unlock();
	return err;
}

static void *__bpf_inode_storage_get(struct bpf_map *map, struct inode *inode,
				     void *value, u64 flags, gfp_t gfp_flags, bool nobusy)
{
	struct bpf_local_storage_data *sdata;

	/* explicitly check that the inode_storage_ptr is not
	 * NULL as inode_storage_lookup returns NULL in this case and
	 * bpf_local_storage_update expects the owner to have a
	 * valid storage pointer.
	 */
	if (!inode || !inode_storage_ptr(inode))
		return NULL;

	sdata = inode_storage_lookup(inode, map, nobusy);
	if (sdata)
		return sdata->data;

	/* only allocate new storage, when the inode is refcounted */
	if (atomic_read(&inode->i_count) &&
	    flags & BPF_LOCAL_STORAGE_GET_F_CREATE && nobusy) {
		sdata = bpf_local_storage_update(
			inode, (struct bpf_local_storage_map *)map, value,
			BPF_NOEXIST, gfp_flags);
		return IS_ERR(sdata) ? NULL : sdata->data;
	}

	return NULL;
}

/* *gfp_flags* is a hidden argument provided by the verifier */
BPF_CALL_5(bpf_inode_storage_get_recur, struct bpf_map *, map, struct inode *, inode,
	   void *, value, u64, flags, gfp_t, gfp_flags)
{
	bool nobusy;
	void *data;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return (unsigned long)NULL;

	nobusy = bpf_inode_storage_trylock();
	data = __bpf_inode_storage_get(map, inode, value, flags, gfp_flags, nobusy);
	if (nobusy)
		bpf_inode_storage_unlock();
	return (unsigned long)data;
}

/* *gfp_flags* is a hidden argument provided by the verifier */
BPF_CALL_5(bpf_inode_storage_get, struct bpf_map *, map, struct inode *, inode,
	   void *, value, u64, flags, gfp_t, gfp_flags)
{
	void *data;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return (unsigned long)NULL;

	bpf_inode_storage_lock();
	data = __bpf_inode_storage_get(map, inode, value, flags, gfp_flags, true);
	bpf_inode_storage_unlock();
	return (unsigned long)data;
}

BPF_CALL_2(bpf_inode_storage_delete_recur, struct bpf_map *, map, struct inode *, inode)
{
	bool nobusy;
	int ret;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (!inode)
		return -EINVAL;

	nobusy = bpf_inode_storage_trylock();
	/* This helper must only called from where the inode is guaranteed
	 * to have a refcount and cannot be freed.
	 */
	ret = inode_storage_delete(inode, map, nobusy);
	bpf_inode_storage_unlock();
	return ret;
}

BPF_CALL_2(bpf_inode_storage_delete, struct bpf_map *, map, struct inode *, inode)
{
	int ret;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (!inode)
		return -EINVAL;

	bpf_inode_storage_lock();
	/* This helper must only called from where the inode is guaranteed
	 * to have a refcount and cannot be freed.
	 */
	ret = inode_storage_delete(inode, map, true);
	bpf_inode_storage_unlock();
	return ret;
}

static int notsupp_get_next_key(struct bpf_map *map, void *key,
				void *next_key)
{
	return -ENOTSUPP;
}

static struct bpf_map *inode_storage_map_alloc(union bpf_attr *attr)
{
	return bpf_local_storage_map_alloc(attr, &inode_cache, false);
}

static void inode_storage_map_free(struct bpf_map *map)
{
	bpf_local_storage_map_free(map, &inode_cache, NULL);
}

const struct bpf_map_ops inode_storage_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = inode_storage_map_alloc,
	.map_free = inode_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_fd_inode_storage_lookup_elem,
	.map_update_elem = bpf_fd_inode_storage_update_elem,
	.map_delete_elem = bpf_fd_inode_storage_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_mem_usage = bpf_local_storage_map_mem_usage,
	.map_btf_id = &bpf_local_storage_map_btf_id[0],
	.map_owner_storage_ptr = inode_storage_ptr,
};

BTF_ID_LIST_SINGLE(bpf_inode_storage_btf_ids, struct, inode)

const struct bpf_func_proto bpf_inode_storage_get_recur_proto = {
	.func		= bpf_inode_storage_get_recur,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_inode_storage_btf_ids[0],
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_inode_storage_get_proto = {
	.func		= bpf_inode_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_inode_storage_btf_ids[0],
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_inode_storage_delete_recur_proto = {
	.func		= bpf_inode_storage_delete_recur,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_inode_storage_btf_ids[0],
};

const struct bpf_func_proto bpf_inode_storage_delete_proto = {
	.func		= bpf_inode_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_inode_storage_btf_ids[0],
};
