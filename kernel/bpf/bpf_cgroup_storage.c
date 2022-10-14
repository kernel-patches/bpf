// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <uapi/linux/btf.h>
#include <linux/btf_ids.h>

DEFINE_BPF_STORAGE_CACHE(cgroup_cache);

static DEFINE_PER_CPU(int, bpf_cgroup_storage_busy);

static void bpf_cgroup_storage_lock(void)
{
	migrate_disable();
	this_cpu_inc(bpf_cgroup_storage_busy);
}

static void bpf_cgroup_storage_unlock(void)
{
	this_cpu_dec(bpf_cgroup_storage_busy);
	migrate_enable();
}

static bool bpf_cgroup_storage_trylock(void)
{
	migrate_disable();
	if (unlikely(this_cpu_inc_return(bpf_cgroup_storage_busy) != 1)) {
		this_cpu_dec(bpf_cgroup_storage_busy);
		migrate_enable();
		return false;
	}
	return true;
}

static struct bpf_local_storage __rcu **cgroup_storage_ptr(void *owner)
{
	struct cgroup *cg = owner;

	return &cg->bpf_cgroup_storage;
}

void bpf_local_cgroup_storage_free(struct cgroup *cgroup)
{
	struct bpf_local_storage *local_storage;
	struct bpf_local_storage_elem *selem;
	bool free_cgroup_storage = false;
	struct hlist_node *n;
	unsigned long flags;

	rcu_read_lock();
	local_storage = rcu_dereference(cgroup->bpf_cgroup_storage);
	if (!local_storage) {
		rcu_read_unlock();
		return;
	}

	/* Neither the bpf_prog nor the bpf-map's syscall
	 * could be modifying the local_storage->list now.
	 * Thus, no elem can be added-to or deleted-from the
	 * local_storage->list by the bpf_prog or by the bpf-map's syscall.
	 *
	 * It is racing with bpf_local_storage_map_free() alone
	 * when unlinking elem from the local_storage->list and
	 * the map's bucket->list.
	 */
	bpf_cgroup_storage_lock();
	raw_spin_lock_irqsave(&local_storage->lock, flags);
	hlist_for_each_entry_safe(selem, n, &local_storage->list, snode) {
		bpf_selem_unlink_map(selem);
		free_cgroup_storage =
			bpf_selem_unlink_storage_nolock(local_storage, selem, false, false);
	}
	raw_spin_unlock_irqrestore(&local_storage->lock, flags);
	bpf_cgroup_storage_unlock();
	rcu_read_unlock();

	/* free_cgroup_storage should always be true as long as
	 * local_storage->list was non-empty.
	 */
	if (free_cgroup_storage)
		kfree_rcu(local_storage, rcu);
}

static struct bpf_local_storage_data *
cgroup_storage_lookup(struct cgroup *cgroup, struct bpf_map *map, bool cacheit_lockit)
{
	struct bpf_local_storage *cgroup_storage;
	struct bpf_local_storage_map *smap;

	cgroup_storage = rcu_dereference_check(cgroup->bpf_cgroup_storage,
					       bpf_rcu_lock_held());
	if (!cgroup_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(cgroup_storage, smap, cacheit_lockit);
}

static void *bpf_cgroup_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct cgroup *cgroup;
	int fd;

	fd = *(int *)key;
	cgroup = cgroup_get_from_fd(fd);
	if (IS_ERR(cgroup))
		return ERR_CAST(cgroup);

	bpf_cgroup_storage_lock();
	sdata = cgroup_storage_lookup(cgroup, map, true);
	bpf_cgroup_storage_unlock();
	cgroup_put(cgroup);
	return sdata ? sdata->data : NULL;
}

static int bpf_cgroup_storage_update_elem(struct bpf_map *map, void *key,
					  void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	struct cgroup *cgroup;
	int err, fd;

	fd = *(int *)key;
	cgroup = cgroup_get_from_fd(fd);
	if (IS_ERR(cgroup))
		return PTR_ERR(cgroup);

	bpf_cgroup_storage_lock();
	sdata = bpf_local_storage_update(cgroup, (struct bpf_local_storage_map *)map,
					 value, map_flags, GFP_ATOMIC);
	bpf_cgroup_storage_unlock();
	err = PTR_ERR_OR_ZERO(sdata);
	cgroup_put(cgroup);
	return err;
}

static int cgroup_storage_delete(struct cgroup *cgroup, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = cgroup_storage_lookup(cgroup, map, false);
	if (!sdata)
		return -ENOENT;

	bpf_selem_unlink(SELEM(sdata), true);
	return 0;
}

static int bpf_cgroup_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct cgroup *cgroup;
	int err, fd;

	fd = *(int *)key;
	cgroup = cgroup_get_from_fd(fd);
	if (IS_ERR(cgroup))
		return PTR_ERR(cgroup);

	bpf_cgroup_storage_lock();
	err = cgroup_storage_delete(cgroup, map);
	bpf_cgroup_storage_unlock();
	if (err)
		return err;

	cgroup_put(cgroup);
	return 0;
}

static int notsupp_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -ENOTSUPP;
}

static struct bpf_map *cgroup_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_local_storage_map *smap;

	smap = bpf_local_storage_map_alloc(attr);
	if (IS_ERR(smap))
		return ERR_CAST(smap);

	smap->cache_idx = bpf_local_storage_cache_idx_get(&cgroup_cache);
	return &smap->map;
}

static void cgroup_storage_map_free(struct bpf_map *map)
{
	struct bpf_local_storage_map *smap;

	smap = (struct bpf_local_storage_map *)map;
	bpf_local_storage_cache_idx_free(&cgroup_cache, smap->cache_idx);
	bpf_local_storage_map_free(smap, NULL);
}

/* *gfp_flags* is a hidden argument provided by the verifier */
BPF_CALL_5(bpf_cgroup_storage_get, struct bpf_map *, map, struct cgroup *, cgroup,
	   void *, value, u64, flags, gfp_t, gfp_flags)
{
	struct bpf_local_storage_data *sdata;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return (unsigned long)NULL;

	if (!cgroup)
		return (unsigned long)NULL;

	if (!bpf_cgroup_storage_trylock())
		return (unsigned long)NULL;

	sdata = cgroup_storage_lookup(cgroup, map, true);
	if (sdata)
		goto unlock;

	/* only allocate new storage, when the cgroup is refcounted */
	if (!percpu_ref_is_dying(&cgroup->self.refcnt) &&
	    (flags & BPF_LOCAL_STORAGE_GET_F_CREATE))
		sdata = bpf_local_storage_update(cgroup, (struct bpf_local_storage_map *)map,
						 value, BPF_NOEXIST, gfp_flags);

unlock:
	bpf_cgroup_storage_unlock();
	return IS_ERR_OR_NULL(sdata) ? (unsigned long)NULL : (unsigned long)sdata->data;
}

BPF_CALL_2(bpf_cgroup_storage_delete, struct bpf_map *, map, struct cgroup *, cgroup)
{
	int ret;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (!cgroup)
		return -EINVAL;

	if (!bpf_cgroup_storage_trylock())
		return -EBUSY;

	ret = cgroup_storage_delete(cgroup, map);
	bpf_cgroup_storage_unlock();
	return ret;
}

BTF_ID_LIST_SINGLE(cgroup_storage_map_btf_ids, struct, bpf_local_storage_map)
const struct bpf_map_ops cgroup_local_storage_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = cgroup_storage_map_alloc,
	.map_free = cgroup_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_cgroup_storage_lookup_elem,
	.map_update_elem = bpf_cgroup_storage_update_elem,
	.map_delete_elem = bpf_cgroup_storage_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_btf_id = &cgroup_storage_map_btf_ids[0],
	.map_owner_storage_ptr = cgroup_storage_ptr,
};

const struct bpf_func_proto bpf_cgroup_storage_get_proto = {
	.func		= bpf_cgroup_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID,
	.arg2_btf_id	= &bpf_cgroup_btf_id[0],
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_cgroup_storage_delete_proto = {
	.func		= bpf_cgroup_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID,
	.arg2_btf_id	= &bpf_cgroup_btf_id[0],
};
