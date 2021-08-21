// SPDX-License-Identifier: GPL-2.0

#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <uapi/linux/btf.h>
#include <linux/bpf_lsm.h>
#include <linux/btf_ids.h>

DEFINE_BPF_STORAGE_CACHE(file_cache);

static struct bpf_local_storage __rcu **file_storage_ptr(void *owner)
{
	struct bpf_storage_blob *bsb;
	struct file *file = owner;

	bsb = bpf_file(file);
	if (!bsb)
		return NULL;
	return &bsb->storage;
}

static struct bpf_local_storage_data *
file_storage_lookup(struct file *file, struct bpf_map *map, bool cacheit_lockit)
{
	struct bpf_local_storage *file_storage;
	struct bpf_local_storage_map *smap;
	struct bpf_storage_blob *bsb;

	bsb = bpf_file(file);
	if (!bsb)
		return NULL;

	file_storage = rcu_dereference(bsb->storage);
	if (!file_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(file_storage, smap, cacheit_lockit);
}

void bpf_file_storage_free(struct file *file)
{
	struct bpf_local_storage *local_storage;
	struct bpf_local_storage_elem *selem;
	bool free_file_storage = false;
	struct bpf_storage_blob *bsb;
	struct hlist_node *n;

	bsb = bpf_file(file);
	if (!bsb)
		return;

	rcu_read_lock();

	local_storage = rcu_dereference(bsb->storage);
	if (!local_storage) {
		rcu_read_unlock();
		return;
	}

	raw_spin_lock_bh(&local_storage->lock);
	hlist_for_each_entry_safe(selem, n, &local_storage->list, snode) {
		bpf_selem_unlink_map(selem);
		free_file_storage = bpf_selem_unlink_storage_nolock(local_storage,
								    selem, false);
	}
	raw_spin_unlock_bh(&local_storage->lock);
	rcu_read_unlock();

	if (free_file_storage)
		kfree_rcu(local_storage, rcu);
}

static void *bpf_fd_file_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct file *file;
	int fd;

	fd = *(int *)key;
	file = fget_raw(fd);
	if (!file)
		return ERR_PTR(-EBADF);

	sdata = file_storage_lookup(file, map, true);
	fput(file);
	return sdata ? sdata->data : NULL;
}

static int bpf_fd_file_storage_update_elem(struct bpf_map *map, void *key,
					   void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	struct file *file;
	int fd;

	fd = *(int *)key;
	file = fget_raw(fd);
	if (!file)
		return -EBADF;
	if (!file_storage_ptr(file)) {
		fput(file);
		return -EBADF;
	}

	sdata = bpf_local_storage_update(file,
					 (struct bpf_local_storage_map *)map,
					 value, map_flags);
	fput(file);
	return PTR_ERR_OR_ZERO(sdata);
}

static int file_storage_delete(struct file *file, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = file_storage_lookup(file, map, false);
	if (!sdata)
		return -ENOENT;

	bpf_selem_unlink(SELEM(sdata));

	return 0;
}

static int bpf_fd_file_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct file *file;
	int fd, err;

	fd = *(int *)key;
	file = fget_raw(fd);
	if (!file)
		return -EBADF;

	err = file_storage_delete(file, map);
	fput(file);
	return err;
}

BPF_CALL_4(bpf_file_storage_get, struct bpf_map *, map, struct file *, file,
	   void *, value, u64, flags)
{
	struct bpf_local_storage_data *sdata;

	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return (unsigned long)NULL;

	if (!file || !file_storage_ptr(file))
		return (unsigned long)NULL;

	sdata = file_storage_lookup(file, map, true);
	if (sdata)
		return (unsigned long)sdata->data;

	if (flags & BPF_LOCAL_STORAGE_GET_F_CREATE) {
		sdata = bpf_local_storage_update(
			file, (struct bpf_local_storage_map *)map, value,
			BPF_NOEXIST);
		return IS_ERR(sdata) ? (unsigned long)NULL :
					     (unsigned long)sdata->data;
	}

	return (unsigned long)NULL;
}

BPF_CALL_2(bpf_file_storage_delete, struct bpf_map *, map, struct file *, file)
{
	if (!file)
		return -EINVAL;

	return file_storage_delete(file, map);
}

static int notsupp_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -ENOTSUPP;
}

static struct bpf_map *file_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_local_storage_map *smap;

	smap = bpf_local_storage_map_alloc(attr);
	if (IS_ERR(smap))
		return ERR_CAST(smap);

	smap->cache_idx = bpf_local_storage_cache_idx_get(&file_cache);
	return &smap->map;
}

static void file_storage_map_free(struct bpf_map *map)
{
	struct bpf_local_storage_map *smap;

	smap = (struct bpf_local_storage_map *)map;
	bpf_local_storage_cache_idx_free(&file_cache, smap->cache_idx);
	bpf_local_storage_map_free(smap, NULL);
}

static int file_storage_map_btf_id;

const struct bpf_map_ops file_storage_map_ops = {
	.map_meta_equal        = bpf_map_meta_equal,
	.map_alloc_check       = bpf_local_storage_map_alloc_check,
	.map_alloc             = file_storage_map_alloc,
	.map_free              = file_storage_map_free,
	.map_get_next_key      = notsupp_get_next_key,
	.map_lookup_elem       = bpf_fd_file_storage_lookup_elem,
	.map_update_elem       = bpf_fd_file_storage_update_elem,
	.map_delete_elem       = bpf_fd_file_storage_delete_elem,
	.map_check_btf         = bpf_local_storage_map_check_btf,
	.map_btf_name          = "bpf_local_storage_map",
	.map_btf_id            = &file_storage_map_btf_id,
	.map_owner_storage_ptr = file_storage_ptr,
};

BTF_ID_LIST_SINGLE(bpf_file_storage_btf_ids, struct, file)

const struct bpf_func_proto bpf_file_storage_get_proto = {
	.func        = bpf_file_storage_get,
	.gpl_only    = false,
	.ret_type    = RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type   = ARG_CONST_MAP_PTR,
	.arg2_type   = ARG_PTR_TO_BTF_ID,
	.arg2_btf_id = &bpf_file_storage_btf_ids[0],
	.arg3_type   = ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type   = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_file_storage_delete_proto = {
	.func        = bpf_file_storage_delete,
	.gpl_only    = false,
	.ret_type    = RET_INTEGER,
	.arg1_type   = ARG_CONST_MAP_PTR,
	.arg2_type   = ARG_PTR_TO_BTF_ID,
	.arg2_btf_id = &bpf_file_storage_btf_ids[0],
};
