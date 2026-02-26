// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include <net/bpf_skb_storage.h>

DEFINE_BPF_STORAGE_CACHE(skb_cache);

static int skb_storage_map_alloc_check(union bpf_attr *attr)
{
	/* Don't allow BPF_F_CLONE yet. Requires skb_ext copy on clone. */
	if (attr->map_flags & ~BPF_F_NO_PREALLOC)
		return -EINVAL;

	return bpf_local_storage_map_alloc_check(attr);
}

static struct bpf_map *skb_storage_map_alloc(union bpf_attr *attr)
{
	return bpf_local_storage_map_alloc(attr, &skb_cache, false);
}

static void skb_storage_map_free(struct bpf_map *map)
{
	bpf_local_storage_map_free(map, &skb_cache);
}

static struct bpf_local_storage __rcu **skb_storage_ptr(void *owner)
{
	struct bpf_skb_storage_ext *ext = owner;

	return &ext->storage;
}

static int notsupp_get_next_key(struct bpf_map *map, void *key,
				void *next_key)
{
	return -EOPNOTSUPP;
}

static void *notsupp_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static long notsupp_update_elem(struct bpf_map *map, void *key,
				void *value, u64 flags)
{
	return -EOPNOTSUPP;
}

static long notsupp_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

const struct bpf_map_ops skb_storage_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = skb_storage_map_alloc_check,
	.map_alloc = skb_storage_map_alloc,
	.map_free = skb_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = notsupp_lookup_elem,
	.map_update_elem = notsupp_update_elem,
	.map_delete_elem = notsupp_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_mem_usage = bpf_local_storage_map_mem_usage,
	.map_owner_storage_ptr = skb_storage_ptr,
	.map_btf_id = &bpf_local_storage_map_btf_id[0],
};

static struct bpf_local_storage_data *
skb_storage_lookup(struct sk_buff *skb, struct bpf_map *map, bool cacheit_lockit)
{
	struct bpf_local_storage_map *smap = (typeof(smap))map;
	struct bpf_local_storage *storage;
	struct bpf_skb_storage_ext *ext;

	ext = skb_ext_find(skb, SKB_EXT_BPF_STORAGE);
	if (!ext)
		return NULL;

	storage = rcu_dereference_check(ext->storage, bpf_rcu_lock_held());
	if (!storage)
		return NULL;

	return bpf_local_storage_lookup(storage, smap, cacheit_lockit);
}

void bpf_skb_storage_free(struct bpf_skb_storage_ext *ext)
{
	struct bpf_local_storage *storage;

	rcu_read_lock_dont_migrate();
	storage = rcu_dereference(ext->storage);
	if (storage)
		bpf_local_storage_destroy(storage);
	rcu_read_unlock_migrate();
}

static bool is_skb_storage_shared(const struct sk_buff *skb)
{
	return skb_ext_exist(skb, SKB_EXT_BPF_STORAGE) &&
	       refcount_read(&skb->extensions->refcnt) != 1;
}

__bpf_kfunc_start_defs();

/**
 * bpf_skb_storage_get() - Get or create local storage for an skb
 * @map: BPF map of type BPF_MAP_TYPE_SKB_STORAGE
 * @skb: Socket buffer to get storage for
 * @value: Initial value to set if creating new storage (can be NULL)
 * @flags: BPF_LOCAL_STORAGE_GET_F_CREATE to create if not exists
 *
 * Get the local storage associated with @skb for @map. If @flags contains
 * BPF_LOCAL_STORAGE_GET_F_CREATE and no storage exists, create new storage
 * initialized with @value (or zeroed if @value is NULL).
 *
 * Return: Pointer to storage value on success, NULL on error
 */
__bpf_kfunc void *bpf_skb_storage_get(struct bpf_map *map__map,
				      struct sk_buff *skb,
				      void *value__nullable, u32 value__szk,
				      u64 flags)
{
	struct bpf_local_storage_map *map = (typeof(map))map__map;
	struct bpf_local_storage_data *sdata;
	struct bpf_skb_storage_ext *ext;

	WARN_ON_ONCE(!bpf_rcu_lock_held());

	if (!skb || flags & ~BPF_LOCAL_STORAGE_GET_F_CREATE)
		goto fail; /* EINVAL */
	if (in_hardirq() || in_nmi())
		goto fail; /* EPERM - requires kmalloc_nolock */
	if (skb->cloned && is_skb_storage_shared(skb))
		goto fail; /* EOPNOTSUPP */

	sdata = skb_storage_lookup(skb, map__map, true);
	if (sdata)
		return sdata->data;
	if (!(flags & BPF_LOCAL_STORAGE_GET_F_CREATE))
		goto fail; /* ENOENT */

	ext = skb_ext_find(skb, SKB_EXT_BPF_STORAGE);
	if (!ext) {
		ext = skb_ext_add(skb, SKB_EXT_BPF_STORAGE);
		if (!ext)
			goto fail; /* ENOMEM */
		RCU_INIT_POINTER(ext->storage, NULL);
	}

	sdata = bpf_local_storage_update(ext, map, value__nullable, BPF_NOEXIST,
					 false, GFP_ATOMIC);
	if (IS_ERR(sdata))
		goto fail;

	return sdata->data;
fail:
	return NULL;
}

/**
 * bpf_skb_storage_delete() - Delete local storage for an skb
 * @map: BPF map of type BPF_MAP_TYPE_SKB_STORAGE
 * @skb: Socket buffer to delete storage from
 *
 * Delete the local storage associated with @skb for @map.
 *
 * Return: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpf_skb_storage_delete(struct bpf_map *map__map,
				       struct sk_buff *skb)
{
	struct bpf_local_storage_data *sdata;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (!skb)
		return -EINVAL;
	if (in_hardirq() || in_nmi())
		return -EPERM;
	if (skb->cloned && is_skb_storage_shared(skb))
		return -EOPNOTSUPP;

	sdata = skb_storage_lookup(skb, map__map, false);
	if (!sdata)
		return -ENOENT;

	return bpf_selem_unlink(SELEM(sdata));
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(skb_storage_kfunc_ids)
BTF_ID_FLAGS(func, bpf_skb_storage_get, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_skb_storage_delete)
BTF_KFUNCS_END(skb_storage_kfunc_ids)

static int skb_storage_tracing_kfunc_filter(const struct bpf_prog *prog,
					    u32 kfunc_id)
{
	/* Disabled until verifier can pass gfp_flags to kfuncs */
	if (prog->sleepable)
		return -EACCES;
	/* Allow only progs with trusted pointers */
	if (prog->type != BPF_PROG_TYPE_LSM &&
	    prog->type != BPF_PROG_TYPE_TRACING)
		return -EACCES;
	return 0;
}

static const struct btf_kfunc_id_set skb_storage_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &skb_storage_kfunc_ids,
};

static const struct btf_kfunc_id_set skb_storage_tracing_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &skb_storage_kfunc_ids,
	.filter = skb_storage_tracing_kfunc_filter,
};

static int __init bpf_skb_storage_kfunc_init(void)
{
	int ret = 0;

	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SOCKET_FILTER,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_CGROUP_SKB,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SOCK_OPS,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SK_SKB,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LWT_OUT,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LWT_IN,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LWT_XMIT,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LWT_SEG6LOCAL,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_NETFILTER,
					       &skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					       &skb_storage_kfunc_set);

	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM,
					       &skb_storage_tracing_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					       &skb_storage_tracing_kfunc_set);

	return ret;
}
late_initcall(bpf_skb_storage_kfunc_init);
