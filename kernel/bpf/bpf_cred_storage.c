// SPDX-License-Identifier: GPL-2.0

#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <linux/bpf_lsm.h>
#include <linux/cred.h>
#include <linux/btf_ids.h>
#include <linux/rcupdate_trace.h>

DEFINE_BPF_STORAGE_CACHE(cred_cache);

static struct bpf_local_storage __rcu **cred_storage_ptr(void *owner)
{
	struct cred *cred = owner;
	struct bpf_storage_blob *bsb;

	bsb = bpf_cred(cred);
	if (!bsb)
		return NULL;
	return &bsb->storage;
}

static struct bpf_local_storage_data *cred_storage_lookup(struct cred *cred,
							  struct bpf_map *map,
							  bool cacheit_lockit)
{
	struct bpf_local_storage *cred_storage;
	struct bpf_local_storage_map *smap;
	struct bpf_storage_blob *bsb;

	bsb = bpf_cred(cred);
	if (!bsb)
		return NULL;

	cred_storage = rcu_dereference_check(bsb->storage, bpf_rcu_lock_held());
	if (!cred_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(cred_storage, smap, cacheit_lockit);
}

void bpf_cred_storage_free(struct cred *cred)
{
	struct bpf_local_storage *local_storage;
	struct bpf_storage_blob *bsb;

	bsb = bpf_cred(cred);
	if (!bsb)
		return;

	migrate_disable();
	rcu_read_lock();

	local_storage = rcu_dereference(bsb->storage);
	if (!local_storage)
		goto out;

	bpf_local_storage_destroy(local_storage);
out:
	rcu_read_unlock();
	migrate_enable();
}

static int cred_storage_delete(struct cred *cred, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = cred_storage_lookup(cred, map, false);
	if (!sdata)
		return -ENOENT;

	bpf_selem_unlink(SELEM(sdata), false);

	return 0;
}

static struct bpf_map *cred_storage_map_alloc(union bpf_attr *attr)
{
	return bpf_local_storage_map_alloc(attr, &cred_cache, false);
}

static void cred_storage_map_free(struct bpf_map *map)
{
	bpf_local_storage_map_free(map, &cred_cache, NULL);
}

static int notsupp_get_next_key(struct bpf_map *map, void *key,
				void *next_key)
{
	return -ENOTSUPP;
}

const struct bpf_map_ops cred_storage_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = cred_storage_map_alloc,
	.map_free = cred_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_mem_usage = bpf_local_storage_map_mem_usage,
	.map_btf_id = &bpf_local_storage_map_btf_id[0],
	.map_owner_storage_ptr = cred_storage_ptr,
};

BTF_ID_LIST_SINGLE(bpf_cred_storage_btf_ids, struct, cred)

__bpf_kfunc struct bpf_local_storage_data *bpf_cred_storage_get(struct bpf_map *map,
								struct cred *cred,
								void *init,
								int init__sz,
								u64 flags)
{
	struct bpf_local_storage_data *sdata;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return NULL;

	if (!cred || !cred_storage_ptr(cred))
		return NULL;

	sdata = cred_storage_lookup(cred, map, true);
	if (sdata)
		return sdata;

	/* This helper must only called from where the cred is guaranteed
	 * to have a refcount and cannot be freed.
	 */
	if (flags & BPF_LOCAL_STORAGE_GET_F_CREATE) {
		sdata = bpf_local_storage_update(
			cred, (struct bpf_local_storage_map *)map, init,
			BPF_NOEXIST, false, GFP_ATOMIC);
		return IS_ERR(sdata) ? NULL : sdata;
	}

	return NULL;
}

__bpf_kfunc int bpf_cred_storage_delete(struct bpf_map *map, struct cred *cred)
{
	if (!cred)
		return -EINVAL;

	return cred_storage_delete(cred, map);
}

BTF_KFUNCS_START(bpf_cred_storage_kfunc_ids)
BTF_ID_FLAGS(func, bpf_cred_storage_delete, 0)
BTF_ID_FLAGS(func, bpf_cred_storage_get, KF_RET_NULL)
BTF_KFUNCS_END(bpf_cred_storage_kfunc_ids)

static const struct btf_kfunc_id_set bpf_cred_storage_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_cred_storage_kfunc_ids,
};

static int __init bpf_cred_storage_init(void)
{
	int err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &bpf_cred_storage_kfunc_set);
	if (err) {
		pr_err("bpf_cred_storage: failed to register kfuncs: %d\n", err);
		return err;
	}

	pr_info("bpf_cred_storage: kfuncs registered successfully\n");
	return 0;
}
late_initcall(bpf_cred_storage_init);
