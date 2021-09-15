// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd
 */
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_dummy_ops.h>

static struct bpf_dummy_ops *bpf_dummy_ops_singletion;
static DEFINE_SPINLOCK(bpf_dummy_ops_lock);

static const struct btf_type *dummy_ops_state;

struct bpf_dummy_ops *bpf_get_dummy_ops(void)
{
	struct bpf_dummy_ops *ops;

	spin_lock(&bpf_dummy_ops_lock);
	ops = bpf_dummy_ops_singletion;
	if (ops && !bpf_try_module_get(ops, ops->owner))
		ops = NULL;
	spin_unlock(&bpf_dummy_ops_lock);

	return ops ? ops : ERR_PTR(-ENXIO);
}
EXPORT_SYMBOL_GPL(bpf_get_dummy_ops);

void bpf_put_dummy_ops(struct bpf_dummy_ops *ops)
{
	bpf_module_put(ops, ops->owner);
}
EXPORT_SYMBOL_GPL(bpf_put_dummy_ops);

static int bpf_dummy_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "bpf_dummy_ops_state",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;

	dummy_ops_state = btf_type_by_id(btf, type_id);

	return 0;
}

static const struct bpf_func_proto *
bpf_dummy_ops_get_func_proto(enum bpf_func_id func_id,
			     const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	default:
		return NULL;
	}
}

static bool bpf_dummy_ops_is_valid_access(int off, int size,
					  enum bpf_access_type type,
					  const struct bpf_prog *prog,
					  struct bpf_insn_access_aux *info)
{
	/* a common helper ? */
	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;

	return btf_ctx_access(off, size, type, prog, info);
}

static int bpf_dummy_ops_btf_struct_access(struct bpf_verifier_log *log,
					   const struct btf *btf,
					   const struct btf_type *t, int off,
					   int size, enum bpf_access_type atype,
					   u32 *next_btf_id)
{
	size_t end;

	if (atype == BPF_READ)
		return btf_struct_access(log, btf, t, off, size, atype,
					 next_btf_id);

	if (t != dummy_ops_state) {
		bpf_log(log, "only read is supported\n");
		return -EACCES;
	}

	switch (off) {
	case offsetof(struct bpf_dummy_ops_state, val):
		end = offsetofend(struct bpf_dummy_ops_state, val);
		break;
	default:
		bpf_log(log, "no write support to bpf_dummy_ops_state at off %d\n",
			off);
		return -EACCES;
	}

	if (off + size > end) {
		bpf_log(log,
			"write access at off %d with size %d beyond the member of bpf_dummy_ops_state ended at %zu\n",
			off, size, end);
		return -EACCES;
	}

	return NOT_INIT;
}

static const struct bpf_verifier_ops bpf_dummy_verifier_ops = {
	.get_func_proto = bpf_dummy_ops_get_func_proto,
	.is_valid_access = bpf_dummy_ops_is_valid_access,
	.btf_struct_access = bpf_dummy_ops_btf_struct_access,
};

static int bpf_dummy_check_member(const struct btf_type *t,
				  const struct btf_member *member)
{
	return 0;
}


static int bpf_dummy_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	return 0;
}

static int bpf_dummy_reg(void *kdata)
{
	struct bpf_dummy_ops *ops = kdata;
	int err = 0;

	spin_lock(&bpf_dummy_ops_lock);
	if (!bpf_dummy_ops_singletion)
		bpf_dummy_ops_singletion = ops;
	else
		err = -EEXIST;
	spin_unlock(&bpf_dummy_ops_lock);

	return err;
}

static void bpf_dummy_unreg(void *kdata)
{
	struct bpf_dummy_ops *ops = kdata;

	spin_lock(&bpf_dummy_ops_lock);
	if (bpf_dummy_ops_singletion == ops)
		bpf_dummy_ops_singletion = NULL;
	else
		WARN_ON(1);
	spin_unlock(&bpf_dummy_ops_lock);
}

extern struct bpf_struct_ops bpf_bpf_dummy_ops;

struct bpf_struct_ops bpf_bpf_dummy_ops = {
	.verifier_ops = &bpf_dummy_verifier_ops,
	.init = bpf_dummy_init,
	.init_member = bpf_dummy_init_member,
	.check_member = bpf_dummy_check_member,
	.reg = bpf_dummy_reg,
	.unreg = bpf_dummy_unreg,
	.name = "bpf_dummy_ops",
};
