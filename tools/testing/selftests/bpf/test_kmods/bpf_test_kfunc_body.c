// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/module.h>

struct bpf_test_kfunc_body_pair {
	u64 a, b;
};

__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_test_kfunc_body(u64 x)
{
	return x;
}

__bpf_kfunc u64 bpf_test_kfunc_body_unset(u64 x)
{
	return x;
}

__bpf_kfunc u64 bpf_test_kfunc_body_pair(struct bpf_test_kfunc_body_pair p)
{
	return p.a;
}

__bpf_kfunc u64 bpf_test_kfunc_body_sleepable(u64 x)
{
	return x;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(test_body_kfunc_ids)
BTF_ID_FLAGS(func, bpf_test_kfunc_body)
BTF_KFUNCS_END(test_body_kfunc_ids)

/* never registered */
BTF_KFUNCS_START(test_body_bad_kfunc_ids)
BTF_ID_FLAGS(func, bpf_test_kfunc_body_pair)
BTF_ID_FLAGS(func, bpf_test_kfunc_body_sleepable, KF_SLEEPABLE)
BTF_KFUNCS_END(test_body_bad_kfunc_ids)

BTF_ID_LIST(test_body_ids)
BTF_ID(func, bpf_test_kfunc_body)
BTF_ID(func, bpf_test_kfunc_body_unset)
BTF_ID(func, bpf_test_kfunc_body_pair)
BTF_ID(func, bpf_test_kfunc_body_sleepable)

static const struct bpf_insn test_body_insns[] = {
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
};

/* writes R6 */
static const struct bpf_insn test_body_bad_insns[] = {
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
};

/* jumps past the last instruction */
static const struct bpf_insn test_body_jump_insns[] = {
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1),
	BPF_MOV64_IMM(BPF_REG_0, 0),
};

static struct bpf_kfunc_body test_body = { .id = &test_body_ids[0] };

static struct btf_kfunc_id_set test_body_set = {
	.owner = THIS_MODULE,
	.set = &test_body_kfunc_ids,
	.bodies = &test_body,
	.body_cnt = 1,
};

static int test_body_rejected(struct btf_id_set8 *set, const u32 *id,
			      const struct bpf_insn *insns, u32 len)
{
	test_body_set.set = set;
	test_body.id = id;
	test_body.insns = insns;
	test_body.len = len;
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &test_body_set) == -EINVAL;
}

/*
 * The module loads only if registration rejects a body without instructions,
 * one with an instruction that writes R6, one with a jump past its last
 * instruction, one for a kfunc outside the set, one with an argument of two
 * registers and one for a kfunc with flags.
 */
static int bpf_test_kfunc_body_init(void)
{
	struct btf_id_set8 *good = &test_body_kfunc_ids, *bad = &test_body_bad_kfunc_ids;

	if (!test_body_rejected(good, &test_body_ids[0], NULL, 0) ||
	    !test_body_rejected(good, &test_body_ids[0], test_body_bad_insns,
				ARRAY_SIZE(test_body_bad_insns)) ||
	    !test_body_rejected(good, &test_body_ids[0], test_body_jump_insns,
				ARRAY_SIZE(test_body_jump_insns)) ||
	    !test_body_rejected(good, &test_body_ids[1], test_body_insns, 1) ||
	    !test_body_rejected(bad, &test_body_ids[2], test_body_insns, 1) ||
	    !test_body_rejected(bad, &test_body_ids[3], test_body_insns, 1))
		return -EINVAL;
	test_body_set.set = good;
	test_body.id = &test_body_ids[0];
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &test_body_set);
}

static void bpf_test_kfunc_body_exit(void)
{
}

module_init(bpf_test_kfunc_body_init);
module_exit(bpf_test_kfunc_body_exit);

MODULE_DESCRIPTION("BPF kfunc body registration test module");
MODULE_LICENSE("GPL");
