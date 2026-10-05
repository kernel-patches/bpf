// SPDX-License-Identifier: GPL-2.0
/*
 * Kfuncs for CPU instructions that BPF lacks, with BPF bodies, see struct
 * bpf_kfunc_body. Arguments named __k must be known constants.
 */
#include <linux/bitops.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/module.h>
#include <linux/unaligned.h>

__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_rol64(u64 x, u32 n__k)
{
	return rol64(x, n__k);
}

__bpf_kfunc u64 bpf_select64(u64 cond, u64 a, u64 b)
{
	return cond ? a : b;
}

__bpf_kfunc u64 bpf_extract64(u64 x, u32 start__k, u32 len__k)
{
	return x << (64 - start__k - len__k) >> (64 - len__k);
}

__bpf_kfunc u64 bpf_load_be64(const void *p, s32 off__k)
{
	return get_unaligned_be64(p + off__k);
}

__bpf_kfunc void bpf_prefetch(const void *p)
{
	/* not prefetch(), which boot-time alternatives may rewrite */
	__builtin_prefetch(p);
}

__bpf_kfunc void bpf_copy16(void *dst, const void *src)
{
	/* both loads first, as in the body, in case the buffers overlap */
	u64 lo = get_unaligned((const u64 *)src);
	u64 hi = get_unaligned((const u64 *)(src + 8));

	put_unaligned(lo, (u64 *)dst);
	put_unaligned(hi, (u64 *)(dst + 8));
}

__bpf_kfunc u64 bpf_lea64(u64 base, u64 index, u32 scale__k, s32 disp__k)
{
	return base + index * scale__k + disp__k;
}

__bpf_kfunc_end_defs();

/* x << n | x >> (-n & 63) */
static const struct bpf_insn rol64_body[] = {
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 63),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_REG(BPF_LSH, BPF_REG_0, BPF_REG_2),
	BPF_ALU64_IMM(BPF_NEG, BPF_REG_2, 0),
	BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 63),
	BPF_ALU64_REG(BPF_RSH, BPF_REG_1, BPF_REG_2),
	BPF_ALU64_REG(BPF_OR, BPF_REG_0, BPF_REG_1),
};

/* the jump lands within the body, here on its last instruction */
static const struct bpf_insn select64_body[] = {
	BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, 1),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_3),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
};

/* x << (64 - start - len) >> (64 - len) */
static const struct bpf_insn extract64_body[] = {
	BPF_MOV32_IMM(BPF_REG_4, 64),
	BPF_ALU32_REG(BPF_SUB, BPF_REG_4, BPF_REG_2),
	BPF_ALU32_REG(BPF_SUB, BPF_REG_4, BPF_REG_3),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
	BPF_ALU64_REG(BPF_LSH, BPF_REG_0, BPF_REG_4),
	BPF_MOV32_IMM(BPF_REG_4, 64),
	BPF_ALU32_REG(BPF_SUB, BPF_REG_4, BPF_REG_3),
	BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_4),
};

/* the offset is an s32 */
static const struct bpf_insn load_be64_body[] = {
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 32),
	BPF_ALU64_IMM(BPF_ARSH, BPF_REG_2, 32),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0),
	BPF_ENDIAN(BPF_TO_BE, BPF_REG_0, 64),
};

/* a load whose value is not used, of memory that the program may read */
static const struct bpf_insn prefetch_body[] = {
	BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_1, 0),
};

/* two loads, then two stores */
static const struct bpf_insn copy16_body[] = {
	BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_2, 0),
	BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_2, 8),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_4, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_5, 8),
};

/* base + index * scale + disp, scale a u32 and disp an s32 */
static const struct bpf_insn lea64_body[] = {
	BPF_MOV32_REG(BPF_REG_3, BPF_REG_3),
	BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
	BPF_ALU64_REG(BPF_MUL, BPF_REG_0, BPF_REG_3),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),
	BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, 32),
	BPF_ALU64_IMM(BPF_ARSH, BPF_REG_4, 32),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_4),
};

#ifdef CONFIG_BPF_INSN_KFUNCS_ARCH
#include "insn_kfuncs.h" /* $(SRCARCH)/insn_kfuncs.h */
#else
#define rol64_emit	NULL
#define select64_emit	NULL
#define extract64_emit	NULL
#define load_be64_emit	NULL
#define lea64_emit	NULL
#endif

BTF_KFUNCS_START(insn_kfunc_ids)
BTF_ID_FLAGS(func, bpf_rol64)
BTF_ID_FLAGS(func, bpf_select64)
BTF_ID_FLAGS(func, bpf_extract64)
BTF_ID_FLAGS(func, bpf_load_be64)
BTF_ID_FLAGS(func, bpf_prefetch)
BTF_ID_FLAGS(func, bpf_copy16)
BTF_ID_FLAGS(func, bpf_lea64)
BTF_KFUNCS_END(insn_kfunc_ids)

BTF_ID_LIST(body_ids)
BTF_ID(func, bpf_rol64)
BTF_ID(func, bpf_select64)
BTF_ID(func, bpf_extract64)
BTF_ID(func, bpf_load_be64)
BTF_ID(func, bpf_prefetch)
BTF_ID(func, bpf_copy16)
BTF_ID(func, bpf_lea64)

#define BODY(i, op, emit)	{ &body_ids[i], op##_body, ARRAY_SIZE(op##_body), emit }

/* without emit, the JIT copies the kfunc, whose code is the instruction itself */
static const struct bpf_kfunc_body bodies[] = {
	BODY(0, rol64, rol64_emit),
	BODY(1, select64, select64_emit),
	BODY(2, extract64, extract64_emit),
	BODY(3, load_be64, load_be64_emit),
	BODY(4, prefetch, NULL),
	BODY(5, copy16, NULL),
	BODY(6, lea64, lea64_emit),
};

static const struct btf_kfunc_id_set insn_kfunc_set = {
	.owner    = THIS_MODULE,
	.set      = &insn_kfunc_ids,
	.bodies   = bodies,
	.body_cnt = ARRAY_SIZE(bodies),
};

static int __init insn_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &insn_kfunc_set);
}

/* the kfunc set goes away with the module's BTF */
static void __exit insn_kfuncs_exit(void)
{
}

module_init(insn_kfuncs_init);
module_exit(insn_kfuncs_exit);

MODULE_DESCRIPTION("Kfuncs for CPU instructions that BPF lacks");
MODULE_LICENSE("GPL");
