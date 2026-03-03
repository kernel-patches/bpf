// SPDX-License-Identifier: GPL-2.0
/*
 * Verifier tests for single- and multi-level pointer parameter handling
 * Copyright (c) 2026 CrowdStrike, Inc.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

#define VALID_CTX_ACCESS(section, name, ctx_offset) \
SEC(section) \
__description(section " - valid ctx access at offset " #ctx_offset) \
__success __retval(0) \
__naked void name##_ctx_at_##ctx_offset##_valid(void) \
{ \
	asm volatile ("				\
	r2 = *(u64 *)(r1 + " #ctx_offset " );		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all); \
}

#define INVALID_CTX_ACCESS(section, name, desc, errmsg, ctx_offset) \
SEC(section) \
__description(desc) \
__failure __msg(errmsg) \
__naked void name##_ctx_at_##ctx_offset##_invalid(void) \
{ \
	asm volatile ("				\
	r2 = *(u64 *)(r1 + " #ctx_offset ");		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all); \
}

#define INVALID_LOAD_OFFSET(section, name, size, offset, ctx_offset) \
SEC(section) \
__description(section " - ctx offset " #ctx_offset ", invalid load at offset " #offset " with scalar") \
__failure __msg("R2 invalid mem access 'scalar'") \
__naked void name##_load_at_##offset##_with_scalar(void) \
{ \
	asm volatile ("				\
	r2 = *(u64 *)(r1 + " #ctx_offset ");		\
	r3 = *(u" #size "*)(r2 + " #offset ");		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all); \
}

#define INVALID_LOAD(section, name, size, ctx_offset) \
	INVALID_LOAD_OFFSET(section, name, size, 0, ctx_offset)

#define INVALID_LOAD_NEG_OFFSET(section, name, size, offset, ctx_offset) \
SEC(section) \
__description(section " - ctx offset " #ctx_offset ", invalid load at negative offset " #offset " with scalar") \
__failure __msg("R2 invalid mem access 'scalar'") \
__naked void name##_load_at_neg_##offset##_with_scalar(void) \
{ \
	asm volatile ("				\
	r2 = *(u64 *)(r1 + " #ctx_offset ");		\
	r3 = *(u" #size "*)(r2 - " #offset ");		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all); \
}

#define INVALID_STORE_OFFSET(section, name, size, offset, ctx_offset) \
SEC(section) \
__description(section " - ctx offset " #ctx_offset ", invalid store " #size " at offset " #offset " with scalar") \
__failure __msg("R2 invalid mem access 'scalar'") \
__naked void name##_store##size##_at_##offset##_with_scalar(void) \
{ \
	asm volatile ("				\
	r2 = *(u64 *)(r1 + " #ctx_offset ");		\
	*(u" #size "*)(r2 + " #offset ") = 1;		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all); \
}

#define INVALID_STORE(section, name, size, ctx_offset) \
	INVALID_STORE_OFFSET(section, name, size, 0, ctx_offset)

#define INVALID_STORE_NEG_OFFSET(section, name, size, offset, ctx_offset) \
SEC(section) \
__description(section " - ctx offset " #ctx_offset ", invalid store " #size " at negative offset " #offset " with scalar") \
__failure __msg("R2 invalid mem access 'scalar'") \
__naked void name##_store##size##_at_neg_##offset##_with_scalar(void) \
{ \
	asm volatile ("				\
	r2 = *(u64 *)(r1 + "#ctx_offset ");		\
	*(u" #size "*)(r2 - " #offset ") = 1;		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all); \
}

/* Double nullable pointer to struct */
VALID_CTX_ACCESS("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 0)
VALID_CTX_ACCESS("fexit/bpf_fentry_test11_pptr_nullable", bpf_fexit_pptr_nullable, 0)
INVALID_LOAD("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 64, 0)
INVALID_LOAD_OFFSET("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 64, 128, 0)
INVALID_LOAD_NEG_OFFSET("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 64, 128, 0)
INVALID_STORE("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 8, 0)
INVALID_STORE("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 16, 0)
INVALID_STORE("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 32, 0)
INVALID_STORE("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 64, 0)
INVALID_STORE_OFFSET("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 64, 128, 0)
INVALID_STORE_NEG_OFFSET("fentry/bpf_fentry_test11_pptr_nullable", bpf_fentry_pptr_nullable, 64, 128, 0)

/* Double pointer parameter to u32 at offset 8 in ctx */
VALID_CTX_ACCESS("fentry/bpf_fentry_test12_pptr", bpf_fentry_test12_pptr, 8)
VALID_CTX_ACCESS("fexit/bpf_fentry_test12_pptr", bpf_fexit_test12_pptr, 8)
INVALID_LOAD("fentry/bpf_fentry_test12_pptr", bpf_fentry_test12_pptr, 64, 8)
INVALID_LOAD_OFFSET("fentry/bpf_fentry_test12_pptr", bpf_fentry_test12_pptr, 64, 64, 8)
INVALID_LOAD_NEG_OFFSET("fentry/bpf_fentry_test12_pptr", bpf_fentry_test12_pptr, 64, 64, 8)
INVALID_STORE("fentry/bpf_fentry_test12_pptr", bpf_fentry_test12_pptr, 64, 8)
INVALID_STORE_OFFSET("fentry/bpf_fentry_test12_pptr", bpf_fentry_test12_pptr, 64, 128, 8)
INVALID_STORE_NEG_OFFSET("fentry/bpf_fentry_test12_pptr", bpf_fentry_test12_pptr, 64, 128, 8)

/* Triple pointer to void with modifiers */
VALID_CTX_ACCESS("fentry/bpf_fentry_test14_ppptr", bpf_fentry_ppptr, 0)
VALID_CTX_ACCESS("fexit/bpf_fentry_test14_ppptr", bpf_fexit_ppptr, 0)
INVALID_LOAD("fentry/bpf_fentry_test14_ppptr", bpf_fentry_ppptr, 64, 0)
INVALID_STORE("fentry/bpf_fentry_test14_ppptr", bpf_fentry_ppptr, 64, 0)

/* Trusted double pointer to void */
SEC("lsm/sb_eat_lsm_opts")
__description("lsm/sb_eat_lsm_opts double pointer parameter trusted - valid ctx access")
__success
__naked void sb_eat_lsm_opts_trusted_valid_ctx_access(void)
{
	asm volatile ("				\
	/* load double pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 8);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/sb_eat_lsm_opts")
__description("lsm/sb_eat_lsm_opts double pointer parameter trusted - invalid load with scalar")
__failure __msg("R2 invalid mem access 'scalar'")
__naked void sb_eat_lsm_opts_trusted_load_with_scalar(void)
{
	asm volatile ("				\
	/* load double pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 8);		\
	r3 = *(u64 *)(r2 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/sb_eat_lsm_opts")
__description("lsm/sb_eat_lsm_opts double pointer parameter trusted - invalid store with scalar")
__failure __msg("R2 invalid mem access 'scalar'")
__naked void sb_eat_lsm_opts_trusted_store_with_scalar(void)
{
	asm volatile ("				\
	/* load double pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 8);		\
	*(u64 *)(r2 + 0) = 1;		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

struct bpf_fentry_test_pptr_t;

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - bpf helpers with nullable var")
__success __retval(0)
int BPF_PROG(ctx_double_ptr_nullable_var_access_bpf_helpers,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	/* Check compatibility with BPF helpers; NULL checks should not be required. */
	void *ptr;

	bpf_probe_read_kernel(&ptr, sizeof(ptr), pptr__nullable);
	return 0;
}

/*
 * Workaround for a bug in LLVM:
 * fatal error: error in backend: Empty type name for BTF_TYPE_ID_REMOTE reloc
 */
typedef __u32 *__u32_p;

/*
 * Workaround for:
 * kfunc bpf_rdonly_cast type ID argument must be of a struct or void
 */
struct __u32_wrap {
	__u32 v;
};

SEC("fexit/bpf_fentry_test12_pptr")
__description("fexit/double pointer return value - valid dereference of return val")
__success __retval(0)
int BPF_PROG(ctx_double_ptr_return_access, __u32 id,
	__u32 **pptr, __u32 **ret)
{
	__u32 **ppu32;
	struct __u32_wrap *pu32;
	ppu32 = bpf_core_cast(ret, __u32_p);
	pu32 = bpf_core_cast(ppu32, struct __u32_wrap);
	bpf_printk("%d", pu32->v);
	return 0;
}

SEC("fexit/bpf_fentry_test12_pptr")
__description("fexit/double pointer parameter - bpf helpers with return val")
__success __retval(0)
int BPF_PROG(ctx_double_ptr_return_access_bpf_helpers, __u32 id,
	__u32 **pptr, __u32 **ret)
{
	/* Check compatibility with BPF helpers */
	void *ptr;

	bpf_probe_read_kernel(&ptr, sizeof(ptr), pptr);
	bpf_probe_read_kernel(&ptr, sizeof(ptr), ret);
	return 0;
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - bpf helpers with nullable var, direct ctx pointer")
__success __retval(0)
int BPF_PROG(ctx_double_ptr_nullable_var_access_bpf_helpers_ctx,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	/*
	 * Check compatibility with BPF helpers
	 * NULL checks should not be required.
	 */
	void *ptr;

	bpf_probe_read_kernel(&ptr, sizeof(ptr), &ctx[0] /*pptr__nullable*/);
	return 0;
}

SEC("fexit/bpf_fentry_test12_pptr")
__description("fexit/double pointer parameter - bpf helpers with return val, direct ctx pointer")
__success __retval(0)
int BPF_PROG(ctx_double_ptr_return_access_bpf_helpers_ctx, __u32 id,
	__u32 **pptr, __u32 **ret)
{
	/* Check compatibility with BPF helpers */
	void *ptr;

	bpf_probe_read_kernel(&ptr, sizeof(ptr), &ctx[1] /*pptr*/);
	bpf_probe_read_kernel(&ptr, sizeof(ptr), &ctx[2] /*ret*/);
	return 0;
}

struct bpf_fentry_test_pptr_t {
	__u32 value1;
	__u32 value2;
};

/*
 * Workaround for a bug in LLVM:
 * fatal error: error in backend: Empty type name for BTF_TYPE_ID_REMOTE reloc
 */
typedef struct bpf_fentry_test_pptr_t *bpf_fentry_test_pptr_p;

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - dereference followed by valid load of field 1")
__success __retval(0)
int BPF_PROG(ctx_double_ptr_deref_with_field_1_load,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t **pptr;
	struct bpf_fentry_test_pptr_t *ptr;

	pptr = bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	ptr = bpf_core_cast((*pptr), struct bpf_fentry_test_pptr_t);
	bpf_printk("%d", ptr->value1);
	return 0;
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - dereference followed by valid load of field 2")
__success __retval(0)
int BPF_PROG(ctx_double_ptr_deref_with_field_2_load,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t **pptr;
	struct bpf_fentry_test_pptr_t *ptr;

	pptr = bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	ptr = bpf_core_cast((*pptr), struct bpf_fentry_test_pptr_t);
	bpf_printk("%d", ptr->value2);
	return 0;
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - dereference followed by invalid out-of-bounds offset load")
__failure __msg("access beyond struct bpf_fentry_test_pptr_t at off 128 size 4")
int BPF_PROG(ctx_double_ptr_deref_with_load_by_positive_out_of_bound_offset,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t **pptr;
	struct bpf_fentry_test_pptr_t *ptr;
	__u32 value;

	pptr = bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	ptr = bpf_core_cast((*pptr), struct bpf_fentry_test_pptr_t);

	asm volatile ("					\
		r2 = %1;					\
		/* Load with out-of-bounds offset */\
		%0 = *(u32 *)(r2 + 0x80)	\
		" : "=r" (value) : "r" (ptr) : "r2");

	bpf_printk("%d", value);
	return 0;
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - dereference followed by invalid out-of-bounds offset load")
__failure __msg("R2 is ptr_bpf_fentry_test_pptr_t invalid negative access: off=-128")
int BPF_PROG(ctx_double_ptr_deref_with_load_by_negative_out_of_bound_offset,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t **pptr;
	struct bpf_fentry_test_pptr_t *ptr;
	__u32 value;

	pptr = bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	ptr = bpf_core_cast((*pptr), struct bpf_fentry_test_pptr_t);

	asm volatile ("					\
		r2 = %1;					\
		/* Load with out-of-bounds offset */\
		%0 = *(u32 *)(r2 - 0x80);	\
		" : "=r" (value) : "r" (ptr) : "r2");

	bpf_printk("%d", value);
	return 0;
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - dereference followed by invalid store to field 1")
__failure __msg("only read is supported")
int BPF_PROG(ctx_double_ptr_deref_with_field_1_modification,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t **pptr;
	struct bpf_fentry_test_pptr_t *ptr;

	pptr = bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	ptr = bpf_core_cast((*pptr), struct bpf_fentry_test_pptr_t);

	asm volatile ("					\
		/* Load immediate 1 into w2 */\
		w2 = 1;						\
		/* Store to ptr->value1 */	\
		*(u32 *)(%0 + 0) = r2;		\
		" :: "r" (ptr) : "r2");

	return 0;
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - dereference followed by invalid store to field 2")
__failure __msg("only read is supported")
int BPF_PROG(ctx_double_ptr_deref_with_field_2_modification,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t **pptr;
	struct bpf_fentry_test_pptr_t *ptr;

	pptr = bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	ptr = bpf_core_cast((*pptr), struct bpf_fentry_test_pptr_t);

	asm volatile ("					\
		/* Load immediate 2 into w2 */\
		w2 = 2;						\
		/* Store to ptr->value2 */	\
		*(u32 *)(%0 + 4) = r2;		\
		" :: "r" (ptr) : "r2");

	return 0;
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - dereference followed by invalid store to positive offset beyond struct boundaries")
__failure __msg("only read is supported")
int BPF_PROG(ctx_double_ptr_deref_with_store_by_positive_invalid_offset,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t **pptr;
	struct bpf_fentry_test_pptr_t *ptr;

	pptr = bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	ptr = bpf_core_cast((*pptr), struct bpf_fentry_test_pptr_t);

	asm volatile ("					\
		r3 = %0;					\
		/* Load immediate 3 into w2 */\
		w2 = 3;						\
		/* Store with offset outside struct size */	\
		*(u32 *)(r3 + 0x80) = r2;		\
		" :: "r" (ptr) : "r2", "r3");

	return 0;
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - dereference followed by invalid store to negative offset beyond struct boundaries")
__failure __msg("R3 is ptr_bpf_fentry_test_pptr_t invalid negative access: off=-128")
int BPF_PROG(ctx_double_ptr_deref_with_store_by_negative_invalid_offset,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	struct bpf_fentry_test_pptr_t **pptr;
	struct bpf_fentry_test_pptr_t *ptr;

	pptr = bpf_core_cast(pptr__nullable, bpf_fentry_test_pptr_p);
	ptr = bpf_core_cast((*pptr), struct bpf_fentry_test_pptr_t);

	asm volatile ("					\
		r3 = %0;					\
		/* Load immediate 3 into w2 */\
		w2 = 3;						\
		/* Store with offset outside struct size */	\
		*(u32 *)(r3 - 0x80) = r2;		\
		" :: "r" (ptr) : "r2", "r3");

	return 0;
}

/* Pointer to enum 32 */
VALID_CTX_ACCESS("fentry/bpf_fentry_test15_penum32", bpf_fentry_penum32, 0)
INVALID_LOAD("fentry/bpf_fentry_test15_penum32", bpf_fentry_penum32, 32, 0)
VALID_CTX_ACCESS("fexit/bpf_fentry_test15_penum32", bpf_fexit_penum32, 0)
INVALID_LOAD("fexit/bpf_fentry_test15_penum32", bpf_fexit_penum32, 32, 0)
INVALID_LOAD_OFFSET("fentry/bpf_fentry_test15_penum32", bpf_fentry_penum32, 8, 1, 0)
INVALID_STORE("fentry/bpf_fentry_test15_penum32", bpf_fentry_penum32, 8, 0)
INVALID_STORE("fentry/bpf_fentry_test15_penum32", bpf_fentry_penum32, 32, 0)
INVALID_STORE("fentry/bpf_fentry_test15_penum32", bpf_fentry_penum32, 64, 0)
INVALID_STORE_OFFSET("fentry/bpf_fentry_test15_penum32", bpf_fentry_penum32, 8, 1, 0)
INVALID_STORE_NEG_OFFSET("fentry/bpf_fentry_test15_penum32", bpf_fentry_penum32, 8, 1, 0)

/* Pointer to enum 64 */
VALID_CTX_ACCESS("fentry/bpf_fentry_test15_penum64", bpf_fentry_penum64, 0)
INVALID_LOAD("fentry/bpf_fentry_test15_penum64", bpf_fentry_penum64, 64, 0)
VALID_CTX_ACCESS("fexit/bpf_fentry_test15_penum64", bpf_fexit_penum64, 0)
INVALID_LOAD("fexit/bpf_fentry_test15_penum64", bpf_fexit_penum64, 64, 0)

/* Double pointer to enum 32 */
VALID_CTX_ACCESS("fentry/bpf_fentry_test16_ppenum32", bpf_fentry_ppenum32, 0)
INVALID_LOAD("fentry/bpf_fentry_test16_ppenum32", bpf_fentry_ppenum32, 8, 0)

/* Double pointer to enum 64 */
VALID_CTX_ACCESS("fentry/bpf_fentry_test16_ppenum64", bpf_fentry_ppenum64, 0)
INVALID_LOAD("fentry/bpf_fentry_test16_ppenum64", bpf_fentry_ppenum64, 64, 0)

/* Pointer to function */
VALID_CTX_ACCESS("fentry/bpf_fentry_test17_pfunc", bpf_fentry_pfunc, 0)
INVALID_LOAD("fentry/bpf_fentry_test17_pfunc", bpf_fentry_pfunc, 8, 0)

/* Double pointer to function */
VALID_CTX_ACCESS("fentry/bpf_fentry_test18_ppfunc", bpf_fentry_ppfunc, 0)
INVALID_LOAD("fentry/bpf_fentry_test18_ppfunc", bpf_fentry_ppfunc, 8, 0)

/* Pointer to float */
INVALID_CTX_ACCESS("fentry/bpf_fentry_test19_pfloat", bpf_fentry_float,
	"fentry/pointer to float - invalid ctx access",
	"func 'bpf_fentry_test19_pfloat' arg0 type FLOAT is not a struct", 0)

/* Double pointer to float */
INVALID_CTX_ACCESS("fentry/bpf_fentry_test20_ppfloat", bpf_fentry_pfloat,
	"fentry/double pointer to float - invalid ctx access",
	"func 'bpf_fentry_test20_ppfloat' arg0 type PTR is not a struct", 0)

/* Pointer to char */
VALID_CTX_ACCESS("fentry/bpf_fentry_test21_pchar", bpf_fentry_pchar, 0)
INVALID_LOAD("fentry/bpf_fentry_test21_pchar", bpf_fentry_pchar, 64, 0)
INVALID_STORE("fentry/bpf_fentry_test21_pchar", bpf_fentry_pchar, 8, 0)
INVALID_STORE("fentry/bpf_fentry_test21_pchar", bpf_fentry_pchar, 16, 0)
INVALID_STORE("fentry/bpf_fentry_test21_pchar", bpf_fentry_pchar, 32, 0)
INVALID_STORE("fentry/bpf_fentry_test21_pchar", bpf_fentry_pchar, 64, 0)

/* Double pointer to char */
VALID_CTX_ACCESS("fentry/bpf_fentry_test22_ppchar", bpf_fentry_ppchar, 0)
INVALID_LOAD("fentry/bpf_fentry_test22_ppchar", bpf_fentry_ppchar, 64, 0)
INVALID_STORE("fentry/bpf_fentry_test22_ppchar", bpf_fentry_ppchar, 8, 0)
INVALID_STORE_OFFSET("fentry/bpf_fentry_test22_ppchar", bpf_fentry_ppchar, 8, 1, 0)
INVALID_STORE("fentry/bpf_fentry_test22_ppchar", bpf_fentry_ppchar, 16, 0)
INVALID_STORE("fentry/bpf_fentry_test22_ppchar", bpf_fentry_ppchar, 32, 0)
INVALID_STORE("fentry/bpf_fentry_test22_ppchar", bpf_fentry_ppchar, 64, 0)

/* Double pointer to char as return value */
INVALID_CTX_ACCESS("fentry/bpf_fentry_test23_ret_ppchar", bpf_fentry_ret_ppchar,
	"fentry/bpf_fentry_test23_ret_ppchar - invalid ctx access for nonexisting prameter",
	"func 'bpf_fentry_test23_ret_ppchar' doesn't have 1-th argument", 0)
VALID_CTX_ACCESS("fexit/bpf_fentry_test23_ret_ppchar", bpf_fexit_ret_ppchar, 0)
INVALID_LOAD("fexit/bpf_fentry_test23_ret_ppchar", bpf_fexit_ret_ppchar, 8, 0)
INVALID_LOAD_OFFSET("fexit/bpf_fentry_test23_ret_ppchar", bpf_fexit_ret_ppchar, 8, 1, 0)
INVALID_LOAD_NEG_OFFSET("fexit/bpf_fentry_test23_ret_ppchar", bpf_fexit_ret_ppchar, 8, 1, 0)
INVALID_STORE("fexit/bpf_fentry_test23_ret_ppchar", bpf_fexit_ret_ppchar, 8, 0)
INVALID_STORE_OFFSET("fexit/bpf_fentry_test23_ret_ppchar", bpf_fexit_ret_ppchar, 8, 1, 0)
INVALID_STORE_NEG_OFFSET("fexit/bpf_fentry_test23_ret_ppchar", bpf_fexit_ret_ppchar, 8, 1, 0)

/* Double pointer to struct file as return value, double pointer to void as input */
VALID_CTX_ACCESS("fentry/bpf_fentry_test24_ret_ppfile", bpf_fenty_ret_ppfile, 0)
INVALID_CTX_ACCESS("fentry/bpf_fentry_test24_ret_ppfile", bpf_fenty_ret_ppfile,
	"fentry/bpf_fentry_test24_ret_ppfile - invalid ctx access for nonexisting prameter",
	"func 'bpf_fentry_test24_ret_ppfile' doesn't have 2-th argument", 8)
VALID_CTX_ACCESS("fexit/bpf_fentry_test24_ret_ppfile", bpf_fexit_ret_ppfile, 0)
VALID_CTX_ACCESS("fexit/bpf_fentry_test24_ret_ppfile", bpf_fexit_ret_ppfile, 8)
INVALID_LOAD("fexit/bpf_fentry_test24_ret_ppfile", bpf_fexit_ret_ppfile, 8, 8)
INVALID_LOAD_OFFSET("fexit/bpf_fentry_test24_ret_ppfile", bpf_fexit_ret_ppfile, 8, 1, 8)
INVALID_LOAD_NEG_OFFSET("fexit/bpf_fentry_test24_ret_ppfile", bpf_fexit_ret_ppfile, 8, 1, 8)
INVALID_STORE("fexit/bpf_fentry_test24_ret_ppfile", bpf_fexit_ret_ppfile, 8, 8)
INVALID_STORE_OFFSET("fexit/bpf_fentry_test24_ret_ppfile", bpf_fexit_ret_ppfile, 8, 1, 8)
INVALID_STORE_NEG_OFFSET("fexit/bpf_fentry_test24_ret_ppfile", bpf_fexit_ret_ppfile, 8, 1, 8)

char _license[] SEC("license") = "GPL";
