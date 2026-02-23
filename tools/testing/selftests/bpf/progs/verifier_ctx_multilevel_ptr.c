// SPDX-License-Identifier: GPL-2.0
/*
 * Verifier tests for double and triple pointer parameter handling
 * Copyright (c) 2026 CrowdStrike, Inc.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - valid ctx access")
__success __retval(0)
__naked void ctx_double_ptr_fentry_valid_ctx_access(void)
{
	asm volatile ("				\
	/* load double pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fexit/bpf_fentry_test11_pptr_nullable")
__description("fexit/double pointer parameter - valid ctx access")
__success __retval(0)
__naked void ctx_double_ptr_fexit_valid_ctx_access(void)
{
	asm volatile ("				\
	/* load double pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer nullable parameter - valid ctx access")
__success __retval(0)
__naked void ctx_double_ptr_valid_ctx_access_nullable(void)
{
	asm volatile ("				\
	/* load double pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer nullable parameter - invalid load with scalar")
__failure __msg("R2 invalid mem access 'scalar'")
__naked void ctx_double_ptr_invalid_load(void)
{
	asm volatile ("				\
	/* load double pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 0);		\
	r3 = *(u64 *)(r2 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer nullable parameter - invalid load with scalar by offset")
__failure __msg("R2 invalid mem access 'scalar'")
__naked void ctx_double_ptr_invalid_load_with_offset(void)
{
	asm volatile ("				\
	/* load double pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 0);		\
	r3 = *(u64 *)(r2 + 0x80);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer nullable parameter - invalid store by scalar")
__failure __msg("R2 invalid mem access 'scalar'")
__naked void ctx_double_ptr_store_with_scalar(void)
{
	asm volatile ("				\
	/* load double pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 0);		\
	*(u64 *)(r2 + 0x0) = 1;		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test14_ppptr")
__description("fentry/triple pointer parameter - valid ctx access")
__success __retval(0)
__naked void ctx_triple_ptr_valid_ctx_access(void)
{
	asm volatile ("				\
	/* load triple pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test14_ppptr")
__description("fentry/triple pointer parameter - invalid load with scalar")
__failure __msg("R2 invalid mem access 'scalar'")
__naked void ctx_triple_ptr_load_with_scalar(void)
{
	asm volatile ("				\
	/* load triple pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 0);		\
	r3 = *(u64 *)(r2 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test14_ppptr")
__description("fentry/triple pointer parameter - invalid store with scalar")
__failure __msg("R2 invalid mem access 'scalar'")
__naked void ctx_triple_ptr_store_with_scalar(void)
{
	asm volatile ("				\
	/* load triple pointer - SCALAR_VALUE */\
	r2 = *(u64 *)(r1 + 0);		\
	*(u64 *)(r2 + 0) = 1;		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/sb_eat_lsm_opts")
__description("lsm/double pointer parameter trusted - valid ctx access")
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
__description("lsm/double pointer parameter trusted - invalid load with scalar")
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
__description("lsm/double pointer parameter trusted - invalid store with scalar")
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
int BPF_PROG(ctx_double_ptr_nulable_var_access_bpf_helpers,
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
	/* Check compatibility with BPF helpers; NULL checks should not be required. */
	void *ptr;

	bpf_probe_read_kernel(&ptr, sizeof(ptr), pptr);
	bpf_probe_read_kernel(&ptr, sizeof(ptr), ret);
	return 0;
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter - bpf helpers with nullable var, direct ctx pointer")
__success __retval(0)
int BPF_PROG(ctx_double_ptr_nulable_var_access_bpf_helpers_ctx,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	/* Check compatibility with BPF helpers; NULL checks should not be required. */
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
	/* Check compatibility with BPF helpers; NULL checks should not be required. */
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
int BPF_PROG(ctx_double_ptr_deref_with_field_2_load, struct bpf_fentry_test_pptr_t **pptr__nullable)
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
int BPF_PROG(ctx_double_ptr_deref_with_field_1_modification, struct bpf_fentry_test_pptr_t **pptr__nullable)
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

char _license[] SEC("license") = "GPL";
