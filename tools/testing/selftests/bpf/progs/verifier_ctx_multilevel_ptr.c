// SPDX-License-Identifier: GPL-2.0
/*
 * Verifier tests for double and triple pointer parameter handling
 * Copyright (c) 2026 CrowdStrike, Inc.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter (rdonly, untrusted, nullable) - valid ctx access")
__success __retval(0)
__naked void ctx_double_ptr_valid_load(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL	*/\
	r2 = *(u64 *)(r1 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter (rdonly, untrusted, nullable) - invalid load without null")
__failure __msg("R2 invalid mem access 'rdonly_untrusted_mem_or_null'")
__naked void ctx_double_ptr_load_no_check_nullable(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 0);		\
	/*							\
	 * invalid dereference without check for NULL when a parameter	\
	 * is marked nullable (PTR_MAYBE_NULL)	\
	 */							\
	r3 = *(u64 *)(r2 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test12_pptr")
__description("fentry/double pointer parameter (rdonly, untrusted) - valid load without null")
__success __retval(0)
__naked void ctx_double_ptr_load_no_check(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED */\
	r2 = *(u64 *)(r1 + 8);		\
	/* valid dereference without check for NULL as the parameter is not marked as nullable */\
	r3 = *(u64 *)(r2 + 0);		\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter (rdonly, untrusted, nullable) - valid load with null")
__success __retval(0)
__naked void ctx_double_ptr_readonly(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 0);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	r3 = *(u64 *)(r2 + 0);		\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter (rdonly, untrusted) - valid load with arbitrary offset")
__success __retval(0)
__naked void ctx_double_ptr_valid_load_with_offset(void)
{
	asm volatile ("					\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED */\
	r2 = *(u64 *)(r1 + 0);		\
	if r2 == 0 goto l0_%=;		/* check for null (PTR_MAYBE_NULL) */\
	/* load with arbitrary offset is protected by an exception handler */\
	r3 = *(u64 *)(r2 + 0x1000);	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter (rdonly, untrusted, nullable) - invalid load with double dereference with offset")
__failure __msg("R3 invalid mem access 'scalar'")
__naked void ctx_double_ptr_invalid_load_with_offset(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED */\
	r2 = *(u64 *)(r1 + 0);		\
	if r2 == 0 goto l0_%=;		/* check for null (PTR_MAYBE_NULL) */\
	r3 = *(u64 *)(r2 + 0);		\
	r4 = *(u64 *)(r3 + 0x1000);	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter (rdonly, untrusted, nullable) - invalid narrow load")
__failure __msg("size 4 must be 8")
__naked void ctx_double_ptr_size_check(void)
{
	asm volatile ("				\
	r2 = *(u32 *)(r1 + 0);		/* invalid narrow load */\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter (rdonly, untrusted, nullable) - invalid store to read only memory")
__failure __msg("R2 cannot write into rdonly_untrusted_mem")
__naked void ctx_double_ptr_write_readonly(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 0);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	*(u64 *)(r2 + 0x0) = 1;		/* read only */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter (rdonly, untrusted, nullable) - invalid store with offset")
__failure __msg("R2 cannot write into rdonly_untrusted_mem")
__naked void ctx_double_ptr_write_offset_readonly(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 0);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	*(u64 *)(r2 + 0x1000) = 1;	/* read only */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fentry/double pointer parameter (rdonly, untrusted, nullable) - invalid store with offset, scalar type")
__failure __msg("R3 invalid mem access 'scalar'")
__naked void ctx_double_ptr_write2_readonly(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 0);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	r3 = *(u64 *)(r2 + 0);		/* R3 is a scalar */	\
	*(u64 *)(r3 + 0) = 1;		/* scalar */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test14_ppptr")
__description("fentry/triple pointer parameter (rdonly, untrusted, nullable) - invalid store to read only memory")
__failure __msg("R2 cannot write into rdonly_untrusted_mem")
__naked void ctx_double_ptr_write3_readonly(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 0);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	*(u64 *)(r2 + 0) = 1;		/* read only */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fentry/bpf_fentry_test14_ppptr")
__description("fentry/triple pointer parameter (rdonly, untrusted, nullable) - invalid mem access (scalar)")
__failure __msg("R3 invalid mem access 'scalar'")
__naked void ctx_double_ptr_write4_readonly(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 0);		\
	if r2 == 0 goto l0_%=;		/* check for null (PTR_MAYBE_NULL) */\
	r3 = *(u64 *)(r2 + 0);		/* R3 type is scalar */	\
	*(u64 *)(r3 + 0) = 1;		/* mem access for scalar */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/sb_eat_lsm_opts")
__description("lsm/double pointer parameter (rdonly, trusted) - invalid load outside boundaries")
__failure __msg("R2 min value is outside of the allowed memory range")
__naked void sb_eat_lsm_opts_trusted_offset_outside_boundaries(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY, PTR_UNTRUSTED is not set */\
	r2 = *(u64 *)(r1 + 8);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	/* should fail as for a trusted parameter verifier checks boundaries */\
	r3 = *(u64 *)(r2 + 0x1000);	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/sb_eat_lsm_opts")
__description("lsm/double pointer parameter (rdonly, trusted) - load within boundaries")
__success
__naked void sb_eat_lsm_opts_trusted_offset_within_boundaries(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY , PTR_UNTRUSTED is not set */\
	r2 = *(u64 *)(r1 + 8);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	/*							\
	 * should pass as for a trusted parameter verifier checks boundaries	\
	 * and access is within boundaries	\
	 */							\
	r3 = *(u64 *)(r2 + 0x0);	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/sb_eat_lsm_opts")
__description("lsm/double pointer parameter (rdonly, trusted) - load within boundaries, no check for null")
__success
__naked void sb_eat_lsm_opts_trusted_offset_within_boundaries_no_null_check(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY , PTR_UNTRUSTED is not set */\
	r2 = *(u64 *)(r1 + 8);		\
	/*							\
	 * should pass as for a trusted parameter verifier checks boundaries	\
	 * and PTR_MAYBE_NULL is not set	\
	 */							\
	r3 = *(u64 *)(r2 + 0x0);	\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/sb_eat_lsm_opts")
__description("lsm/double pointer parameter (rdonly, trusted) - invalid store within boundaries to read only mem")
__failure __msg("R2 cannot write into rdonly_mem")
__naked void sb_eat_lsm_opts_trusted_modification_within_boundaries(void)
{
	asm volatile ("				\
	/* load double pointer - should be PTR_TO_MEM | MEM_RDONLY , PTR_UNTRUSTED is not set */\
	r2 = *(u64 *)(r1 + 8);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	*(u64 *)(r2 + 0x0) = 1;		/* read only */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("lsm/sb_eat_lsm_opts")
__description("lsm/double pointer parameter (rdonly, trusted) - invalid store outside boundaries to read only mem")
__failure __msg("R2 cannot write into rdonly_mem")
__naked void sb_eat_lsm_opts_trusted_modification_outside_boundaries(void)
{
	asm volatile ("				\
	/* load double pointer - PTR_TO_MEM | MEM_RDONLY , PTR_UNTRUSTED is not set */\
	r2 = *(u64 *)(r1 + 8);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	*(u64 *)(r2 + 0x1000) = 1;	/* read only */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fexit/bpf_fentry_test12_pptr")
__description("fexit/double pointer return (rdonly, untrusted, nullable) - valid load")
__success __retval(0)
__naked void ctx_double_ptr_return_load1(void)
{
	asm volatile ("				\
	/* load double pointer return value - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 16);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	r3 = *(u64 *)(r2 + 0);		/* R3 is a scalar */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fexit/bpf_fentry_test12_pptr")
__description("fexit/double pointer return (rdonly, untrusted, nullable) - valid load with offset")
__success __retval(0)
__naked void ctx_double_ptr_return_load2(void)
{
	asm volatile ("				\
	/* load double pointer return value - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 16);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	/* verifier doesn't check boundaries for access protect by an exception handler */\
	r3 = *(u64 *)(r2 - 0x100);	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fexit/bpf_fentry_test12_pptr")
__description("fexit/double pointer return (rdonly, untrusted, nullable) - invalid load with double dereference")
__failure __msg("R3 invalid mem access 'scalar'")
__naked void ctx_double_ptr_return_load3(void)
{
	asm volatile ("				\
	/* load double pointer return value - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 16);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	r3 = *(u64 *)(r2 + 0);		/* R3 is a scalar */	\
	r4 = *(u64 *)(r3 + 0);	    /* load from scalar */\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fexit/bpf_fentry_test12_pptr")
__description("fexit/double pointer return (rdonly, untrusted, nullable) - invalid store to read only memory")
__failure __msg("R2 cannot write into rdonly_untrusted_mem")
__naked void ctx_double_ptr_return_write1(void)
{
	asm volatile ("				\
	/* load double pointer return value - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 16);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	*(u64 *)(r2 + 0) = 1;		/* R2 contains read only memory address */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

SEC("fexit/bpf_fentry_test12_pptr")
__description("fexit/double pointer return (rdonly, untrusted, nullable) - invalid store to read only memory with double dereference")
__failure __msg("R3 invalid mem access 'scalar'")
__naked void ctx_double_ptr_return_write2(void)
{
	asm volatile ("				\
	/* load double pointer return value - PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED | PTR_MAYBE_NULL */\
	r2 = *(u64 *)(r1 + 16);		\
	if r2 == 0 goto l0_%=;		/* check for null */\
	r3 = *(u64 *)(r2 + 0);		/* R3 is a scalar */	\
	*(u64 *)(r3 + 0) = 1;		/* mem access for scalar */	\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	::: __clobber_all);
}

struct bpf_fentry_test_pptr_t;

SEC("fentry/bpf_fentry_test11_pptr_nullable")
__description("fexit/double pointer return (rdonly, untrusted, nullable) - bpf helpers with nullable var")
__success __retval(0)
int BPF_PROG(ctx_double_ptr_nulable_var_access_bpf_helpers,
	struct bpf_fentry_test_pptr_t **pptr__nullable)
{
	/* Check compatibility with BPF helpers; NULL checks should not be required. */
	void *ptr;

	bpf_probe_read_kernel(&ptr, sizeof(ptr), pptr__nullable);
	return 0;
}

SEC("fexit/bpf_fentry_test12_pptr")
__description("fexit/double pointer return (rdonly, untrusted, nullable) - bpf helpers with return val")
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
__description("fexit/double pointer return (rdonly, untrusted, nullable) - bpf helpers with nullable var, direct ctx pointer")
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
__description("fexit/double pointer return (rdonly, untrusted, nullable) - bpf helpers with return val, direct ctx pointer")
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


char _license[] SEC("license") = "GPL";
