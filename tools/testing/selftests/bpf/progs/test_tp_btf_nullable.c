// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"
#include "bpf_misc.h"

SEC("tp_btf/bpf_testmod_test_nullable_bare_tp")
__success
int BPF_PROG(handle_tp_btf_nullable_bare1, struct bpf_testmod_test_read_ctx *nullable_ctx)
{
	return nullable_ctx->len;
}

SEC("tp_btf/bpf_testmod_test_nullable_bare_tp")
int BPF_PROG(handle_tp_btf_nullable_bare2, struct bpf_testmod_test_read_ctx *nullable_ctx)
{
	if (nullable_ctx)
		return nullable_ctx->len;
	return 0;
}

SEC("tp_btf/bpf_testmod_test_nullable_bare_tp")
__success
int BPF_PROG(handle_tp_btf_nullable_mem, struct bpf_testmod_test_read_ctx *nullable_ctx)
{
	return nullable_ctx->buf[0];
}

SEC("tp_btf/bpf_testmod_test_nullable_bare_tp")
__failure __msg("pointer arithmetic on trusted_ptr_or_null_ prohibited")
int BPF_PROG(handle_tp_btf_nullable_arith, struct bpf_testmod_test_read_ctx *nullable_ctx)
{
	asm volatile("%[ctx] += 1" : [ctx] "+r"(nullable_ctx));
	return nullable_ctx->len;
}

SEC("tp_btf/bpf_testmod_test_nullable_bare_tp")
__failure __msg("invalid mem access 'trusted_ptr_or_null_'")
int BPF_PROG(handle_tp_btf_nullable_atomic_rmw,
	     struct bpf_testmod_test_read_ctx *nullable_ctx)
{
	asm volatile ("r1 = %[ctx];"
		      "w2 = 1;"
		      "lock *(u32 *)(r1 + %[len]) += w2;"
		      :
		      : [ctx] "r"(nullable_ctx),
			__imm_const(len,
				    offsetof(struct bpf_testmod_test_read_ctx,
					     len))
		      : "r1", "r2", "memory");
	return 0;
}

#ifdef __BPF_FEATURE_LOAD_ACQ_STORE_REL
SEC("tp_btf/bpf_testmod_test_nullable_bare_tp")
__failure
__msg("BPF_ATOMIC loads from R{{[0-9]+}} trusted_ptr_or_null_")
int BPF_PROG(handle_tp_btf_nullable_load_acquire,
	     struct bpf_testmod_test_read_ctx *nullable_ctx)
{
	return __atomic_load_n(&nullable_ctx->len, __ATOMIC_ACQUIRE);
}
#endif

char _license[] SEC("license") = "GPL";
