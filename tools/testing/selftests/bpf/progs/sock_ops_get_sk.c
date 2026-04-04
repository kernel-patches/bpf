// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * Test that SOCK_OPS_GET_SK() correctly returns NULL when dst_reg == src_reg
 * and is_fullsock == 0 (e.g., during TCP_NEW_SYN_RECV). Before the fix, the
 * macro failed to zero the destination register, leaving a stale ctx pointer
 * that bypassed the NULL check.
 */

int bug_detected;
int null_seen;

SEC("sockops")
__naked void sock_ops_get_sk_same_reg(void)
{
	asm volatile (
		"r7 = *(u32 *)(r1 + %[is_fullsock_off]);"
		"r1 = *(u64 *)(r1 + %[sk_off]);"
		"if r7 != 0 goto 2f;"
		"if r1 == 0 goto 1f;"
		"r1 = %[bug_detected] ll;"
		"r2 = 1;"
		"*(u32 *)(r1 + 0) = r2;"
		"goto 2f;"
	"1:"
		"r1 = %[null_seen] ll;"
		"r2 = 1;"
		"*(u32 *)(r1 + 0) = r2;"
	"2:"
		"r0 = 1;"
		"exit;"
		:
		: __imm_const(is_fullsock_off, offsetof(struct bpf_sock_ops, is_fullsock)),
		  __imm_const(sk_off, offsetof(struct bpf_sock_ops, sk)),
		  __imm_addr(bug_detected),
		  __imm_addr(null_seen)
		: __clobber_all);
}

char _license[] SEC("license") = "GPL";
