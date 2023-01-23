// SPDX-License-Identifier: GPL-2.0
/* Converted from tools/testing/selftests/bpf/verifier/jeq_infer_not_null.c */
/* Use test_loader marker */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} map_xskmap SEC(".maps");

/* This is equivalent to the following program:
 *
 *   r6 = skb->sk;
 *   r7 = sk_fullsock(r6);
 *   r0 = sk_fullsock(r6);
 *   if (r0 == 0) return 0;    (a)
 *   if (r0 != r7) return 0;   (b)
 *   *r7->type;                (c)
 *   return 0;
 *
 * It is safe to dereference r7 at point (c), because of (a) and (b).
 * The test verifies that relation r0 == r7 is propagated from (b) to (c).
 */
__description("jne/jeq infer not null, PTR_TO_SOCKET_OR_NULL -> PTR_TO_SOCKET for JNE false branch")
__success __failure_unpriv __msg_unpriv("R7 pointer comparison")
SEC("cgroup/skb")
__naked void socket_for_jne_false_branch(void)
{
	asm volatile (
"	r6 = *(u64*)(r1 + %[__sk_buff_sk_offset]);	\n\
	if r6 == 0 goto exit_%=;			\n\
	r1 = r6;					\n\
	call %[bpf_sk_fullsock];			\n\
	r7 = r0;					\n\
	r1 = r6;					\n\
	call %[bpf_sk_fullsock];			\n\
	if r0 == 0 goto exit_%=;			\n\
	if r0 != r7 goto exit_%=;			\n\
	r0 = *(u32*)(r7 + %[bpf_sock_type_offset]);	\n\
exit_%=:						\n\
	r0 = 0;						\n\
	exit;						\n\
"	:
	: [__sk_buff_sk_offset]"i"(offsetof(struct __sk_buff, sk)),
	  [bpf_sock_type_offset]"i"(offsetof(struct bpf_sock, type)),
	  __imm(bpf_sk_fullsock)
	: __clobber_all);
}

/* Same as above, but verify that another branch of JNE still
 * prohibits access to PTR_MAYBE_NULL.
 */
__description("jne/jeq infer not null, PTR_TO_SOCKET_OR_NULL unchanged for JNE true branch")
__failure __msg("R7 invalid mem access 'sock_or_null'")
__failure_unpriv __msg_unpriv("R7 pointer comparison")
SEC("cgroup/skb")
__naked void unchanged_for_jne_true_branch(void)
{
	asm volatile (
"	r6 = *(u64*)(r1 + %[__sk_buff_sk_offset]);	\n\
	if r6 == 0 goto exit_%=;			\n\
	r1 = r6;					\n\
	call %[bpf_sk_fullsock];			\n\
	r7 = r0;					\n\
	r1 = r6;					\n\
	call %[bpf_sk_fullsock];			\n\
	if r0 != 0 goto exit_%=;			\n\
	if r0 != r7 goto l1_%=;				\n\
	goto exit_%=;					\n\
l1_%=:							\n\
	r0 = *(u32*)(r7 + %[bpf_sock_type_offset]);	\n\
exit_%=:						\n\
	r0 = 0;						\n\
	exit;						\n\
"	:
	: [__sk_buff_sk_offset]"i"(offsetof(struct __sk_buff, sk)),
	  [bpf_sock_type_offset]"i"(offsetof(struct bpf_sock, type)),
	  __imm(bpf_sk_fullsock)
	: __clobber_all);
}

/* Same as a first test, but not null should be inferred for JEQ branch */
__description("jne/jeq infer not null, PTR_TO_SOCKET_OR_NULL -> PTR_TO_SOCKET for JEQ true branch")
__success __failure_unpriv __msg_unpriv("R7 pointer comparison")
SEC("cgroup/skb")
__naked void socket_for_jeq_true_branch(void)
{
	asm volatile (
"	r6 = *(u64*)(r1 + %[__sk_buff_sk_offset]);	\n\
	if r6 == 0 goto exit_%=;			\n\
	r1 = r6;					\n\
	call %[bpf_sk_fullsock];			\n\
	r7 = r0;					\n\
	r1 = r6;					\n\
	call %[bpf_sk_fullsock];			\n\
	if r0 == 0 goto exit_%=;			\n\
	if r0 == r7 goto l1_%=;				\n\
	goto exit_%=;					\n\
l1_%=:							\n\
	r0 = *(u32*)(r7 + %[bpf_sock_type_offset]);	\n\
exit_%=:						\n\
	r0 = 0;						\n\
	exit;						\n\
"	:
	: [__sk_buff_sk_offset]"i"(offsetof(struct __sk_buff, sk)),
	  [bpf_sock_type_offset]"i"(offsetof(struct bpf_sock, type)),
	  __imm(bpf_sk_fullsock)
	: __clobber_all);
}

/* Same as above, but verify that another branch of JNE still
 * prohibits access to PTR_MAYBE_NULL.
 */
__description("jne/jeq infer not null, PTR_TO_SOCKET_OR_NULL unchanged for JEQ false branch")
__failure __msg("R7 invalid mem access 'sock_or_null'")
__failure_unpriv __msg_unpriv("R7 pointer comparison")
SEC("cgroup/skb")
__naked void unchanged_for_jeq_false_branch(void)
{
	asm volatile (
"	r6 = *(u64*)(r1 + %[__sk_buff_sk_offset]);	\n\
	if r6 == 0 goto exit_%=;			\n\
	r1 = r6;					\n\
	call %[bpf_sk_fullsock];			\n\
	r7 = r0;					\n\
	r1 = r6;					\n\
	call %[bpf_sk_fullsock];			\n\
	if r0 == 0 goto exit_%=;			\n\
	if r0 == r7 goto exit_%=;			\n\
	r0 = *(u32*)(r7 + %[bpf_sock_type_offset]);	\n\
exit_%=:						\n\
	r0 = 0;						\n\
	exit;						\n\
"	:
	: [__sk_buff_sk_offset]"i"(offsetof(struct __sk_buff, sk)),
	  [bpf_sock_type_offset]"i"(offsetof(struct bpf_sock, type)),
	  __imm(bpf_sk_fullsock)
	: __clobber_all);
}

/* Maps are treated in a different branch of `mark_ptr_not_null_reg`,
 * so separate test for maps case.
 */
__description("jne/jeq infer not null, PTR_TO_MAP_VALUE_OR_NULL -> PTR_TO_MAP_VALUE")
__success
SEC("xdp")
__naked void null_ptr_to_map_value(void)
{
	asm volatile (
"	r1 = 0;						\n\
	*(u32*)(r10 - 8) = r1;				\n\
	r9 = r10;					\n\
	r9 += -8;					\n\
	/* r8 = process local map */			\n\
	r8 = %[map_xskmap] ll;				\n\
	/* r6 = map_lookup_elem(r8, r9); */		\n\
	r1 = r8;					\n\
	r2 = r9;					\n\
	call %[bpf_map_lookup_elem];			\n\
	r6 = r0;					\n\
	/* r7 = map_lookup_elem(r8, r9); */		\n\
	r1 = r8;					\n\
	r2 = r9;					\n\
	call %[bpf_map_lookup_elem];			\n\
	r7 = r0;					\n\
	if r6 == 0 goto exit_%=;			\n\
	if r6 != r7 goto exit_%=;			\n\
	/* read *r7; */					\n\
	r0 = *(u32*)(r7 + %[bpf_xdp_sock_queue_id_offset]);\n\
exit_%=:						\n\
	r0 = 0;						\n\
	exit;						\n\
"	:
	: [bpf_xdp_sock_queue_id_offset]"i"(offsetof(struct bpf_xdp_sock, queue_id)),
	  __imm(bpf_map_lookup_elem),
	  __imm_addr(map_xskmap)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";

