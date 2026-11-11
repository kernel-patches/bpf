// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_res_spin_lock rlock;

/*
 * A socket cast to its struct by a helper carries the reference of the
 * socket a lookup acquired: the socket is in the slot the lookup filled at
 * the throw, and the release through the cast pointer clears that slot.
 */
SEC("tc")
__description("frame_desc: a throw with a socket cast to tcp_sock live")
__arch_x86_64 __arch_arm64
__success
int sock_cast_at_throw(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	struct tcp_sock *tp;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		bpf_sk_release(sk);
		return 0;
	}
	if (skb->len > 100)
		bpf_throw(0);
	bpf_sk_release((struct bpf_sock *)tp);
	return 1;
}

/* Nothing reads the socket after the lookup: it is in the slot of the frame at the throw. */
SEC("tc")
__description("frame_desc: a socket read by nothing but the throw")
__arch_x86_64 __arch_arm64
__success
int sock_dead_at_throw(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	bpf_throw(0);
	return 1;
}

static __noinline int throw_unconditionally(void)
{
	bpf_throw(0);
	return 0;
}

/*
 * The callee's throw is unconditional, so the caller never reads the socket
 * again after the call and keeps it nowhere in its stack: the socket is in
 * the hidden slot of the caller's frame, which the lookup filled, and the
 * statistics line reports the slot and the insns that keep it.
 */
SEC("tc")
__description("frame_desc: a socket nothing reads in the caller of a throw")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 1 insns 2 sites 0 classes 1")
int sock_dead_in_caller(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	return throw_unconditionally();
}

static __noinline struct bpf_sock *lookup_in_subprog(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};

	return bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
}

/*
 * The socket was acquired by a subprog that has returned: the call acquired
 * it for the caller, whose frame holds it at the throw in the slot of the
 * call. Nothing is unwound while the subprog holds it, so the lookup in the
 * subprog has no slot.
 */
SEC("tc")
__description("frame_desc: a socket a returned subprog acquired, held at a throw")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 1 insns 2 sites 0 classes 1")
int sock_dead_from_subprog(struct __sk_buff *skb)
{
	struct bpf_sock *sk;

	sk = lookup_in_subprog(skb);
	if (!sk)
		return 0;
	return throw_unconditionally();
}

/*
 * The throw is reached holding the lock, or without it when the lock failed:
 * the address of the lock goes into the slot of the call in front of it, the
 * slot is cleared again when the call did not return 0, and the unlock clears
 * the slot. The statistics line reports the slot and the insns that keep it.
 */
SEC("tc")
__description("frame_desc: a resilient lock that fails leaves its slot empty")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 1 insns 7 sites 0 classes 1")
int res_lock_fails_leaves_slot_empty(struct __sk_buff *skb)
{
	int ret;

	ret = bpf_res_spin_lock(&rlock);
	if (skb->len > 100)
		bpf_throw(0);
	if (!ret)
		bpf_res_spin_unlock(&rlock);
	return ret;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

/*
 * The socket is released before the throw: no frame is unwound while it
 * holds the socket, so nothing keeps track of it.
 */
SEC("tc")
__description("frame_desc: a socket released before the throw has no slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 0 classes 1")
int sock_released_before_throw(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), -1, 0);
	if (!sk)
		return 0;
	bpf_sk_release(sk);
	bpf_throw(0);
	return 1;
}

/*
 * The record is spilled on every path to the throw: the descriptor of the
 * throw names the slot of the program's stack, and the frame has no hidden
 * slot.
 */
SEC("tc")
__description("frame_desc: a record spilled at the throw has no slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int record_spilled_at_throw(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"*(u64 *)(r10 - 8) = r0;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The record is spilled in the caller of the subprog that throws: the
 * descriptor is that of the call, the site the caller is unwound at.
 */
SEC("tc")
__description("frame_desc: a record spilled in the caller of a throw has no slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int record_spilled_in_caller(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"*(u64 *)(r10 - 8) = r0;"
	"call throw_unconditionally;"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve)
	: __clobber_all);
}

/*
 * The record is spilled on one path to the throw and in R6 on the other, and
 * in no other register: the visits of the throw do not agree on where it is,
 * so it is kept in a slot.
 */
SEC("tc")
__description("frame_desc: a record spilled on one path to the throw keeps its slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 1 insns 2 sites 0 classes 1")
__naked int record_spilled_on_one_path(void)
{
	asm volatile (
	"r7 = *(u32 *)(r1 + %[len]);"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r0 = 0;"
	"if r7 == 0 goto 1f;"
	"*(u64 *)(r10 - 8) = r6;"
	"r6 = 0;"
	"1: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/* May throw, and returns when it does not. */
__used static __noinline int throw_maybe(void)
{
	if (bpf_get_prandom_u32() & 1)
		bpf_throw(0);
	return 0;
}

/*
 * The record is spilled in a slot nothing reads again, and two paths join
 * between the spill and the call of a subprog that may throw. The verifier
 * forgets what dead slots hold where paths join, so the call reads every slot
 * of the stack: the spill is still known at the call, and its descriptor
 * names the slot.
 */
SEC("tc")
__description("frame_desc: a spill nothing reads again is found at a call that may throw")
__arch_x86_64 __arch_arm64
__success __log_level(5) __flag(BPF_F_TEST_STATE_FREQ)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int dead_spill_at_call(void)
{
	asm volatile (
	"r8 = *(u32 *)(r1 + %[len]);"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"*(u64 *)(r10 - 8) = r6;"
	"if r8 == 0 goto 1f;"
	"r7 = 0;"
	"1: call throw_maybe;"
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard),
	  [len]"i"(offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/*
 * The record is in R6 when the frame throws: the descriptor of the throw
 * names the register.
 */
SEC("tc")
__description("frame_desc: a record in R6 at the throw has no slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int record_in_r6_at_throw(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r6 = r0;"
	"r0 = 0;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The record is in R0 only, where the call that reserved it left it: the
 * unwinder has every register of the frame that throws.
 */
SEC("tc")
__description("frame_desc: a record in R0 at the throw has no slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int record_in_r0_at_throw(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The record is in R6 in the caller of the subprog that may throw: R6 is
 * callee-saved, so the unwinder has it for a frame in a call, and the
 * descriptor of the call names it.
 */
SEC("tc")
__description("frame_desc: a record in R6 in the caller of a throw has no slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int record_in_r6_in_caller(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r6 = r0;"
	"call throw_maybe;"
	"r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/*
 * The record is in R2 only in the caller of the subprog that throws, a
 * register the call does not preserve: the unwinder has it for the frame that
 * throws only, so the record is kept in a slot.
 */
SEC("tc")
__description("frame_desc: a record in R2 in the caller of a throw keeps its slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 1 insns 2 sites 0 classes 1")
__naked int record_in_r2_in_caller(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r2 = r0;"
	"r0 = 0;"
	"call throw_unconditionally;"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve)
	: __clobber_all);
}

/*
 * The record is in R6, which nothing reads again, and two paths join in front
 * of the throw. The verifier forgets what dead registers hold where paths
 * join, so the throw reads the registers: the record is still known to be in
 * R6 at the throw, and its descriptor names the register.
 */
SEC("tc")
__description("frame_desc: a register nothing reads again is found at the throw")
__arch_x86_64 __arch_arm64
__success __log_level(5) __flag(BPF_F_TEST_STATE_FREQ)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int dead_reg_at_throw(void)
{
	asm volatile (
	"r8 = *(u32 *)(r1 + %[len]);"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 2f;"
	"r6 = r0;"
	"r0 = 0;"
	"if r8 == 0 goto 1f;"
	"r7 = 0;"
	"1: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/* An iterator is on the stack wherever it is held: the descriptor of the throw names it. */
SEC("tc")
__description("frame_desc: an iterator at the throw has no slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
int iter_at_throw(struct __sk_buff *skb)
{
	struct bpf_iter_num it;
	int *v;

	bpf_iter_num_new(&it, 0, 10);
	while ((v = bpf_iter_num_next(&it))) {
		if (*v == 3 && skb->len > 100)
			bpf_throw(0);
	}
	bpf_iter_num_destroy(&it);
	return 0;
}

/*
 * BTF FUNC records are not generated for kfuncs that only inline assembly
 * refers to, and libbpf needs them to link the programs.
 */
void __kfunc_btf_root(void)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
}

/*
 * Every path to the throw is in one RCU read section: the descriptor of the
 * throw says so, and the frame does not count its sections.
 */
SEC("tc")
__description("frame_desc: a section at the throw has no count")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int rcu_at_throw(void)
{
	asm volatile (
	"call %[bpf_rcu_read_lock];"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm(bpf_rcu_read_lock),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * One path to the throw is in an RCU read section and the other is not: the
 * frame counts its sections in a slot, which starts at zero and which the
 * lock adds one to.
 */
SEC("tc")
__description("frame_desc: a section on one path to the throw is counted")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 1 insns 4 sites 0 classes 1")
__naked int rcu_on_one_path(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[len]);"
	"if r6 == 0 goto 1f;"
	"call %[bpf_rcu_read_lock];"
	"1: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"exit;"
	:
	: __imm(bpf_rcu_read_lock),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/* Discards the record in R1. */
__naked __noinline __used
static long discard_record(void)
{
	asm volatile (
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ringbuf_discard)
	: __clobber_all);
}

/*
 * The callee discards the record its caller passes it and keeps in R6. The
 * throw in front of the call finds the record in the register and the one
 * after it finds nothing held: the record has no slot, so the call that hands
 * it to the callee has none to empty.
 */
SEC("tc")
__description("frame_desc: a callee discards what its caller holds without a slot")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int callee_releases_no_slot(void)
{
	asm volatile (
	"r7 = *(u32 *)(r1 + %[len]);"
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 3f;"
	"r6 = r0;"
	"r0 = 0;"
	"if r7 != 1 goto 1f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r6;"
	"call discard_record;"
	"if r7 != 2 goto 2f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"2: r0 = 0;"
	"3: exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len))
	: __clobber_all);
}

/* A choice the callees below read without a call, which would clobber their argument. */
__u32 throw_flag;

/*
 * Keeps the record its caller hands it in R6 and discards it, and may throw
 * in front of the discard and after it.
 */
__used __naked static __noinline int consume_record(void)
{
	asm volatile (
	"r6 = r1;"
	"r7 = %[throw_flag] ll;"
	"r7 = *(u32 *)(r7 + 0);"
	"if r7 != 1 goto 1f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r6;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"if r7 != 2 goto 2f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(throw_flag),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The caller hands the record to a callee that discards it and keeps no copy
 * of it. The record is the callee's from the call on: the throw in front of
 * the discard finds it in R6 of the callee, the one after it finds nothing,
 * and no frame keeps a slot.
 */
SEC("tc")
__description("frame_desc: a callee that is handed a record holds it in a register")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int callee_consumes_record(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r1 = r0;"
	"r0 = 0;"
	"call consume_record;"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve)
	: __clobber_all);
}

/* Discards the record its caller hands it, or throws with the cookie in its place in R1. */
__used __naked static __noinline int consume_or_lose_record(void)
{
	asm volatile (
	"r2 = %[throw_flag] ll;"
	"r2 = *(u32 *)(r2 + 0);"
	"if r2 != 1 goto 1f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(throw_flag),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_throw)
	: __clobber_all);
}

/*
 * The callee has the record it is handed nowhere when it throws, so it keeps
 * it in a slot of its own: its entry stores the argument there, and the
 * discard clears the slot.
 */
SEC("tc")
__description("frame_desc: a callee that is handed a record keeps it in a slot of its own")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 1 insns 4 sites 0 classes 1")
__naked int callee_consumes_record_slot(void)
{
	asm volatile (
	"r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 1f;"
	"r1 = r0;"
	"r0 = 0;"
	"call consume_or_lose_record;"
	"1: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve)
	: __clobber_all);
}

private(B) struct bpf_spin_lock slock;

/* Unlocks the lock its caller took. */
__used static __noinline int unlock_slock(void)
{
	bpf_spin_unlock(&slock);
	return 0;
}

/*
 * The lock of a global variable is at a fixed address, which the descriptor
 * of the throw gives: it has no slot, so the callee that unlocks it has none
 * to empty.
 */
SEC("tc")
__description("frame_desc: a callee unlocks the lock its caller holds at a throw")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 0 insns 0 sites 1 classes 1")
__naked int callee_unlocks(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[len]);"
	"r1 = %[slock] ll;"
	"call %[bpf_spin_lock];"
	"if r6 != 1 goto 1f;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: call unlock_slock;"
	"r0 = 0;"
	"exit;"
	:
	: __imm_addr(slock),
	  __imm(bpf_spin_lock),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len))
	: __clobber_all);
}

struct lock_value {
	int data;
	struct bpf_spin_lock lock;
};

/* Two elements, so that a lock of one is found through the pointer to it, not at a fixed address. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct lock_value);
	__uint(max_entries, 2);
} lock_values SEC(".maps");

/* Unlocks the lock of the value its caller locked. */
__used static __noinline int unlock_value(struct lock_value *val)
{
	bpf_spin_unlock(&val->lock);
	return 0;
}

/*
 * The frame has the pointer to the value nowhere at the throw, so the lock is
 * in a slot of the caller: stored in front of the lock, empty at the entry,
 * and emptied in front of the call of the callee that unlocks, which cannot
 * reach it.
 */
SEC("tc")
__description("frame_desc: the caller empties the slot of a lock its callee unlocks")
__arch_x86_64 __arch_arm64
__success __log_level(5)
__msg("frame descriptors: slots 1 insns 3 sites 0 classes 1")
__naked int callee_unlocks_slot(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + %[len]);"
	"r1 = 0;"
	"*(u32 *)(r10 - 4) = r1;"
	"r1 = %[lock_values] ll;"
	"r2 = r10;"
	"r2 += -4;"
	"call %[bpf_map_lookup_elem];"
	"if r0 == 0 goto 2f;"
	"r7 = r0;"
	"r1 = r7;"
	"r1 += %[lock_off];"
	"call %[bpf_spin_lock];"
	"if r6 != 1 goto 1f;"
	"r7 = 0;"
	"r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"1: r1 = r7;"
	"call unlock_value;"
	"2: r0 = 0;"
	"exit;"
	:
	: __imm_addr(lock_values),
	  __imm(bpf_map_lookup_elem),
	  __imm(bpf_spin_lock),
	  __imm(bpf_throw),
	  [len]"i"(offsetof(struct __sk_buff, len)),
	  [lock_off]"i"(offsetof(struct lock_value, lock))
	: __clobber_all);
}

/*
 * A loop the verifier walks reserves a record at one insn on each of two
 * iterations, the first kept in R7 and the second spilled: the call has one
 * slot in the frame, which cannot hold both records.
 */
SEC("tc")
__description("frame_desc: two records reserved at one insn are held at once")
__arch_x86_64 __arch_arm64
__failure __msg("a frame holds two resources of insn 6 at once")
__naked int release_one_of_several(void)
{
	asm volatile (
	"r7 = 0;"
	"r6 = 0;"
	"1: r1 = %[ringbuf] ll;"
	"r2 = 8;"
	"r3 = 0;"
	"call %[bpf_ringbuf_reserve];"
	"if r0 == 0 goto 5f;"
	"if r7 != 0 goto 2f;"
	"r7 = r0;"
	"goto 3f;"
	"2: *(u64 *)(r10 - 8) = r0;"
	"3: r6 += 1;"
	"if r6 < 2 goto 1b;"
	"call %[bpf_get_prandom_u32];"
	"if r0 == 0 goto 4f;"
	"r1 = r7;"
	"call discard_record;"
	"4: r1 = 0xeB9F;"
	"call %[bpf_throw];"
	"5: if r7 == 0 goto 6f;"
	"r1 = r7;"
	"r2 = 0;"
	"call %[bpf_ringbuf_discard];"
	"6: r0 = 0;"
	"exit;"
	:
	: __imm_addr(ringbuf),
	  __imm(bpf_ringbuf_reserve),
	  __imm(bpf_ringbuf_discard),
	  __imm(bpf_get_prandom_u32),
	  __imm(bpf_throw)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
