// SPDX-License-Identifier: GPL-2.0
/* Programs above the limits that the verifier used to have, and unsafe twins of them */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

#define REP10(M, p) M(p##0) M(p##1) M(p##2) M(p##3) M(p##4) M(p##5) M(p##6) M(p##7) M(p##8) M(p##9)
#define REP100(M, p) REP10(M, p##0) REP10(M, p##1) REP10(M, p##2) REP10(M, p##3) REP10(M, p##4) \
		     REP10(M, p##5) REP10(M, p##6) REP10(M, p##7) REP10(M, p##8) REP10(M, p##9)

/* 100 maps */

#define MAP(n) char map##n[8] SEC(".data.map" #n) = { 1 };
#define MAP_READ(n) "r1 = map" #n " ll; r1 = *(u8 *)(r1 + 0); r0 += r1;"
REP100(MAP, 1)

SEC("?tc")
__success __retval(100)
__naked void maps_100(void)
{
	asm volatile ("r0 = 0;" REP100(MAP_READ, 1) "exit;" ::: __clobber_all);
}

SEC("?tc")
__failure __msg("invalid access to map value, value_size=8 off=8 size=1")
__naked void maps_100_bad(void)
{
	asm volatile ("r0 = 0;" REP100(MAP_READ, 1) "r1 = map199 ll; r0 = *(u8 *)(r1 + 8); exit;"
		      ::: __clobber_all);
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} jmp_table SEC(".maps");

/* 1100 subprogs */

#define REP1100(M) REP100(M, 10) REP100(M, 11) REP100(M, 12) REP100(M, 13) REP100(M, 14) \
		   REP100(M, 15) REP100(M, 16) REP100(M, 17) REP100(M, 18) REP100(M, 19) \
		   REP100(M, 20)
#define FUNC(n) __naked __noinline __used static void func##n(void) \
		{ asm volatile ("r0 = r1; r0 += 1; r2 = 0; exit;"); }
#define FUNC_CALL(n) "r1 = r0; call func" #n ";"
REP1100(FUNC)

SEC("?tc")
__success __retval(1100)
__naked void subprogs_1100(void)
{
	asm volatile ("r0 = 0;" REP1100(FUNC_CALL) "exit;" ::: __clobber_all);
}

SEC("?tc")
__failure __msg("invalid mem access 'scalar'")
__naked void subprogs_1100_bad(void)
{
	asm volatile ("r0 = 0;" REP1100(FUNC_CALL) "r0 = *(u8 *)(r0 + 0); exit;" ::: __clobber_all);
}

/* Calls in dead code do not count. Only the main pass knows that (x & 7) > 7 is false. */

#define DEAD_IF(limit)			\
	"call %[bpf_get_prandom_u32];"	\
	"r0 &= 7;"			\
	"if r0 <= " #limit " goto 1f;"

#define RECURSION(name, limit)					\
__naked __noinline __used static void name##_func(void)	\
{								\
	asm volatile (						\
	DEAD_IF(limit)						\
	"call " #name "_func;"					\
"1:	r0 = 0;"						\
	"exit;"							\
	:: __imm(bpf_get_prandom_u32) : __clobber_all);		\
}								\
__naked void name(void)						\
{								\
	asm volatile ("call " #name "_func; exit;" ::: __clobber_all); \
}

void dead_recursion(void) SEC("?raw_tp") __success;
RECURSION(dead_recursion, 7)

void live_recursion(void) SEC("?raw_tp") __failure __msg("in a tracing program");
RECURSION(live_recursion, 6)

#define TAIL_CALL_IN_CB(name, limit)				\
__naked __noinline __used static void name##_cb(void)		\
{								\
	asm volatile (						\
	"r6 = *(u64 *)(r2 + 0);"				\
	DEAD_IF(limit)						\
	"r1 = r6;"						\
	"r2 = %[jmp_table] ll;"					\
	"r3 = 0;"						\
	"call %[bpf_tail_call];"				\
"1:	r0 = 1;"						\
	"exit;"							\
	:: __imm(bpf_get_prandom_u32), __imm(bpf_tail_call),	\
	   __imm_addr(jmp_table) : __clobber_all);		\
}								\
__naked void name(void)						\
{								\
	asm volatile (						\
	"*(u64 *)(r10 - 8) = r1;"				\
	"r1 = 1;"						\
	"r2 = " #name "_cb ll;"					\
	"r3 = r10;"						\
	"r3 += -8;"						\
	"r4 = 0;"						\
	"call %[bpf_loop];"					\
	"exit;"							\
	:: __imm(bpf_loop) : __clobber_all);			\
}

void dead_tail_call_in_cb(void) SEC("?tc") __success __retval(1);
TAIL_CALL_IN_CB(dead_tail_call_in_cb, 7)

void live_tail_call_in_cb(void) SEC("?tc") __failure __msg("tail call");
TAIL_CALL_IN_CB(live_tail_call_in_cb, 6)

/* Many edges to one insn: the dominators take linear time */
SEC("?tc")
__success __retval(0)
__naked void goto_out_30000(void)
{
	asm volatile (
	"r6 = *(u32 *)(r1 + 0);"
	".rept 30000;"
	"if r6 == 1 goto 1f;"
	".endr;"
"1:	r0 = 0;"
	"exit;"
	::: __clobber_all);
}

/* GCC loses the tag of 'struct task_struct __kptr *task[1000]' */
struct one_kptr {
	struct task_struct __kptr *p;
};

/* 1000 kptrs in a map value. The struct is too big for an allocated object. */

struct many_kptrs {
	long x;
	struct task_struct __kptr *first;
	struct one_kptr task[1000];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct many_kptrs);
} kptr_map SEC(".maps");

SEC("?tc")
__success __retval(0)
int kptrs_1000(void *ctx)
{
	struct many_kptrs *v = bpf_map_lookup_elem(&kptr_map, &(int){ 0 });
	struct task_struct *t;

	if (!v)
		return 1;
	t = bpf_kptr_xchg(&v->task[999].p, NULL);
	if (t)
		bpf_task_release(t);
	return v->x;
}

SEC("?tc")
__failure __msg("kptr access misaligned")
int kptrs_1000_bad(void *ctx)
{
	struct many_kptrs *v = bpf_map_lookup_elem(&kptr_map, &(int){ 0 });

	if (!v)
		return 1;
	*(volatile int *)((void *)&v->task[999].p + 4) = 1;
	return 0;
}

SEC("?tc")
__success __retval(1)
int kptrs_1000_obj_new(void *ctx)
{
	struct many_kptrs *p = bpf_obj_new(typeof(*p));

	if (!p)
		return 1;
	bpf_obj_drop(p);
	return 0;
}

/* 500 kptrs in an allocated object */

struct obj_kptrs {
	struct task_struct __kptr *first;
	struct one_kptr task[499];
};

SEC("?tc")
__failure __msg("direct access to kptr is disallowed")
int kptrs_500_obj_bad(void *ctx)
{
	struct obj_kptrs *p = bpf_obj_new(typeof(*p));

	if (!p)
		return 1;
	*(volatile long *)&p->task[498].p = 1;
	bpf_obj_drop(p);
	return 0;
}

char _license[] SEC("license") = "GPL";
