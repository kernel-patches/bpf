// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

#define TEST(NAME, CALLEE) \
	SEC("socket")					\
	__description("r0: " #NAME)	\
	__failure __msg("math between ctx pointer and register with unbounded min value") \
	__naked int check_abnormal_ret_r0_##NAME(void)	\
	{						\
		asm volatile("				\
		r6 = r1;				\
		r2 = r10;				\
		r2 += -8;				\
		call " #CALLEE ";			\
		r6 += r0;				\
		r0 = 0;					\
		exit;					\
	"	:					\
		:					\
		: __clobber_all);			\
	}						\
							\
	SEC("socket")					\
	__description("ref: " #NAME)	\
	__failure __msg("math between ctx pointer and register with unbounded min value") \
	__naked int check_abnormal_ret_ref_##NAME(void)	\
	{						\
		asm volatile("				\
		r6 = r1;				\
		r7 = r10;				\
		r7 += -8;				\
		r2 = r7;				\
		call " #CALLEE ";			\
		r0 = *(u64*)(r7 + 0);			\
		r6 += r0;				\
		exit;					\
	"	:					\
		:					\
		: __clobber_all);			\
	}

TEST(ld_abs, callee_ld_abs);
TEST(ld_ind, callee_ld_ind);
TEST(tail_call, callee_tail_call);

static __naked __noinline __used
int callee_ld_abs(void)
{
	asm volatile("					\
	r6 = r1;					\
	r9 = r2;					\
	.8byte %[ld_abs];				\
	*(u64*)(r9 + 0) = 1;				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm_insn(ld_abs, BPF_LD_ABS(BPF_W, 0))
	: __clobber_all);
}

static __naked __noinline __used
int callee_ld_ind(void)
{
	asm volatile("					\
	r6 = r1;					\
	r7 = 1;						\
	r9 = r2;					\
	.8byte %[ld_ind];				\
	*(u64*)(r9 + 0) = 1;				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm_insn(ld_ind, BPF_LD_IND(BPF_W, BPF_REG_7, 0))
	: __clobber_all);
}

SEC("socket")
__auxiliary __naked
int dummy_prog(void)
{
	asm volatile("r0 = 1; exit;");
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__array(values, void(void));
} map_prog SEC(".maps") = {
	.values = {
		[0] = (void *)&dummy_prog,
	},
};

static __noinline __used
int callee_tail_call(struct __sk_buff *skb, __u64 *foo)
{
	bpf_tail_call(skb, &map_prog, 0);
	*foo = 1;
	return 0;
}

SEC("socket")
__description("r0 not set by tail_call")
__failure __msg("R0 !read_ok")
int check_abnormal_ret_tail_call_fail(struct __sk_buff *skb)
{
	return bpf_tail_call(skb, &map_prog, 0);
}

char _license[] SEC("license") = "GPL";
