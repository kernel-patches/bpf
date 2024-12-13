// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

#define TEST(NAME, CALLEE) \
	SEC("socket")					\
	__description("abnormal_ret: " #NAME)		\
	__failure __msg("math between ctx pointer and register with unbounded min value") \
	__naked void check_abnormal_ret_##NAME(void)	\
	{						\
		asm volatile("				\
		r6 = r1;				\
		call " #CALLEE ";			\
		r6 += r0;				\
		r0 = 0;					\
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
	.8byte %[ld_abs];				\
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
	.8byte %[ld_ind];				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm_insn(ld_ind, BPF_LD_IND(BPF_W, BPF_REG_7, 0))
	: __clobber_all);
}

SEC("socket")
__auxiliary __naked
void dummy_prog(void)
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

static __naked __noinline __used
int callee_tail_call(void)
{
	asm volatile("					\
	r2 = %[map_prog] ll;				\
	r3 = 0;						\
	call %[bpf_tail_call];				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_tail_call), __imm_addr(map_prog)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
