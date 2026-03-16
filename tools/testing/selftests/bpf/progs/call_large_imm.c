// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct __sk_buff;

static __attribute__((noinline)) void padding_subprog(void)
{
	asm volatile ("					\
		r0 = 0;					\
		.rept 200000;				\
		r0 += 0;				\
		.endr;					\
	" ::: "r0");
}

static __attribute__((noinline)) int target_subprog(struct __sk_buff *ctx)
{
	volatile int magic_ret = 3;
	return magic_ret;
}

SEC("socket")
int call_large_imm_test(struct __sk_buff *ctx)
{
	int ret = 0;

	if (ctx == (void *)0)
		padding_subprog();

	ret = target_subprog(ctx);

	bpf_printk("Target subprog returned: %d\n", ret);

	return ret;
}

char LICENSE[] SEC("license") = "GPL";
