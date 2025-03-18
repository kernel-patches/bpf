// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u32);
} just_map SEC(".maps");

int ret_user;

#define VAL_ON	7
#define VAL_OFF	3

DEFINE_STATIC_KEY(key1);

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_one_key_likely(void *ctx)
{
	if (bpf_static_branch_likely(&key1))
		ret_user += VAL_ON;
	else
		ret_user += VAL_OFF;

	return 0;
}

DEFINE_STATIC_KEY(key2);

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_one_key_unlikely(void *ctx)
{
	if (bpf_static_branch_unlikely(&key2))
		ret_user += VAL_ON;
	else
		ret_user += VAL_OFF;

	return 0;
}

DEFINE_STATIC_KEY(key3);

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_one_key_multiple(void *ctx)
{
	if (bpf_static_branch_likely(&key3))
		ret_user += VAL_ON;
	else
		ret_user += VAL_OFF;

	bpf_printk("%lu\n", bpf_jiffies64());

	if (bpf_static_branch_unlikely(&key3))
		ret_user += VAL_ON;
	else
		ret_user += VAL_OFF;

	bpf_printk("%lu\n", bpf_jiffies64());

	if (bpf_static_branch_likely(&key3))
		ret_user += VAL_ON;
	else
		ret_user += VAL_OFF;

	return 0;
}

static __always_inline int big_chunk_of_code(volatile int *x)
{
	#pragma clang loop unroll_count(256)
	for (int i = 0; i < 256; i++)
		*x += 1;

	return *x;
}

DEFINE_STATIC_KEY(key4);

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_one_key_long_jump(void *ctx)
{
	int x;

	if (bpf_static_branch_unlikely(&key4)) {
		x = 1744;
		big_chunk_of_code(&x);
		ret_user = x;
	} else {
		x = 744;
		big_chunk_of_code(&x);
		ret_user = x;
	}

	return 0;
}

DEFINE_STATIC_KEY(key5);
DEFINE_STATIC_KEY(key6);

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int check_multiple_keys(void *ctx)
{
	__u64 j = bpf_jiffies64();

	if (bpf_static_branch_likely(&key5))
		ret_user += 1;
	if (bpf_static_branch_unlikely(&key6))
		ret_user += 10;

	bpf_printk("%lu\n", j);

	if (bpf_static_branch_unlikely(&key5))
		ret_user += 1;
	if (bpf_static_branch_likely(&key6))
		ret_user += 10;

	bpf_printk("%lu\n", bpf_jiffies64());

	if (bpf_static_branch_likely(&key5))
		ret_user += 1;
	if (bpf_static_branch_unlikely(&key6))
		ret_user += 10;

	return 0;
}

char _license[] SEC("license") = "GPL";
