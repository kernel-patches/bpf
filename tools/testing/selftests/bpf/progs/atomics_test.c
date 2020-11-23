// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u64 add64_value = 1;
__u64 add64_result;
__u32 add32_value = 1;
__u32 add32_result;
__u64 add_stack_value_copy;
__u64 add_stack_result;
SEC("fentry/bpf_fentry_test1")
int BPF_PROG(add, int a)
{
	__u64 add_stack_value = 1;

	add64_result = __sync_fetch_and_add(&add64_value, 2);
	add32_result = __sync_fetch_and_add(&add32_value, 2);
	add_stack_result = __sync_fetch_and_add(&add_stack_value, 2);
	add_stack_value_copy = add_stack_value;

	return 0;
}

__u64 cmpxchg64_value = 1;
__u64 cmpxchg64_result_fail;
__u64 cmpxchg64_result_succeed;
__u32 cmpxchg32_value = 1;
__u32 cmpxchg32_result_fail;
__u32 cmpxchg32_result_succeed;
SEC("fentry/bpf_fentry_test1")
int BPF_PROG(cmpxchg, int a)
{
	cmpxchg64_result_fail = __sync_val_compare_and_swap(
		&cmpxchg64_value, 0, 3);
	cmpxchg64_result_succeed = __sync_val_compare_and_swap(
		&cmpxchg64_value, 1, 2);

	cmpxchg32_result_fail = __sync_val_compare_and_swap(
		&cmpxchg32_value, 0, 3);
	cmpxchg32_result_succeed = __sync_val_compare_and_swap(
		&cmpxchg32_value, 1, 2);

	return 0;
}

__u64 xchg64_value = 1;
__u64 xchg64_result;
__u32 xchg32_value = 1;
__u32 xchg32_result;
SEC("fentry/bpf_fentry_test1")
int BPF_PROG(xchg, int a)
{
	__u64 val64 = 2;
	__u32 val32 = 2;

	__atomic_exchange(&xchg64_value, &val64, &xchg64_result, __ATOMIC_RELAXED);
	__atomic_exchange(&xchg32_value, &val32, &xchg32_result, __ATOMIC_RELAXED);

	return 0;
}
