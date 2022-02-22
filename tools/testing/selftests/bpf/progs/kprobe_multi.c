// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern const void bpf_fentry_test1 __ksym;
extern const void bpf_fentry_test2 __ksym;
extern const void bpf_fentry_test3 __ksym;
extern const void bpf_fentry_test4 __ksym;
extern const void bpf_fentry_test5 __ksym;
extern const void bpf_fentry_test6 __ksym;
extern const void bpf_fentry_test7 __ksym;
extern const void bpf_fentry_test8 __ksym;

/* No tests, just to trigger bpf_fentry_test* through tracing test_run */
SEC("fentry/bpf_modify_return_test")
int BPF_PROG(test1)
{
	return 0;
}

__u64 test2_result = 0;

SEC("kprobe.multi/bpf_fentry_test?")
int test2(struct pt_regs *ctx)
{
	__u64 addr = bpf_get_func_ip(ctx);

	test2_result += (const void *) addr == &bpf_fentry_test1 ||
			(const void *) addr == &bpf_fentry_test2 ||
			(const void *) addr == &bpf_fentry_test3 ||
			(const void *) addr == &bpf_fentry_test4 ||
			(const void *) addr == &bpf_fentry_test5 ||
			(const void *) addr == &bpf_fentry_test6 ||
			(const void *) addr == &bpf_fentry_test7 ||
			(const void *) addr == &bpf_fentry_test8;
	return 0;
}

__u64 test3_result = 0;

SEC("kretprobe.multi/bpf_fentry_test*")
int test3(struct pt_regs *ctx)
{
	__u64 addr = bpf_get_func_ip(ctx);

	test3_result += (const void *) addr == &bpf_fentry_test1 ||
			(const void *) addr == &bpf_fentry_test2 ||
			(const void *) addr == &bpf_fentry_test3 ||
			(const void *) addr == &bpf_fentry_test4 ||
			(const void *) addr == &bpf_fentry_test5 ||
			(const void *) addr == &bpf_fentry_test6 ||
			(const void *) addr == &bpf_fentry_test7 ||
			(const void *) addr == &bpf_fentry_test8;
	return 0;
}
