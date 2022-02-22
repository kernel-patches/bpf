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

SEC("kprobe.multi/bpf_fentry_tes??")
int test2(struct pt_regs *ctx)
{
	__u64 cookie = bpf_get_attach_cookie(ctx);
	__u64 addr = bpf_get_func_ip(ctx);

	test2_result += (const void *) addr == &bpf_fentry_test1 && cookie == 1;
	test2_result += (const void *) addr == &bpf_fentry_test2 && cookie == 2;
	test2_result += (const void *) addr == &bpf_fentry_test3 && cookie == 3;
	test2_result += (const void *) addr == &bpf_fentry_test4 && cookie == 4;
	test2_result += (const void *) addr == &bpf_fentry_test5 && cookie == 5;
	test2_result += (const void *) addr == &bpf_fentry_test6 && cookie == 6;
	test2_result += (const void *) addr == &bpf_fentry_test7 && cookie == 7;
	test2_result += (const void *) addr == &bpf_fentry_test8 && cookie == 8;

	return 0;
}

__u64 test3_result = 0;

SEC("kretprobe.multi/bpf_fentry_test*")
int test3(struct pt_regs *ctx)
{
	__u64 cookie = bpf_get_attach_cookie(ctx);
	__u64 addr = bpf_get_func_ip(ctx);

	test3_result += (const void *) addr == &bpf_fentry_test1 && cookie == 8;
	test3_result += (const void *) addr == &bpf_fentry_test2 && cookie == 7;
	test3_result += (const void *) addr == &bpf_fentry_test3 && cookie == 6;
	test3_result += (const void *) addr == &bpf_fentry_test4 && cookie == 5;
	test3_result += (const void *) addr == &bpf_fentry_test5 && cookie == 4;
	test3_result += (const void *) addr == &bpf_fentry_test6 && cookie == 3;
	test3_result += (const void *) addr == &bpf_fentry_test7 && cookie == 2;
	test3_result += (const void *) addr == &bpf_fentry_test8 && cookie == 1;

	return 0;
}
