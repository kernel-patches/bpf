// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

bool test_cookies;
__u64 fentry_cookie;
__u64 fexit_cookie;
__u64 fsession_cookie;
__u64 test_result_fentry;
__u64 test_result_fexit;
__u64 test_result_fsession_entry;
__u64 test_result_fsession_exit;
__u64 target_1_result;
__u64 target_2_result;

SEC("syscall")
int target_1(void *ctx)
{
	target_1_result++;
	return 1;
}

SEC("syscall")
int target_2(void *ctx)
{
	target_2_result++;
	return 2;
}

SEC("fentry.multi")
int BPF_PROG(test_fentry)
{
	if (!test_cookies || bpf_get_attach_cookie(ctx) == fentry_cookie)
		test_result_fentry++;
	return 0;
}

SEC("fexit.multi")
int BPF_PROG(test_fexit)
{
	if (!test_cookies || bpf_get_attach_cookie(ctx) == fexit_cookie)
		test_result_fexit++;
	return 0;
}

SEC("fsession.multi")
int BPF_PROG(test_fsession)
{
	if (test_cookies && bpf_get_attach_cookie(ctx) != fsession_cookie)
		return 0;

	if (bpf_session_is_return(ctx))
		test_result_fsession_exit++;
	else
		test_result_fsession_entry++;

	return 0;
}
