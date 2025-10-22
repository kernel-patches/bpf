// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 test1_entry_result = 0;
__u64 test1_exit_result = 0;

SEC("fsession/bpf_fentry_test5")
int BPF_PROG(test1, __u64 a, void *b, short c, int d, __u64 e, int ret)
{
	__u64 *cookie = bpf_fsession_cookie(ctx);

	if (!bpf_tracing_is_exit(ctx)) {
		test1_entry_result = a == 11 && b == (void *)12 && c == 13 && d == 14 &&
			e == 15 && ret == 0;
		*cookie = 0x123456ULL;
		return 0;
	}

	test1_exit_result = a == 11 && b == (void *)12 && c == 13 && d == 14 &&
		e == 15 && ret == 65 && *cookie == 0x123456ULL;
	return 0;
}

__u64 test2_result = 0;
SEC("fexit/bpf_fentry_test5")
int BPF_PROG(test2, __u64 a, void *b, short c, int d, __u64 e, int ret)
{
	test2_result = a == 11 && b == (void *)12 && c == 13 && d == 14 &&
		e == 15 && ret == 65;
	return 0;
}

__u64 test3_result = 0;
SEC("fentry/bpf_fentry_test5")
int BPF_PROG(test3, __u64 a, void *b, short c, int d, __u64 e)
{
	test3_result = a == 11 && b == (void *)12 && c == 13 && d == 14 &&
		e == 15;
	return 0;
}
