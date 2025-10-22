// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 ChinaTelecom */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 test1_entry_ok = 0;
__u64 test1_exit_ok = 0;

SEC("fsession/bpf_fentry_test1")
int BPF_PROG(test1, int a)
{
	__u64 *cookie = bpf_fsession_cookie(ctx);

	if (!bpf_tracing_is_exit(ctx)) {
		if (cookie) {
			*cookie = 0xAAAABBBBCCCCDDDDull;
			test1_entry_ok = *cookie == 0xAAAABBBBCCCCDDDDull;
		}
		return 0;
	}

	if (cookie)
		test1_exit_ok = *cookie == 0xAAAABBBBCCCCDDDDull;
	return 0;
}

__u64 test2_entry_ok = 0;
__u64 test2_exit_ok = 0;

SEC("fsession/bpf_fentry_test1")
int BPF_PROG(test2, int a)
{
	__u64 *cookie = bpf_fsession_cookie(ctx);

	if (!bpf_tracing_is_exit(ctx)) {
		if (cookie) {
			*cookie = 0x1111222233334444ull;
			test2_entry_ok = *cookie == 0x1111222233334444ull;
		}
		return 0;
	}

	if (cookie)
		test2_exit_ok = *cookie == 0x1111222233334444ull;
	return 0;
}
