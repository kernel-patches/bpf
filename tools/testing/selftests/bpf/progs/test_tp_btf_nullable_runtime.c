// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

int monitored_tid;
int calls;
__u64 nonnull_len;
__u64 null_len;

SEC("tp_btf/bpf_testmod_test_nullable_bare_tp")
int BPF_PROG(handle_nullable_runtime,
	     struct bpf_testmod_test_read_ctx *nullable_ctx)
{
	__u32 tid = bpf_get_current_pid_tgid();
	__u64 len;
	int call;

	if (tid != monitored_tid)
		return 0;

	len = nullable_ctx->len;
	call = calls++;

	if (call == 0)
		nonnull_len = len;
	else if (call == 1)
		null_len = len;

	return 0;
}
