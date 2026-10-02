// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint")
int target(struct trace_event_raw_sys_enter *ctx __arg_ctx)
{
	return 0;
}

SEC("?freplace")
int replacement(struct trace_event_raw_sys_enter *ctx __arg_ctx)
{
	return ctx->id;
}

char LICENSE[] SEC("license") = "GPL";
