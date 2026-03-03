// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

int dummy_run;
u64 data;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_dummy SEC(".maps");

#if defined(__TARGET_ARCH_x86)
SEC("?kprobe")
int dummy_kprobe(void *ctx)
{
	dummy_run++;
	bpf_tail_call_static(ctx, &prog_array_dummy, 0);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_kprobe SEC(".maps");

SEC("?kprobe")
int kprobe(struct pt_regs *regs)
{
	data = regs->di = 0;
	bpf_tail_call_static(regs, &prog_array_kprobe, 0);
	return 0;
}

SEC("?kprobe")
int kprobe_tailcall(struct pt_regs *regs)
{
	bpf_tail_call_static(regs, &prog_array_kprobe, 0);
	return 0;
}
#endif

SEC("?fentry/bpf_fentry_test1")
int dummy_fentry(void *ctx)
{
	dummy_run++;
	bpf_tail_call_static(ctx, &prog_array_dummy, 0);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_tracing SEC(".maps");

SEC("?fentry/bpf_fentry_test1")
int BPF_PROG(fentry)
{
	data = bpf_get_func_ip(ctx);
	bpf_tail_call_static(ctx, &prog_array_tracing, 0);
	return 0;
}

SEC("?fentry/bpf_fentry_test1")
int BPF_PROG(fentry_tailcall)
{
	bpf_tail_call_static(ctx, &prog_array_tracing, 0);
	return 0;
}

SEC("?fsession/bpf_fentry_test2")
int dummy_fsession(void *ctx)
{
	dummy_run++;
	bpf_tail_call_static(ctx, &prog_array_dummy, 0);
	return 0;
}

SEC("?fsession/bpf_fentry_test2")
int BPF_PROG(fsession_cookie)
{
	u64 *cookie = bpf_session_cookie(ctx);

	data = *cookie = 0;
	bpf_tail_call_static(ctx, &prog_array_tracing, 0);
	return 0;
}

SEC("?fsession/bpf_fentry_test2")
int BPF_PROG(fsession_tailcall)
{
	bpf_tail_call_static(ctx, &prog_array_tracing, 0);
	return 0;
}
