// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Define the standard kernel tracepoint context structure explicitly
 * to provide the Clang compiler with exact memory offsets.
 */
struct tracepoint_raw_syscalls_sys_enter {
	unsigned long long unused;
	long id;
	unsigned long args[6];
};

__u32 my_pid SEC(".data") = 0;

/* High-performance Per-CPU Array Map to eliminate global lock variance */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} pcpu_hits_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} jmp_table SEC(".maps");

static __always_inline void increment_pcpu_counter(void)
{
	__u32 key = 0;
	__u64 *val;

	val = bpf_map_lookup_elem(&pcpu_hits_map, &key);
	if (val) {
		/* Lockless and stable per-CPU increment without cacheline bounce */
		(*val)++;
	}
}

/* Target Program: The final destination of the tail call */
SEC("tracepoint/raw_syscalls/sys_enter")
int tailcall_bench_target(struct tracepoint_raw_syscalls_sys_enter *ctx)
{
	increment_pcpu_counter();
	return 0;
}

/* bpf2bpf Sub-function driving a tail call to pointerize the counter */
static __noinline int bpf2bpf_tailcall(struct tracepoint_raw_syscalls_sys_enter *ctx)
{
	bpf_tail_call(ctx, &jmp_table, 1);
	return 0;
}

/* Main program: Entry point for filtered syscall tracepoints */
SEC("tracepoint/raw_syscalls/sys_enter")
int tailcall_bench_main(struct tracepoint_raw_syscalls_sys_enter *ctx)
{
	__u32 current_pid = bpf_get_current_pid_tgid() >> 32;

	if (current_pid != my_pid)
		return 0;

	increment_pcpu_counter();

	/*
	 * Branch based on the syscall's first argument from user space.
	 * Alternating between a direct tail call and a bpf2bpf tail call
	 * forces the tail call counter at the target program's prologue to
	 * swing dynamically between a pure scalar value and an inherited
	 * kernel pointer.
	 */
	if (ctx->args[0] & 1) {
		/* Path A: Direct tail call -> pure scalar value */
		bpf_tail_call(ctx, &jmp_table, 1);
	} else {
		/* Path B: bpf2bpf tail call -> inherited kernel pointer */
		bpf2bpf_tailcall(ctx);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
