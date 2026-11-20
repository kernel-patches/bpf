// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Permit pretty deep stack traces */
#define MAX_STACK_RAWTP 100
struct stack_trace_t {
	int pid;
	int kern_stack_size;
	int user_stack_size;
	int user_stack_buildid_size;
	__u64 kern_stack[MAX_STACK_RAWTP];
	__u64 user_stack[MAX_STACK_RAWTP];
	struct bpf_stack_build_id user_stack_buildid[MAX_STACK_RAWTP];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
} perfmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stack_trace_t);
} stackdata_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64[MAX_STACK_RAWTP]);
} rawdata_map SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int bpf_prog1(void *ctx)
{
	int max_len, max_buildid_len, total_size;
	struct stack_trace_t *data;
	long usize, ksize;
	void *raw_data;
	__u32 key = 0;

	data = bpf_map_lookup_elem(&stackdata_map, &key);
	if (!data)
		return 0;

	max_len = MAX_STACK_RAWTP * sizeof(__u64);
	max_buildid_len = MAX_STACK_RAWTP * sizeof(struct bpf_stack_build_id);
	data->pid = bpf_get_current_pid_tgid();
	data->kern_stack_size = bpf_get_stack(ctx, data->kern_stack,
					      max_len, 0);
	data->user_stack_size = bpf_get_stack(ctx, data->user_stack, max_len,
					    BPF_F_USER_STACK);
	data->user_stack_buildid_size = bpf_get_stack(
		ctx, data->user_stack_buildid, max_buildid_len,
		BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);
	bpf_perf_event_output(ctx, &perfmap, 0, data, sizeof(*data));

	/* write both kernel and user stacks to the same buffer */
	raw_data = bpf_map_lookup_elem(&rawdata_map, &key);
	if (!raw_data)
		return 0;

	usize = bpf_get_stack(ctx, raw_data, max_len, BPF_F_USER_STACK);
	if (usize < 0)
		return 0;

	ksize = bpf_get_stack(ctx, raw_data + usize, max_len - usize, 0);
	if (ksize < 0)
		return 0;

	total_size = usize + ksize;
	if (total_size > 0 && total_size <= max_len)
		bpf_perf_event_output(ctx, &perfmap, 0, raw_data, total_size);

	return 0;
}

char _license[] SEC("license") = "GPL";
