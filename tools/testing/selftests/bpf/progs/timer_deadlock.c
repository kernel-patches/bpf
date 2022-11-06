// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

int tid = 0;

struct map_value {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
} array_map SEC(".maps");

static int cb(struct bpf_map *map, int *key, struct map_value *val)
{
	return 0;
}

SEC("tc")
int tc_prog(void *ctx)
{
	struct task_struct *current = bpf_get_current_task_btf();
	struct map_value *v, val = {};

	v = bpf_map_lookup_elem(&array_map, &(int){0});
	if (!v)
		return 0;
	bpf_timer_init(&v->timer, &array_map, 0);
	bpf_timer_set_callback(&v->timer, &cb);

	tid = current->pid;
	return bpf_map_update_elem(&array_map, &(int){0}, &val, 0);
}

SEC("fentry/bpf_prog_put")
int fentry_prog(void *ctx)
{
	struct map_value val = {};

	if (tid == bpf_get_current_task_btf()->pid)
		bpf_map_update_elem(&array_map, &(int){0}, &val, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
