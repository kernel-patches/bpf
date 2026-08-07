// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 */

#include "bpf_experimental.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct elem {
	struct bpf_thread_wq twq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct elem);
} map_arr SEC(".maps");

__u64 target_cgroup_id;
__u64 callback_cgroup_id;
int twq_done;
int test_key;

static int twq_callback(void *map, int *key, void *value)
{
	callback_cgroup_id = bpf_get_current_cgroup_id();
	twq_done = 1;
	return 0;
}

SEC("syscall")
int start_thread_wq(void *ctx)
{
	struct elem *val;
	int key = test_key;
	int ret;

	val = bpf_map_lookup_elem(&map_arr, &key);
	if (!val)
		return -1;

	ret = bpf_thread_wq_init(&val->twq, &map_arr, target_cgroup_id, 0);
	if (ret)
		goto out;

	ret = bpf_thread_wq_set_callback(&val->twq, twq_callback, 0);
	if (ret)
		goto out;

	ret = bpf_thread_wq_start(&val->twq, 0);

out:
	return ret;
}
