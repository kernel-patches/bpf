// SPDX-License-Identifier: GPL-2.0-only

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"
#include "../test_kmods/bpf_testmod_kfunc.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} array_map SEC(".maps");

int st_ops3_data;
int timer_nsec;

__noinline static int timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	st_ops3_data = bpf_kfunc_st_ops_test_this_ptr_impl(NULL);
	return 0;
}

SEC("struct_ops")
int BPF_PROG(test1)
{
	struct bpf_timer *timer;
	int key = 0;

	timer = bpf_map_lookup_elem(&array_map, &key);
	if (!timer)
		return 0;

	bpf_timer_init(timer, &array_map, 1);
	bpf_timer_set_callback(timer, timer_cb);
	bpf_timer_start(timer, timer_nsec, 0);
	return 1;
}

SEC("syscall")
__success __retval(1)
int syscall_this_ptr_in_timer(void *ctx)
{
	return bpf_testmod_ops3_call_test_1();
}

SEC(".struct_ops.link")
struct bpf_testmod_ops3 testmod_this_ptr = {
	.test_1 = (void *)test1,
	.data = 1234,
};


