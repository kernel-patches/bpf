// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

int unused SEC(".percpu.looooooooong");
int data2 SEC(".percpu.data");
int data SEC(".percpu") = -1;
int nums[7] SEC(".percpu");
char run SEC(".percpu") = 0;
struct {
	char set;
	int i;
	int nums[7];
} struct_data SEC(".percpu") = {
	.set = 0,
	.i = -1,
};

SEC("raw_tp/task_rename")
__auxiliary
int update_percpu_data(void *ctx)
{
	struct_data.nums[6] = 0xc0de;
	struct_data.set = 1;
	struct_data.i = 1;
	nums[6] = 0xc0de;
	data = 1;
	run = 1;
	return 0;
}

char _license[] SEC("license") = "GPL";
