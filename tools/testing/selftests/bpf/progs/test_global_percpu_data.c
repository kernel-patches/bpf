// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int data SEC(".percpu") = -1;
char run SEC(".percpu") = 0;
int nums[7] SEC(".percpu");
struct {
	char set;
	int i;
	int nums[7];
} struct_data SEC(".percpu") = {
	.set = 0,
	.i = -1,
};

SEC("raw_tp/task_rename")
int update_percpu_data(struct __sk_buff *skb)
{
	data = 1;
	run = 1;
	nums[6] = 0xc0de;

	struct_data.i = 1;
	struct_data.set = 1;
	struct_data.nums[6] = 0xc0de;

	return 0;
}

char _license[] SEC("license") = "GPL";
