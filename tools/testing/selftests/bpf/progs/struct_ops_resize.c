// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

char resizable[1] SEC(".data.resizable");

SEC("struct_ops/test_1")
int BPF_PROG(test_1)
{
	return 0;
}

struct bpf_testmod_ops {
	int (*test_1)(void);
};

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod = {
	.test_1 = (void *)test_1
};
