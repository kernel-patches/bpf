// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops/try_charge_memcg")
int BPF_PROG(test_try_charge_memcg,
	     struct try_charge_memcg *tcm)
{
	return 0;
}

SEC(".struct_ops")
struct memcg_ops mcg_ops = {
	.try_charge_memcg = (void *)test_try_charge_memcg,
};
