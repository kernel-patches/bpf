// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef int (*func_proto_typedef___match)(long);
typedef int (*func_proto_typedef___overflow)(func_proto_typedef___match);

int proto_out;

SEC("raw_tracepoint/sys_enter")
int core_relo_proto(void *ctx)
{
	proto_out = bpf_core_type_exists(func_proto_typedef___overflow);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
