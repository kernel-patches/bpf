// SPDX-License-Identifier: GPL-2.0
#include "btf_ptr.h"
#include <bpf/bpf_helpers.h>

const volatile __u32 const_void_id;
char out[64];
long ret;

SEC("raw_tp/sys_enter")
int dump_const_void(void *ctx)
{
	struct btf_ptr ptr = {
		.ptr = ctx,
		.type_id = const_void_id,
		.flags = 0,
	};

	ret = bpf_snprintf_btf(out, sizeof(out), &ptr, sizeof(ptr), 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
