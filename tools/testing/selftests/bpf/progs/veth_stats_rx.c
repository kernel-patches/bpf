// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Oracle and/or its affiliates. */

#include "btf_ptr.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <errno.h>

long ret = 0;
int num_subtests = 0;
int ran_subtests = 0;
s32 veth_stats_btf_id = 0;
s32 veth_obj_id = 0;

#define STRSIZE			2048

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof((x)[0]))
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[STRSIZE]);
} strdata SEC(".maps");

SEC("kprobe/veth_stats_rx")
int veth_stats_rx(struct pt_regs *ctx)
{
	static __u64 flags[] = { 0, BTF_F_COMPACT, BTF_F_ZERO, BTF_F_PTR_RAW,
				 BTF_F_NONAME, BTF_F_COMPACT | BTF_F_ZERO |
				 BTF_F_PTR_RAW | BTF_F_NONAME };
	static struct btf_ptr p = { };
	__u32 btf_ids[] = { 0, 0 };
	__u32 obj_ids[] = { 0, 0 };
	void *ptrs[] = { 0, 0 };
	__u32 key = 0;
	int i, j;
	char *str;

	btf_ids[0] = veth_stats_btf_id;
	obj_ids[0] = veth_obj_id;
	ptrs[0] = (void *)PT_REGS_PARM1_CORE(ctx);

	btf_ids[1] = bpf_core_type_id_kernel(struct net_device);
	ptrs[1] = (void *)PT_REGS_PARM2_CORE(ctx);

	str = bpf_map_lookup_elem(&strdata, &key);
	if (!str)
		return 0;

	for (i = 0; i < ARRAY_SIZE(btf_ids); i++) {
		p.type_id = btf_ids[i];
		p.obj_id = obj_ids[i];
		p.ptr = ptrs[i];
		for (j = 0; j < ARRAY_SIZE(flags); j++) {
			++num_subtests;
			ret = bpf_snprintf_btf(str, STRSIZE, &p, sizeof(p), 0);
			if (ret < 0)
				bpf_printk("returned %d when writing id %d",
					   ret, p.type_id);
			++ran_subtests;
		}
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
