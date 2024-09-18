// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright 2024 Bytedance.
 */

#include <errno.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__u32 classid = 0;

SEC("cgroup_skb/egress")
int cg_skb_classid(struct __sk_buff *ctx)
{
	classid = bpf_skb_cgroup_classid(ctx);

	return 1;
}
