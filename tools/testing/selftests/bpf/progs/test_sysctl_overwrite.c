// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <string.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include "bpf_compiler.h"

static const char sysctl_value[] = "31337";
static const char sysctl_name[] = "net/ipv4/ip_local_reserved_ports";
static __always_inline int is_expected_name(struct bpf_sysctl *ctx)
{
	unsigned char i;
	char name[sizeof(sysctl_name)];
	int ret;

	memset(name, 0, sizeof(name));
	ret = bpf_sysctl_get_name(ctx, name, sizeof(name), 0);
	if (ret < 0 || ret != sizeof(sysctl_name) - 1)
		return 0;

	__pragma_loop_unroll_full
	for (i = 0; i < sizeof(sysctl_name); ++i)
		if (name[i] != sysctl_name[i])
			return 0;

	return 1;
}

SEC("cgroup/sysctl")
int test_value_overwrite(struct bpf_sysctl *ctx)
{
	if (!ctx->write)
		return 1;

	if (!is_expected_name(ctx))
		return 0;

	if (bpf_sysctl_set_new_value(ctx, sysctl_value, sizeof(sysctl_value)) == 0)
		return 1;
	return 0;
}

char _license[] SEC("license") = "GPL";
