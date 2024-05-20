// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <string.h>
#include <stdbool.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include "bpf_compiler.h"

#define SYSCTL_VALUE_LEN 16
#define SYSCTL_NAME_LEN 128

#define SUCCESS 1
#define FAILURE 0

const char sysctl_updval[SYSCTL_VALUE_LEN];
volatile const unsigned int updval_len;
const char sysctl_name[SYSCTL_NAME_LEN];
volatile const unsigned int name_len;

static __always_inline bool is_expected_name(struct bpf_sysctl *ctx)
{
	char name[SYSCTL_NAME_LEN];
	unsigned int size;

	memset(name, 0, sizeof(name));
	size = bpf_sysctl_get_name(ctx, name, sizeof(name), 0);
	if (size == 0 || size != name_len - 1)
		return 1;

	return bpf_strncmp(name, size, (const char *)sysctl_name) == 0;
}

SEC("cgroup/sysctl")
int cgrp_sysctl_overwrite(struct bpf_sysctl *ctx)
{
	if (!ctx->write)
		return SUCCESS;

	if (!is_expected_name(ctx))
		return SUCCESS;

	if (bpf_sysctl_set_new_value(ctx, (char *)sysctl_updval, updval_len) == 0)
		return SUCCESS;
	return FAILURE;
}

char _license[] SEC("license") = "GPL";
