// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "exceptions_cleanup.h"

/* Without a 32-bit int in BTF, libbpf's dummy_ksym var gets type id 0. */
int btf_int_anchor;

SEC("freplace/fr_callee")
__u64 new_fr_callee(__u64 x)
{
	bpf_throw(THROW_COOKIE);
	return 0;
}

char _license[] SEC("license") = "GPL";
