// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

/*
 * A pointer to a scalar walks as untrusted memory, which is probed, but it
 * is __nullable, so a check has to come first all the same.
 */
SEC("struct_ops/test_nullable")
__failure __msg("invalid mem access 'rdonly_untrusted_mem_or_null'")
int BPF_PROG(unchecked_scalar, struct bpf_testmod_nullable_args *args)
{
	return *args->int_or_null;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops3 testmod_nullable_fail = {
	.test_nullable = (void *)unchecked_scalar,
};
