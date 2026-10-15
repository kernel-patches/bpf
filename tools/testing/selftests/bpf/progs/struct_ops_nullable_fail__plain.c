// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

/*
 * Through a plain pointer the member is probed, which would tolerate NULL,
 * but it is __nullable, so a check has to come first all the same.
 */
SEC("struct_ops/test_nullable")
__failure __msg("invalid mem access 'ptr_or_null_'")
int BPF_PROG(unchecked_plain, struct bpf_testmod_nullable_args *args)
{
	return args->self->task_or_null->pid;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops3 testmod_nullable_fail = {
	.test_nullable = (void *)unchecked_plain,
};
