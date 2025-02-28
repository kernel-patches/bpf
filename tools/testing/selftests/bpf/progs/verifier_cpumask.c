// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#include "cpumask_common.h"

#define CPUMASK_TEST_MASKLEN (8 * sizeof(u64))

u64 bits[CPUMASK_TEST_MASKLEN];

SEC("syscall")
__success
int BPF_PROG(test_cpumask_fill)
{
	struct bpf_cpumask *mask;
	int ret;

	mask = bpf_cpumask_create();
	if (!mask) {
		err = 1;
		return 0;
	}

	ret = bpf_cpumask_fill((struct cpumask *)mask, bits, CPUMASK_TEST_MASKLEN);
	if (!ret)
		err = 2;

	if (mask)
		bpf_cpumask_release(mask);

	return 0;
}

SEC("syscall")
__description("bpf_cpumask_fill: invalid cpumask target")
__failure __msg("type=scalar expected=fp")
int BPF_PROG(test_cpumask_fill_cpumask_invalid)
{
	struct bpf_cpumask *invalid = (struct bpf_cpumask *)0x123456;
	int ret;

	ret = bpf_cpumask_fill((struct cpumask *)invalid, bits, CPUMASK_TEST_MASKLEN);
	if (!ret)
		err = 2;

	return 0;
}

SEC("syscall")
__description("bpf_cpumask_fill: invalid cpumask source")
__failure __msg("leads to invalid memory access")
int BPF_PROG(test_cpumask_fill_bpf_invalid)
{
	void *garbage = (void *)0x123456;
	struct bpf_cpumask *local;
	int ret;

	local = create_cpumask();
	if (!local) {
		err = 1;
		return 0;
	}

	ret = bpf_cpumask_fill((struct cpumask *)local, garbage, CPUMASK_TEST_MASKLEN);
	if (!ret)
		err = 2;

	bpf_cpumask_release(local);

	return 0;
}

char _license[] SEC("license") = "GPL";
