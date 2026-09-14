// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

enum core_reloc_truncated_ldimm64 {
	CORE_RELOC_TRUNCATED_LDIMM64_VALUE,
};

SEC("raw_tracepoint/sys_enter")
int core_reloc_truncated_ldimm64_resolved(void *ctx)
{
	return bpf_core_enum_value_exists(enum core_reloc_truncated_ldimm64,
					  CORE_RELOC_TRUNCATED_LDIMM64_VALUE);
}

SEC("raw_tracepoint/sys_exit")
int core_reloc_truncated_ldimm64_poison(void *ctx)
{
	return bpf_core_enum_value(enum core_reloc_truncated_ldimm64,
				   CORE_RELOC_TRUNCATED_LDIMM64_VALUE);
}

char LICENSE[] SEC("license") = "GPL";
