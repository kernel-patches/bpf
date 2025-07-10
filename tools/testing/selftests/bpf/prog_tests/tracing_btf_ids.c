// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "tracing_btf_ids.skel.h"

void test_tracing_btf_ids(void)
{
	int btf_id;

	// `migrate_disable` depends on `CONFIG_SMP`, may not exists
	btf_id = libbpf_find_vmlinux_btf_id("migrate_disable", BPF_TRACE_FENTRY);
	if (btf_id <= 0)
		return;

	RUN_TESTS(tracing_btf_ids);
}
