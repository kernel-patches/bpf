// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "tracing_deny.skel.h"

void test_tracing_deny(void)
{
	/* migrate_disable depends on CONFIG_SMP */
	if (libbpf_find_vmlinux_btf_id("migrate_disable", BPF_TRACE_FENTRY) > 0)
		RUN_TESTS(tracing_deny);
}
