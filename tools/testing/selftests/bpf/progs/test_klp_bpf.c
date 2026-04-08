// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/test_klp_bpf.h"

char _license[] SEC("license") = "GPL";

extern void bpf_klp_seq_write(struct seq_file *m,
			      const char *data, u32 data__sz) __ksym;

SEC("struct_ops/set_cmdline")
int BPF_PROG(set_cmdline, struct seq_file *m)
{
	char custom[] = "klp_bpf: custom cmdline\n";

	bpf_klp_seq_write(m, custom, sizeof(custom) - 1);
	return 0;
}

SEC(".struct_ops.link")
struct klp_bpf_cmdline_ops cmdline_ops = {
	.set_cmdline = (void *)set_cmdline,
};
