/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef _TEST_KLP_BPF_H
#define _TEST_KLP_BPF_H

struct seq_file;

struct klp_bpf_cmdline_ops {
	int (*set_cmdline)(struct seq_file *m);
};

#endif /* _TEST_KLP_BPF_H */
