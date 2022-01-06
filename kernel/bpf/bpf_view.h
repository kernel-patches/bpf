// SPDX-License-Identifier: GPL-2.0-only
#ifndef _BPF_VIEW_H_
#define _BPF_VIEW_H_

#include <linux/bpf.h>

#define BPF_VIEW_FUNC_PREFIX "bpf_view_"
#define DEFINE_BPF_VIEW_FUNC(target, args...) \
	extern int bpf_view_ ## target(args); \
	int __init bpf_view_ ## target(args) { return 0; }

#define BPF_VIEW_CTX_ARG_MAX 2

struct bpf_view_cgroup_ctx {
	__bpf_md_ptr(struct seq_file *, seq);
	__bpf_md_ptr(struct cgroup *, cgroup);
};

bool bpf_link_is_view(struct bpf_link *link);

/* Run a bpf_view program */
int run_view_prog(struct bpf_prog *prog, void *ctx);

#endif  // _BPF_VIEW_H_
