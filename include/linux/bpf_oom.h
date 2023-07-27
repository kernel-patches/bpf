/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _BPF_OOM_H
#define _BPF_OOM_H

#include <linux/bpf.h>
#include <linux/filter.h>
#include <uapi/linux/bpf.h>

struct bpf_oom_policy {
	struct bpf_prog_array __rcu	*progs;
};

int oom_policy_prog_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int oom_policy_prog_detach(const union bpf_attr *attr);
int oom_policy_prog_query(const union bpf_attr *attr, union bpf_attr __user *uattr);

int __bpf_run_oom_policy(u64 cg_id_1, u64 cg_id_2);

bool bpf_oom_policy_enabled(void);

#endif
