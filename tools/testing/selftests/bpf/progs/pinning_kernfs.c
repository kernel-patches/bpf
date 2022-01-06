// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Google */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_map_def SEC("maps") wait_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u64),
	.max_entries = 65532,
};

/* task_group() from kernel/sched/sched.h */
static struct task_group *task_group(struct task_struct *p)
{
	return p->sched_task_group;
}

static struct cgroup *task_cgroup(struct task_struct *p)
{
	struct task_group *tg;

	tg = task_group(p);
	return tg->css.cgroup;
}

/* cgroup_id() from linux/cgroup.h */
static __u64 cgroup_id(const struct cgroup *cgroup)
{
	return cgroup->kn->id;
}

SEC("tp_btf/sched_stat_wait")
int BPF_PROG(wait_record, struct task_struct *p, __u64 delta)
{
	struct cgroup *cgrp;
	__u64 *wait_ns;
	__u64 id;

	cgrp = task_cgroup(p);
	if (!cgrp)
		return 0;

	id = cgroup_id(cgrp);
	wait_ns = bpf_map_lookup_elem(&wait_map, &id);

	/* record the max wait latency seen so far */
	if (!wait_ns)
		bpf_map_update_elem(&wait_map, &id, &delta, BPF_NOEXIST);
	else if (*wait_ns < delta)
		*wait_ns = delta;
	return 0;
}

SEC("view/cgroup")
int BPF_PROG(wait_show, struct seq_file *seq, struct cgroup *cgroup)
{
	__u64 id, *value;

	id = cgroup_id(cgroup);
	value = bpf_map_lookup_elem(&wait_map, &id);

	if (value)
		BPF_SEQ_PRINTF(seq, "%llu %llu\n", id, *value);
	else
		BPF_SEQ_PRINTF(seq, "%llu 0\n", id);
	return 0;
}

char _license[] SEC("license") = "GPL";
