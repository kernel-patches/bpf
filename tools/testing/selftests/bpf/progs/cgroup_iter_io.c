// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"
#include "cgroup_iter_io.h"

char _license[] SEC("license") = "GPL";

struct io_query io_query SEC(".data.query");

struct io_query root_query SEC(".data.query");

__u64 got_root_css SEC(".data.query");

/* Device selected by userspace in kernel dev_t format. */
__u64 target_dev SEC(".data.query");

/* Keep inline: RCU and open-coded iterators cannot cross a BPF call. */
static __always_inline int read_target_dev(struct cgroup *cgrp,
					   struct io_query *out)
{
	struct cgroup_subsys_state *css;
	struct blkcg_gq *pos;
	__u64 dev;
	int ssid;

	/* The flush can sleep, so run it before the RCU section. */
	bpf_blkcg_flush_stats(cgrp);

	bpf_rcu_read_lock();
	ssid = bpf_core_enum_value(enum cgroup_subsys_id, io_cgrp_id);

	/*
	 * subsys[] is __rcu, so this read gives an RCU pointer the iterator
	 * accepts. BPF_CORE_READ() would return a plain value instead.
	 */
	css = cgrp->subsys[ssid];
	if (!css) {
		bpf_rcu_read_unlock();
		return 0;
	}

	bpf_for_each(blkg, pos, css) {
		dev = BPF_CORE_READ(pos, q, disk, part0, bd_dev);
		if (dev != target_dev)
			continue;

		out->dev = dev;
		out->rbytes = BPF_CORE_READ(pos, iostat.cur.bytes[BLKG_IOSTAT_READ]);
		out->wbytes = BPF_CORE_READ(pos, iostat.cur.bytes[BLKG_IOSTAT_WRITE]);
		out->rios = BPF_CORE_READ(pos, iostat.cur.ios[BLKG_IOSTAT_READ]);
		out->wios = BPF_CORE_READ(pos, iostat.cur.ios[BLKG_IOSTAT_WRITE]);
		out->dbytes = BPF_CORE_READ(pos, iostat.cur.bytes[BLKG_IOSTAT_DISCARD]);
		out->dios = BPF_CORE_READ(pos, iostat.cur.ios[BLKG_IOSTAT_DISCARD]);
		break;
	}
	bpf_rcu_read_unlock();
	return 1;
}

SEC("iter.s/cgroup")
int cgroup_io_query(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;

	if (!cgrp)
		return 1;

	/* Start fresh so a device that is not found stays all-zero. */
	__builtin_memset(&io_query, 0, sizeof(io_query));

	read_target_dev(cgrp, &io_query);
	return 0;
}

SEC("iter.s/cgroup")
int cgroup_root_io_query(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *root;

	if (!ctx->cgroup)
		return 1;

	__builtin_memset(&root_query, 0, sizeof(root_query));

	/* The root cgroup always has id 1. */
	root = bpf_cgroup_from_id(1);
	if (!root)
		return 0;

	/* Root counters include all cgroups' I/O. */
	if (read_target_dev(root, &root_query))
		got_root_css = 1;

	bpf_cgroup_release(root);
	return 0;
}
