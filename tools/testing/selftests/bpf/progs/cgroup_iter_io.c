// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"
#include "cgroup_iter_io.h"

char _license[] SEC("license") = "GPL";

struct io_query io_query SEC(".data.query");

/* Device selected by userspace in kernel dev_t format. */
__u64 target_dev SEC(".data.query");

/* Keep inline: RCU and open-coded iterators cannot cross a BPF call. */
static __always_inline int read_target_dev(struct cgroup *cgrp,
					   struct io_query *out)
{
	struct cgroup_subsys_state *css;
	struct blkcg *blkcg;
	struct blkcg_gq *pos;
	__u64 dev;
	int ssid;

	ssid = bpf_core_enum_value(enum cgroup_subsys_id, io_cgrp_id);
	css = bpf_cgroup_css(cgrp, ssid);
	if (!css)
		return 0;

	css_rstat_flush(css);

	bpf_rcu_read_lock();

	blkcg = bpf_css_to_blkcg(css);
	if (!blkcg) {
		bpf_rcu_read_unlock();
		bpf_css_release(css);
		return 0;
	}

	bpf_for_each(blkg, pos, blkcg) {
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
	bpf_css_release(css);
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
