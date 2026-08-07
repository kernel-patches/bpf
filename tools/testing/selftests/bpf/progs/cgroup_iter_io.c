// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"
#include "cgroup_iter_io.h"

char _license[] SEC("license") = "GPL";

/* The counters of the device named by target_dev are stored here. */
struct io_query io_query SEC(".data.query");

/* The same device's counters read through the root block cgroup. */
struct io_query root_query SEC(".data.query");

/* Set to 1 by cgroup_root_blkcg_query when bpf_get_root_blkcg() succeeds. */
__u64 got_root_blkcg SEC(".data.query");

/* Device to read, set by userspace (kernel dev_t). Pinning the device keeps
 * the read deterministic and lets the value be compared to io.stat exactly.
 */
__u64 target_dev SEC(".data.query");

/*
 * Flush @blkcg and copy the target device's counters into @out. Reading only
 * the one pinned device keeps the result deterministic: that device is
 * quiesced, so its counters match io.stat exactly, while picking "any device
 * with I/O" would race with backing-store writeback.
 */
static __always_inline void read_target_dev(struct blkcg *blkcg,
					    struct io_query *out)
{
	struct blkcg_gq *pos;

	/* io.stat needs a flush before it can be read (sleepable). */
	bpf_blkcg_flush_stats(blkcg);

	/* The per-device blkg walk needs an RCU section. */
	bpf_rcu_read_lock();
	bpf_for_each(blkg, pos, blkcg) {
		if (bpf_blkg_dev(pos) != target_dev)
			continue;

		out->dev = bpf_blkg_dev(pos);
		out->rbytes = bpf_blkg_iostat_bytes(pos, BLKG_IOSTAT_READ);
		out->wbytes = bpf_blkg_iostat_bytes(pos, BLKG_IOSTAT_WRITE);
		out->rios = bpf_blkg_iostat_ios(pos, BLKG_IOSTAT_READ);
		out->wios = bpf_blkg_iostat_ios(pos, BLKG_IOSTAT_WRITE);
		out->dbytes = bpf_blkg_iostat_bytes(pos, BLKG_IOSTAT_DISCARD);
		out->dios = bpf_blkg_iostat_ios(pos, BLKG_IOSTAT_DISCARD);
		break;
	}
	bpf_rcu_read_unlock();
}

SEC("iter.s/cgroup")
int cgroup_io_query(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;
	struct blkcg *blkcg;

	/* The last iteration has a NULL cgroup, skip it. */
	if (!cgrp)
		return 1;

	/* Start fresh so a device that is not found stays all-zero. */
	__builtin_memset(&io_query, 0, sizeof(io_query));

	blkcg = bpf_get_blkcg(&cgrp->self);
	if (!blkcg)
		return 0;

	read_target_dev(blkcg, &io_query);

	bpf_put_blkcg(blkcg);
	return 0;
}

SEC("iter.s/cgroup")
int cgroup_root_blkcg_query(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;
	struct blkcg *blkcg;

	/* The last iteration has a NULL cgroup, skip it. */
	if (!cgrp)
		return 1;

	__builtin_memset(&root_query, 0, sizeof(root_query));

	blkcg = bpf_get_root_blkcg();
	if (!blkcg)
		return 0;

	/*
	 * The root cgroup takes its numbers from the disks themselves rather
	 * than from rstat, so this also covers the root side of
	 * bpf_blkcg_flush_stats(). The counters cover every cgroup's I/O, so
	 * they can only be at or above what this test's own cgroup did.
	 */
	read_target_dev(blkcg, &root_query);

	got_root_blkcg = 1;
	bpf_put_blkcg(blkcg);
	return 0;
}
