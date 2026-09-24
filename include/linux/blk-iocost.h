/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BLK_IOCOST_H
#define _LINUX_BLK_IOCOST_H

#include <linux/types.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>

#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF

struct bio;
struct blkcg;
struct request_queue;

/*
 * Pluggable cost model interface for blk-iocost.
 *
 * A BPF struct_ops implementation is attached to one device, identified
 * by the dev member set from userspace before load, following the
 * hid_bpf_ops model: attaching the struct_ops switches the device to
 * the BPF model, detaching it restores the builtin linear model, and
 * the struct_ops core owns the lifetime of the program.  The model
 * then owns pricing for every charged IO on the device: it prices all
 * operations, including flushes, from the bio charging path.
 *
 * calc_cost() is called from the IO submission path with RCU read lock
 * held and must not sleep.  It receives the bio itself so the model
 * can read whatever it needs (operation flags, size, sector, the
 * issuing cgroup through bio->bi_blkg).  It returns the cost of the
 * IO in vtime units, where 1 second of device time equals
 * VTIME_PER_SEC (2^37, available to BPF programs through vmlinux.h).
 * The returned value is clamped to 1 second of device time per IO.
 *
 * The struct_ops also carries the transfer cost coefficients, vtime
 * per page for reads and writes: while a model is attached, the
 * builtin latency tracking and vrate adjustment use these instead of
 * the builtin linear coefficients for the completion-time request
 * sizing, so the whole controller follows the model's pricing.  Letting
 * a model take over the QoS side entirely (latency tracking, vrate
 * control) is left for a later extension.
 *
 * The cgroup callbacks are bound to the iocg policy lifetime, one
 * (cgroup, device) pair per invocation, matching the builtin cursor:
 * state created in init (or lazily on first use) must be released in
 * free.
 */

/*
 * iocost-specific call metadata for calc_cost()'s model_flags
 * argument; the merge indicator is not a property of the bio.
 * An enum so the value is exported through BTF and BPF models can
 * use it from vmlinux.h.
 */
enum {
	IOCOST_COST_F_MERGE	= 1 << 0,	/* called from merge path */
};

struct iocost_model_ops {
	/*
	 * target device (major:minor), set from userspace before load;
	 * must stay the first member so userspace can write it through
	 * the struct_ops map's initial value
	 */
	dev_t dev;
	/* kernel-private: the open bdev file pinning the queue */
	struct file *bdev_file;

	/* vtime per page, used by the builtin sizing and vrate logic */
	u64 read_vtime_per_page;
	u64 write_vtime_per_page;

	u64 (*calc_cost)(struct bio *bio, u64 model_flags);
	/*
	 * per-(cgroup, device) lifecycle: both callbacks run inside
	 * an RCU read-side critical section (see below) and must not
	 * sleep; IRQs may be enabled or disabled, so per-CPU state
	 * must not rely on the IRQs-off guarantee.  iocg_init() is
	 * delivered for
	 * cgroups which appear on the device while the model is
	 * attached; cgroups which already exist when the model is
	 * attached never see an init, so iocg_free() must tolerate
	 * freeing state it never initialized.  iocg_free() is only
	 * delivered while the model is attached: detaching does not
	 * flush state created by iocg_init(), so models must keep
	 * their per-cgroup state reclaimable by other means
	 */
	void (*iocg_init)(struct blkcg *blkcg, struct request_queue *q);
	void (*iocg_free)(struct blkcg *blkcg, struct request_queue *q);

	/* private: */

	/* queue of the attached device, NULL = not attached */
	struct request_queue	*q;
};

int ioc_bpf_attach(struct iocost_model_ops *ops);
void ioc_bpf_detach(struct iocost_model_ops *ops);
void ioc_bpf_unreg(struct iocost_model_ops *ops);

#else	/* CONFIG_BLK_CGROUP_IOCOST_BPF */

#endif	/* CONFIG_BLK_CGROUP_IOCOST_BPF */
#endif	/* _LINUX_BLK_IOCOST_H */
