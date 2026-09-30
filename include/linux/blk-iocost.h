/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BLK_IOCOST_H
#define _LINUX_BLK_IOCOST_H

#include <linux/types.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>

struct bio;
struct blkcg;
struct request_queue;

/*
 * Pluggable cost model interface for blk-iocost.
 *
 * A BPF struct_ops implementation is attached to one device, identified
 * by the dev member set from userspace before load, following the
 * hid_bpf_ops model: the struct_ops core owns the lifetime of the
 * program.  Attaching creates the ioc if needed, like an io.cost.model
 * write does, switches the device to the BPF model under the same
 * queue freeze and quiesce, and delivers iocg_init() to the cgroups
 * which already exist on the device.  Enabling and disabling the
 * controller stays with io.cost.qos.  While a model is attached,
 * io.cost.model selects between it and the builtin model: "model=bpf"
 * switches to the attached model, "model=linear" switches back to the
 * builtin model, and neither detaches the struct_ops; only detaching
 * removes the model.  The builtin linear coefficients are kept while
 * the BPF model is in use and take effect again when switched back.
 *
 * While the BPF model is the one in use, it owns pricing for every
 * charged IO on the device: it prices all operations, including
 * flushes, from the bio charging path.
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
 * per page for reads and writes: while the BPF model is in use, the
 * builtin latency tracking and vrate adjustment use these instead of
 * the builtin linear coefficients for the completion-time request
 * sizing, so the whole controller follows the model's pricing.  Letting
 * a model take over the QoS side entirely (latency tracking, vrate
 * control) is left for a later extension.
 *
 * The cgroup callbacks are bound to the iocg policy lifetime, one
 * (cgroup, device) pair per invocation: iocg_init() is delivered on
 * attach to every cgroup which already exists on the device and to
 * each one appearing afterwards; iocg_free() is delivered on detach to
 * every cgroup still existing then, and at policy deactivation time
 * for the rest, so init and free always pair up.  Both callbacks run
 * inside an RCU read-side critical section and must not sleep.
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
	 * target device (major:minor), set from userspace before load
	 * through the struct_ops map's initial value, in the userspace
	 * dev_t encoding new_decode_dev() accepts
	 */
	dev_t dev;

	/* vtime per page, used by the builtin sizing and vrate logic */
	u64 read_vtime_per_page;
	u64 write_vtime_per_page;

	u64 (*calc_cost)(struct bio *bio, u64 model_flags);
	void (*iocg_init)(struct blkcg *blkcg, struct request_queue *q);
	void (*iocg_free)(struct blkcg *blkcg, struct request_queue *q);

	/* private: */

	/*
	 * bdev reference held while attached; dropped by the removal
	 * ejection or .unreg, whichever detaches the model first
	 */
	struct block_device	*bdev;
	/* queue of the attached device, NULL = not attached */
	struct request_queue	*q;
};

#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF

int ioc_bpf_attach(struct iocost_model_ops *ops);
void ioc_bpf_detach(struct iocost_model_ops *ops);

#else	/* CONFIG_BLK_CGROUP_IOCOST_BPF */

static inline int ioc_bpf_attach(struct iocost_model_ops *ops)
{
	return -EOPNOTSUPP;
}
static inline void ioc_bpf_detach(struct iocost_model_ops *ops) { }

#endif	/* CONFIG_BLK_CGROUP_IOCOST_BPF */
#endif	/* _LINUX_BLK_IOCOST_H */
