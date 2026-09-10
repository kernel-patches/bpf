/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BLK_IOCOST_H
#define _LINUX_BLK_IOCOST_H

#include <linux/types.h>
#include <linux/blk_types.h>

#define IOCOST_MODEL_NAME_LEN	16

#ifdef CONFIG_BLK_CGROUP_IOCOST_BPF

struct blkcg;

/*
 * Pluggable cost model interface for blk-iocost.
 *
 * A BPF struct_ops implementation registered against "iocost_model_ops"
 * fully replaces the builtin linear model on the devices it is bound to
 * through io.cost.model.  The model owns pricing for every IO on a bound
 * device: it prices all operations, including flushes, and both the bio
 * charging path and the request-level sizing path consult it.
 *
 * calc_cost() is called from the IO submission path with RCU read lock
 * held and must not sleep.  It returns the cost of the IO in vtime
 * units, where 1 second of device time equals VTIME_PER_SEC (2^37,
 * available to BPF programs through vmlinux.h).  The returned value is
 * clamped to 1 second of device time per IO.
 *
 * The model is passed the blkcg of the issuing cgroup so it can keep
 * per-cgroup state.  blkcg_online()/blkcg_offline() are optional
 * callbacks mirroring the blkcg css lifecycle: state created on online
 * (or lazily on first use) must be released on offline.
 *
 * The registration and binding model follows the TCP congestion
 * control framework: registering a struct_ops makes the model available
 * by its name, while io.cost.model binds one registered model to a
 * device.  Unregistering removes the name from the registry; devices
 * already bound keep using it until switched back to the builtin
 * model.
 */

#define IOCOST_MODEL_NAME_LEN	16

/*
 * iocost-specific call metadata for calc_cost()'s model_flags
 * argument; everything else, including REQ_PREFLUSH/REQ_FUA, is
 * already present in the opf argument
 */
#define IOCOST_COST_F_MERGE	(1ULL << 0)	/* called from merge path */

struct iocost_model_ops {
	u64 (*calc_cost)(u64 opf, u64 nbytes, sector_t sector,
			 struct blkcg *blkcg, u64 model_flags);
	void (*blkcg_online)(struct blkcg *blkcg);
	void (*blkcg_offline)(struct blkcg *blkcg);

	/* model name, used to select the model through io.cost.model */
	char name[16];
};

int iocost_bpf_model_get(const char *name,
			 const struct iocost_model_ops **opsp);
void iocost_bpf_model_put(const struct iocost_model_ops *ops);
void iocost_notify_blkcg_online(struct blkcg *blkcg);
void iocost_notify_blkcg_offline(struct blkcg *blkcg);

#else	/* CONFIG_BLK_CGROUP_IOCOST_BPF */

struct blkcg;
struct iocost_model_ops;

static inline int iocost_bpf_model_get(const char *name,
				       const struct iocost_model_ops **opsp)
{
	return -EOPNOTSUPP;
}
static inline void iocost_bpf_model_put(const struct iocost_model_ops *ops) { }
static inline void iocost_notify_blkcg_online(struct blkcg *blkcg) { }
static inline void iocost_notify_blkcg_offline(struct blkcg *blkcg) { }

#endif	/* CONFIG_BLK_CGROUP_IOCOST_BPF */
#endif	/* _LINUX_BLK_IOCOST_H */
