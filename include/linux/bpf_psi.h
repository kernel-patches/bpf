/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef __BPF_PSI_H
#define __BPF_PSI_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/psi_types.h>

struct cgroup;
struct bpf_psi;
struct psi_trigger;
struct psi_trigger_params;

#define BPF_PSI_FULL 0x80000000

struct bpf_psi_ops {
	/**
	 * @init: Initialization callback, suited for creating psi triggers.
	 * @bpf_psi: bpf_psi pointer, can be passed to bpf_psi_create_trigger().
	 *
	 * A non-0 return value means the initialization has been failed.
	 */
	int (*init)(struct bpf_psi *bpf_psi);

	/**
	 * @handle_psi_event: PSI event callback
	 * @t: psi_trigger pointer
	 */
	void (*handle_psi_event)(struct bpf_psi *bpf_psi, struct psi_trigger *t);

	/**
	 * @handle_cgroup_online: Cgroup online callback
	 * @cgroup_id: Id of the new cgroup
	 *
	 * Called every time a new cgroup is created. Can be used
	 * to create new psi triggers.
	 */
	void (*handle_cgroup_online)(struct bpf_psi *bpf_psi, u64 cgroup_id);

	/**
	 * @handle_cgroup_offline: Cgroup offline callback
	 * @cgroup_id: Id of offlined cgroup
	 *
	 * Called every time a cgroup with an attached bpf psi trigger is
	 * offlined.
	 */
	void (*handle_cgroup_offline)(struct bpf_psi *bpf_psi, u64 cgroup_id);

	/* private */
	struct bpf_psi *bpf_psi;
};

struct bpf_psi {
	spinlock_t lock;
	struct list_head triggers;
	struct bpf_psi_ops *ops;
	struct srcu_struct srcu;
	struct list_head node; /* Protected by bpf_psi_lock */
};

#ifdef CONFIG_BPF_SYSCALL
void bpf_psi_add_trigger(struct psi_trigger *t,
			 const struct psi_trigger_params *params);
void bpf_psi_remove_trigger(struct psi_trigger *t);
void bpf_psi_handle_event(struct psi_trigger *t);

#else /* CONFIG_BPF_SYSCALL */
static inline void bpf_psi_add_trigger(struct psi_trigger *t,
			const struct psi_trigger_params *params) {}
static inline void bpf_psi_remove_trigger(struct psi_trigger *t) {}
static inline void bpf_psi_handle_event(struct psi_trigger *t) {}

#endif /* CONFIG_BPF_SYSCALL */

#if (defined(CONFIG_CGROUPS) && defined(CONFIG_PSI) && defined(CONFIG_BPF_SYSCALL))
void bpf_psi_cgroup_online(struct cgroup *cgroup);
void bpf_psi_cgroup_offline(struct cgroup *cgroup);

#else /* CONFIG_CGROUPS && CONFIG_PSI && CONFIG_BPF_SYSCALL */
static inline void bpf_psi_cgroup_online(struct cgroup *cgroup) {}
static inline void bpf_psi_cgroup_offline(struct cgroup *cgroup) {}

#endif /* CONFIG_CGROUPS && CONFIG_PSI && CONFIG_BPF_SYSCALL */

#endif /* __BPF_PSI_H */
