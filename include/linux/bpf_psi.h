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
	void (*handle_psi_event)(struct psi_trigger *t);

	/**
	 * @handle_cgroup_free: Cgroup free callback
	 * @cgroup_id: Id of freed cgroup
	 *
	 * Called every time a cgroup with an attached bpf psi trigger is freed.
	 * No psi events can be raised after handle_cgroup_free().
	 */
	void (*handle_cgroup_free)(u64 cgroup_id);

	/* private */
	struct bpf_psi *bpf_psi;
};

struct bpf_psi {
	spinlock_t lock;
	struct list_head triggers;
	struct bpf_psi_ops *ops;
	struct srcu_struct srcu;
};

#ifdef CONFIG_BPF_SYSCALL
void bpf_psi_add_trigger(struct psi_trigger *t,
			 const struct psi_trigger_params *params);
void bpf_psi_remove_trigger(struct psi_trigger *t);
void bpf_psi_handle_event(struct psi_trigger *t);
#ifdef CONFIG_CGROUPS
void bpf_psi_cgroup_free(struct cgroup *cgroup);
#endif

#else /* CONFIG_BPF_SYSCALL */
static inline void bpf_psi_add_trigger(struct psi_trigger *t,
			const struct psi_trigger_params *params) {}
static inline void bpf_psi_remove_trigger(struct psi_trigger *t) {}
static inline void bpf_psi_handle_event(struct psi_trigger *t) {}
static inline void bpf_psi_cgroup_free(struct cgroup *cgroup) {}

#endif /* CONFIG_BPF_SYSCALL */

#endif /* __BPF_PSI_H */
