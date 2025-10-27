/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PSI_H
#define _LINUX_PSI_H

#include <linux/jump_label.h>
#include <linux/psi_types.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/cgroup-defs.h>
#include <linux/cgroup.h>

struct seq_file;
struct css_set;

#ifdef CONFIG_PSI

extern struct static_key_false psi_disabled;
extern struct psi_group psi_system;

void psi_init(void);

void psi_memstall_enter(unsigned long *flags);
void psi_memstall_leave(unsigned long *flags);

int psi_show(struct seq_file *s, struct psi_group *group, enum psi_res res);
int psi_trigger_parse(struct psi_trigger_params *params, const char *buf);
struct psi_trigger *psi_trigger_create(struct psi_group *group,
				const struct psi_trigger_params *param);
void psi_trigger_destroy(struct psi_trigger *t);

__poll_t psi_trigger_poll(void **trigger_ptr, struct file *file,
			poll_table *wait);

static inline bool psi_file_privileged(struct file *file)
{
	/*
	 * Checking the privilege here on file->f_cred implies that a privileged user
	 * could open the file and delegate the write to an unprivileged one.
	 */
	return cap_raised(file->f_cred->cap_effective, CAP_SYS_RESOURCE);
}

#ifdef CONFIG_CGROUPS
static inline struct psi_group *cgroup_psi(struct cgroup *cgrp)
{
	return cgroup_ino(cgrp) == 1 ? &psi_system : cgrp->psi;
}

int psi_cgroup_alloc(struct cgroup *cgrp);
void psi_cgroup_free(struct cgroup *cgrp);
void cgroup_move_task(struct task_struct *p, struct css_set *to);
void psi_cgroup_restart(struct psi_group *group);
#endif

#else /* CONFIG_PSI */

static inline void psi_init(void) {}

static inline void psi_memstall_enter(unsigned long *flags) {}
static inline void psi_memstall_leave(unsigned long *flags) {}

#ifdef CONFIG_CGROUPS
static inline int psi_cgroup_alloc(struct cgroup *cgrp)
{
	return 0;
}
static inline void psi_cgroup_free(struct cgroup *cgrp)
{
}
static inline void cgroup_move_task(struct task_struct *p, struct css_set *to)
{
	rcu_assign_pointer(p->cgroups, to);
}
static inline void psi_cgroup_restart(struct psi_group *group) {}
#endif

#endif /* CONFIG_PSI */

#endif /* _LINUX_PSI_H */
