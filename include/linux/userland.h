/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

#ifndef _LINUX_USERLAND_H
#define _LINUX_USERLAND_H

#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

struct file;
struct nsproxy;
struct pid;
struct user_namespace;

enum userland_state {
	USERLAND_INIT		= 0,
	USERLAND_FORKING	= 1,
	USERLAND_RUNNING	= 2,
	USERLAND_DEAD		= 3,
};

struct userland {
	refcount_t		usage;
	int			exit_code;
	struct user_namespace	*user_ns;
	struct nsproxy		*ns;
	struct pid		*init_pid;
	spinlock_t		lock;		/* Guards userland lifecycle state */
	wait_queue_head_t	waitq;
	unsigned int		flags;
	enum userland_state	state;
};

#ifdef CONFIG_USERLAND
void userland_put(struct userland *c);
bool userland_is_file(struct file *file);
#else
static inline void userland_put(struct userland *c)
{
}

static inline bool userland_is_file(struct file *file)
{
	return false;
}
#endif /* CONFIG_USERLAND */

#endif /* _LINUX_USERLAND_H */
