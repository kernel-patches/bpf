/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

#ifndef _LINUX_USERLAND_H
#define _LINUX_USERLAND_H

#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>
#include <linux/wait.h>

struct file;
struct nsproxy;
struct pid;
struct pid_namespace;
struct rusage;
struct siginfo;
struct task_struct;
struct user_namespace;
struct waitid_info;

/**
 * enum userland_state - Userland lifecycle states
 * @USERLAND_INIT:	Build phase after ``userland_open()`` before any
 *			process has entered. ``USERLAND_SHARE_NSFD`` is
 *			permitted, ID mappings may be configured on the owning
 *			user namespace, and ``"/"`` must be mounted in the
 *			mount namespace before entry.
 * @USERLAND_FORKING:	Bootstrap phase while the first
 *			``clone3(CLONE_INTO_USERLAND)`` call creates PID 1.
 *			Concurrent callers wait killably; reverts to
 *			%USERLAND_INIT if ``copy_process()`` fails, or advances
 *			to %USERLAND_RUNNING once PID 1 is attached.
 * @USERLAND_RUNNING:	Live phase while PID 1 is attached. Subsequent
 *			``clone3(CLONE_INTO_USERLAND)`` calls join the PID
 *			namespace until teardown begins,
 *			``USERLAND_GET_NSFD(CLONE_NEWPID)`` and
 *			``pidfd_send_signal()`` are enabled, and
 *			``USERLAND_SHARE_NSFD`` returns ``-EBUSY``.
 * @USERLAND_DEAD:	Terminal phase entered after PID 1 exits and the PID
 *			namespace has killed and reaped all member processes.
 *			``poll()`` reports ``EPOLLHUP`` and
 *			``waitid(P_USERLAND, ...)`` reports PID 1's exit status
 *			without consuming it.
 *
 * State transitions advance from %USERLAND_INIT through %USERLAND_FORKING and
 * %USERLAND_RUNNING to %USERLAND_DEAD, reverting from %USERLAND_FORKING to
 * %USERLAND_INIT only if the initial bootstrap fork fails.
 */
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
	kuid_t			init_uid;
	spinlock_t		lock;		/* Guards userland lifecycle state */
	wait_queue_head_t	waitq;
	unsigned int		flags;
	enum userland_state	state;
};

#ifdef CONFIG_USERLAND
void userland_put(struct userland *c);
bool userland_is_file(struct file *file);
void userland_copy(struct task_struct *tsk, struct pid *pid,
		   struct userland *userland);
void userland_exit(struct pid_namespace *pid_ns, struct task_struct *tsk);
long userland_waitid(int upid, struct waitid_info *infop, int options,
		     struct rusage *ru);
int userland_send_signal(struct file *file, int sig,
			 struct siginfo __user *info, unsigned int flags);
#else
static inline void userland_put(struct userland *c)
{
}

static inline bool userland_is_file(struct file *file)
{
	return false;
}

static inline void userland_copy(struct task_struct *tsk, struct pid *pid,
				 struct userland *userland)
{
}

static inline void userland_exit(struct pid_namespace *pid_ns,
				 struct task_struct *tsk)
{
}

static inline long userland_waitid(int upid, struct waitid_info *infop,
				   int options, struct rusage *ru)
{
	return -EINVAL;
}

static inline int userland_send_signal(struct file *file, int sig,
				       struct siginfo __user *info,
				       unsigned int flags)
{
	return -EBADF;
}
#endif /* CONFIG_USERLAND */

#endif /* _LINUX_USERLAND_H */
