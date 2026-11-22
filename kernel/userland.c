// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

/**
 * DOC: Overview
 *
 * A userland is an anonymous-inode control object opened by ``userland_open()``
 * that binds a detached namespace set, an initially empty mount namespace, an
 * owning user namespace, and an init process lifecycle.
 */
#include <linux/poll.h>
#include <linux/wait.h>
#include <uapi/linux/wait.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/userland.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/nsfs.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/time_namespace.h>
#include <linux/user_namespace.h>
#include <linux/idr.h>
#include <uapi/linux/userland.h>

void userland_put(struct userland *c)
{
	if (!c || !refcount_dec_and_test(&c->usage))
		return;

	if (c->ns)
		put_nsproxy(c->ns);
	if (c->init_pid)
		put_pid(c->init_pid);
	if (c->user_ns) {
		ns_ref_active_put(c->user_ns);
		put_user_ns(c->user_ns);
	}
	kfree(c);
}

static __poll_t userland_poll(struct file *file, poll_table *wait)
{
	struct userland *userland = file->private_data;
	__poll_t mask = 0;

	poll_wait(file, &userland->waitq, wait);

	if (READ_ONCE(userland->state) == USERLAND_DEAD)
		mask |= EPOLLHUP;

	return mask;
}

static int userland_release(struct inode *inode, struct file *file)
{
	struct userland *userland = file->private_data;

	if (userland->flags & USERLAND_KILL_ON_CLOSE) {
		struct pid *pid = NULL;

		scoped_guard(spinlock, &userland->lock) {
			if (userland->state == USERLAND_RUNNING)
				pid = get_pid(userland->init_pid);
		}
		if (pid) {
			kill_pid(pid, SIGKILL, true);
			put_pid(pid);
		}
	}
	userland_put(userland);
	return 0;
}

static const struct file_operations userland_fops = {
	.poll		= userland_poll,
	.release	= userland_release,
};

bool userland_is_file(struct file *file)
{
	return file->f_op == &userland_fops;
}
