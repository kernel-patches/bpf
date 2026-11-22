// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
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

void userland_copy(struct task_struct *tsk, struct pid *pid, struct userland *c)
{
	if (likely(!c || !is_child_reaper(pid)))
		return;

	scoped_guard(spinlock, &c->lock) {
		if (c->state != USERLAND_FORKING)
			return;
		refcount_inc(&c->usage);
		ns_of_pid(pid)->userland = c;
		WRITE_ONCE(c->init_pid, get_pid(pid));
		WRITE_ONCE(c->state, USERLAND_RUNNING);
	}
}

void userland_exit(struct pid_namespace *pid_ns, struct task_struct *tsk)
{
	struct userland *c = pid_ns->userland;
	struct task_struct *leader;
	kuid_t uid;
	int status;

	if (!c)
		return;

	leader = tsk->group_leader;
	rcu_read_lock();
	uid = task_uid(leader);
	rcu_read_unlock();
	status = (tsk->signal->flags & SIGNAL_GROUP_EXIT) ?
		 tsk->signal->group_exit_code : leader->exit_code;

	scoped_guard(spinlock, &c->lock) {
		c->exit_code = status;
		c->init_uid = uid;
		WRITE_ONCE(c->state, USERLAND_DEAD);
	}

	pid_ns->userland = NULL;
	__wake_up(&c->waitq, TASK_NORMAL, 0, poll_to_key(EPOLLHUP));
	userland_put(c);
}

static struct user_namespace *userland_create_user_ns(void)
{
	struct user_namespace *user_ns;
	struct cred *new;
	int ret;

	new = prepare_creds();
	if (!new)
		return ERR_PTR(-ENOMEM);

	ret = create_user_ns(new);
	if (ret < 0) {
		abort_creds(new);
		return ERR_PTR(ret);
	}

	user_ns = get_user_ns(new->user_ns);
	abort_creds(new);
	return user_ns;
}

static struct userland *userland_create(unsigned int flags)
{
	u64 clone_flags = CLONE_NEWNS | CLONE_EMPTY_MNTNS | CLONE_NEWPID |
			  CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC |
			  CLONE_NEWNET |
			  (IS_ENABLED(CONFIG_TIME_NS) ? CLONE_NEWTIME : 0);
	struct user_namespace *user_ns;
	struct nsproxy *ns;
	struct userland *c;
	int ret;

	c = kzalloc_obj(*c, GFP_KERNEL);
	if (!c)
		return ERR_PTR(-ENOMEM);

	init_waitqueue_head(&c->waitq);
	spin_lock_init(&c->lock);
	refcount_set(&c->usage, 1);
	c->flags = flags;

	user_ns = userland_create_user_ns();
	if (IS_ERR(user_ns)) {
		ret = PTR_ERR(user_ns);
		goto err_put;
	}
	c->user_ns = user_ns;
	ns_ref_active_get(user_ns);

	if (!ns_capable(user_ns, CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto err_put;
	}

	ns = create_new_namespaces(clone_flags, current, user_ns, NULL);
	if (IS_ERR(ns)) {
		ret = PTR_ERR(ns);
		goto err_put;
	}

	if (ns->time_ns != ns->time_ns_for_children) {
		get_time_ns(ns->time_ns_for_children);
		put_time_ns(ns->time_ns);
		ns->time_ns = ns->time_ns_for_children;
	}
	c->ns = ns;
	nsproxy_ns_active_get(ns);

	return c;

err_put:
	userland_put(c);
	return ERR_PTR(ret);
}

/**
 * sys_userland_open - Open a new userland
 * @flags: Combination of &enum userland_flags values
 *
 * Allocate a userland owning a fresh user namespace and dedicated
 * empty mount, PID, UTS, IPC, network, cgroup, and time namespaces.
 *
 * Return: Userland file descriptor on success, negative error code on failure.
 */
SYSCALL_DEFINE1(userland_open, unsigned int, flags)
{
	struct userland *c;
	int fd;

	if (flags & ~USERLAND_ALL_FLAGS)
		return -EINVAL;
	if (unlikely(!current->nsproxy))
		return -EOPNOTSUPP;

	c = userland_create(flags);
	if (IS_ERR(c))
		return PTR_ERR(c);

	fd = anon_inode_getfd("userland", &userland_fops, c,
			      O_RDWR |
			      (flags & USERLAND_CLOSE_ON_EXEC ? O_CLOEXEC : 0));
	if (fd < 0)
		userland_put(c);

	return fd;
}
