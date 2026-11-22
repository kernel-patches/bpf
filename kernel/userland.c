// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

#include <linux/poll.h>
#include <linux/wait.h>
#include <uapi/linux/wait.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/anon_inodes.h>
#include <linux/userland.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/cgroup_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/nsfs.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/time_namespace.h>
#include <linux/user_namespace.h>
#include <linux/uts_namespace.h>
#include <net/net_namespace.h>
#include <linux/idr.h>
#include <uapi/linux/userland.h>

#include "exit.h"

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

static long userland_get_nsfd(struct userland *userland, unsigned long nstype)
{
	struct ns_common *ns = NULL;

	if (nstype > UINT_MAX)
		return -EINVAL;
	if (!ns_capable(userland->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (nstype == CLONE_NEWPID) {
		if (!pidns_is_ancestor(userland->ns->pid_ns_for_children,
				       task_active_pid_ns(current)))
			return -EXDEV;
		if (READ_ONCE(userland->state) != USERLAND_RUNNING)
			return -ESRCH;
	}

	scoped_guard(spinlock, &userland->lock) {
		switch (nstype) {
		case CLONE_NEWNS:
			ns = from_mnt_ns(userland->ns->mnt_ns);
			break;
		case CLONE_NEWCGROUP:
			ns = to_ns_common(userland->ns->cgroup_ns);
			break;
		case CLONE_NEWUTS:
			ns = to_ns_common(userland->ns->uts_ns);
			break;
		case CLONE_NEWIPC:
			ns = to_ns_common(userland->ns->ipc_ns);
			break;
		case CLONE_NEWUSER:
			ns = to_ns_common(userland->user_ns);
			break;
		case CLONE_NEWPID:
			ns = to_ns_common(userland->ns->pid_ns_for_children);
			break;
		case CLONE_NEWNET:
			ns = to_ns_common(userland->ns->net_ns);
			break;
		case CLONE_NEWTIME:
#ifdef CONFIG_TIME_NS
			ns = to_ns_common(userland->ns->time_ns);
			break;
#else
			return -EOPNOTSUPP;
#endif
		default:
			return -EINVAL;
		}

		if (!__ns_ref_get(ns))
			return -ESRCH;
	}

	return open_namespace(ns);
}

static long userland_share_nsfd(struct userland *c, unsigned long arg)
{
	struct ns_common *old_time_children = NULL;
	struct ns_common *old_ns = NULL;
	struct ns_common *ns;

	if (arg > INT_MAX)
		return -EBADF;

	CLASS(fd, f)((int)arg);
	if (fd_empty(f))
		return -EBADF;
	if (!proc_ns_file(fd_file(f)))
		return -EINVAL;
	if (unlikely(!current->nsproxy))
		return -EOPNOTSUPP;

	ns = get_proc_ns(file_inode(fd_file(f)));
	switch (ns->ns_type) {
	case CLONE_NEWCGROUP:
	case CLONE_NEWIPC:
	case CLONE_NEWUTS:
	case CLONE_NEWNET:
		break;
	case CLONE_NEWTIME:
		if (!IS_ENABLED(CONFIG_TIME_NS))
			return -EOPNOTSUPP;
		break;
	default:
		return -EINVAL;
	}

	if (!ns_capable(c->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	if (!is_current_namespace(ns) &&
	    !ns_capable(ns->ops->owner(ns), CAP_SYS_ADMIN))
		return -EPERM;

	scoped_guard(spinlock, &c->lock) {
		if (c->state != USERLAND_INIT)
			return -EBUSY;

		__ns_ref_inc(ns);
		__ns_ref_active_get(ns);

		switch (ns->ns_type) {
		case CLONE_NEWCGROUP:
			old_ns = to_ns_common(c->ns->cgroup_ns);
			c->ns->cgroup_ns = to_cg_ns(ns);
			break;
		case CLONE_NEWIPC:
			old_ns = to_ns_common(c->ns->ipc_ns);
			c->ns->ipc_ns = to_ipc_ns(ns);
			break;
		case CLONE_NEWUTS:
			old_ns = to_ns_common(c->ns->uts_ns);
			c->ns->uts_ns = to_uts_ns(ns);
			break;
		case CLONE_NEWNET:
			old_ns = to_ns_common(c->ns->net_ns);
			c->ns->net_ns = to_net_ns(ns);
			break;
#ifdef CONFIG_TIME_NS
		case CLONE_NEWTIME:
			__ns_ref_inc(ns);
			__ns_ref_active_get(ns);
			old_ns = to_ns_common(c->ns->time_ns);
			old_time_children =
				to_ns_common(c->ns->time_ns_for_children);
			c->ns->time_ns = to_time_ns(ns);
			c->ns->time_ns_for_children = to_time_ns(ns);
			break;
#endif
		default:
			WARN_ON_ONCE(1);
			break;
		}
	}

	__ns_ref_active_put(old_ns);
	old_ns->ops->put(old_ns);
	if (old_time_children) {
		__ns_ref_active_put(old_time_children);
		old_time_children->ops->put(old_time_children);
	}
	return 0;
}

/**
 * DOC: P_USERLAND
 *
 * ``waitid(P_USERLAND, userland_fd, &infop, options, NULL)`` waits freezably until
 * ``userland_fd`` reaches ``USERLAND_DEAD`` (unless ``WNOHANG`` or ``O_NONBLOCK`` is
 * set) and writes init's exit information into ``infop`` without consuming it.
 * ``options`` must include ``WEXITED`` and may include ``WNOHANG`` and
 * ``WNOWAIT``; ``rusage`` must be ``NULL``, and the caller must run in an
 * ancestor active PID namespace.
 */
long userland_waitid(int upid, struct waitid_info *infop, int options,
		     struct rusage *ru)
{
	struct pid_namespace *pid_ns;
	unsigned int f_flags;
	struct userland *userland;
	bool nonblock;
	int status;
	kuid_t uid;
	long ret;

	if (upid < 0 || ru)
		return -EINVAL;
	if (options & ~(WEXITED | WNOHANG | WNOWAIT))
		return -EINVAL;
	if (!(options & WEXITED))
		return -EINVAL;

	CLASS(fd, f)(upid);
	if (fd_empty(f) || !userland_is_file(fd_file(f)))
		return -EBADF;

	f_flags = READ_ONCE(fd_file(f)->f_flags);
	nonblock = (options & WNOHANG) || (f_flags & O_NONBLOCK);
	userland = fd_file(f)->private_data;
	pid_ns = task_active_pid_ns(current);

	if (!pidns_is_ancestor(userland->ns->pid_ns_for_children, pid_ns))
		return -ECHILD;
	if (READ_ONCE(userland->state) == USERLAND_INIT)
		return -ECHILD;

	if (!nonblock) {
		ret = wait_event_freezable(userland->waitq,
					   READ_ONCE(userland->state) ==
					   USERLAND_DEAD ||
					   READ_ONCE(userland->state) ==
					   USERLAND_INIT);
		if (ret)
			return ret;
	}

	scoped_guard(spinlock, &userland->lock) {
		if (userland->state == USERLAND_INIT)
			return -ECHILD;
		if (userland->state != USERLAND_DEAD)
			return (options & WNOHANG) ? 0 : -EAGAIN;
		ret = pid_nr_ns(userland->init_pid, pid_ns);
		if (ret <= 0)
			return -ECHILD;
		status = userland->exit_code;
		uid = userland->init_uid;
	}

	if ((status & 0x7f) == 0) {
		infop->cause = CLD_EXITED;
		infop->status = status >> 8;
	} else {
		infop->cause = (status & 0x80) ? CLD_DUMPED : CLD_KILLED;
		infop->status = status & 0x7f;
	}
	infop->pid = ret;
	infop->uid = from_kuid_munged(current_user_ns(), uid);
	return ret;
}

/**
 * DOC: pidfd_send_signal
 *
 * ``pidfd_send_signal(userland_fd, sig, NULL, 0)`` delivers ``sig`` (or ``0`` for
 * a permission and existence probe) once to each member thread group in a
 * running userland. ``info`` must be ``NULL``, ``flags`` must be ``0``, and the
 * caller must run in an ancestor active PID namespace.
 */
int userland_send_signal(struct file *file, int sig,
			 struct siginfo __user *info, unsigned int flags)
{
	struct userland *userland = file->private_data;
	struct pid_namespace *pid_ns = userland->ns->pid_ns_for_children;
	bool any_success = false;
	bool any_other = false;
	bool any_perm = false;
	int other_err = 0;
	struct pid *pid;
	int nr;

	if (info || flags || sig < 0 || !valid_signal(sig))
		return -EINVAL;
	if (!pidns_is_ancestor(pid_ns, task_active_pid_ns(current)))
		return -EXDEV;
	if (READ_ONCE(userland->state) != USERLAND_RUNNING)
		return -ESRCH;

	scoped_guard(rcu) {
		read_lock(&tasklist_lock);
		idr_for_each_entry(&pid_ns->idr, pid, nr) {
			struct task_struct *task = pid_task(pid, PIDTYPE_TGID);
			int err;

			if (!task)
				continue;

			err = group_send_sig_info(sig, SEND_SIG_NOINFO, task,
						  PIDTYPE_MAX);
			if (!err) {
				any_success = true;
			} else if (err == -EPERM) {
				any_perm = true;
			} else if (err != -ESRCH && !any_other) {
				any_other = true;
				other_err = err;
			}
		}
		read_unlock(&tasklist_lock);
	}

	if (any_success)
		return 0;
	if (any_other)
		return other_err;
	if (any_perm)
		return -EPERM;
	return -ESRCH;
}

static long userland_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct userland *userland = file->private_data;

	switch (cmd) {
	case USERLAND_GET_NSFD:
		return userland_get_nsfd(userland, arg);
	case USERLAND_SHARE_NSFD:
		return userland_share_nsfd(userland, arg);
	default:
		return -ENOIOCTLCMD;
	}
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
	.unlocked_ioctl	= userland_ioctl,
	.compat_ioctl	= userland_ioctl,
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

/**
 * DOC: CLONE_INTO_USERLAND
 *
 * Passing ``CLONE_INTO_USERLAND`` in ``struct clone_args.flags`` (with
 * ``size >= CLONE_ARGS_SIZE_VER3``) spawns the child into the userland identified
 * by ``struct clone_args.userland`` once ``"/"`` is mounted in its mount
 * namespace. The first caller bootstraps PID 1 while concurrent bootstrap
 * callers wait killably; subsequent callers join the running PID namespace
 * until teardown begins.
 *
 * Requires ``CAP_SYS_ADMIN`` and ``CAP_SYS_CHROOT`` in the target user
 * namespace (plus ``CAP_SYS_CHROOT`` in the caller's user namespace when
 * chrooted) and an ancestor active PID namespace. May be combined with
 * ``CLONE_VFORK``, ``CLONE_PIDFD``, ``CLONE_PIDFD_AUTOKILL``,
 * ``CLONE_AUTOREAP``, ``CLONE_CLEAR_SIGHAND``, ``CLONE_INTO_CGROUP``, and
 * ``CLONE_NNP``.
 */
static bool userland_pidns_alive(struct pid_namespace *pid_ns)
{
	for (; pid_ns != &init_pid_ns; pid_ns = pid_ns->parent) {
		if (!(READ_ONCE(pid_ns->pid_allocated) & PIDNS_ADDING))
			return false;
	}
	return true;
}

int userland_prepare_fork(struct kernel_clone_args *args)
{
	struct file *file __free(fput) = fget(args->userland_fd);
	struct path root __free(path_put) = {};
	struct pid_namespace *pid_ns;
	bool bootstrapping = false;
	struct userland *userland;
	int ret;

	if (!file)
		return -EBADF;
	if (!userland_is_file(file))
		return -EINVAL;

	userland = file->private_data;
	if (!ns_capable(userland->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(userland->user_ns, CAP_SYS_CHROOT))
		return -EPERM;
	if (current_chrooted() && !ns_capable(current_user_ns(), CAP_SYS_CHROOT))
		return -EPERM;

	pid_ns = userland->ns->pid_ns_for_children;
	if (!pidns_is_ancestor(pid_ns, task_active_pid_ns(current)))
		return -EXDEV;

	ret = mnt_ns_get_root(userland->ns->mnt_ns, &root);
	if (ret)
		return ret;

	for (;;) {
		bool wait = false;

		scoped_guard(spinlock, &userland->lock) {
			switch (userland->state) {
			case USERLAND_INIT:
				if (!userland_pidns_alive(pid_ns))
					return -ESRCH;
				if (READ_ONCE(pid_ns->child_reaper))
					return -EBUSY;
				WRITE_ONCE(userland->state, USERLAND_FORKING);
				bootstrapping = true;
				break;
			case USERLAND_FORKING:
				wait = true;
				break;
			case USERLAND_RUNNING:
				if (!userland_pidns_alive(pid_ns))
					return -ESRCH;
				break;
			case USERLAND_DEAD:
				return -ESRCH;
			}
		}
		if (!wait)
			break;

		ret = wait_event_killable(userland->waitq,
					  READ_ONCE(userland->state) !=
					  USERLAND_FORKING);
		if (ret)
			return ret;
	}

	args->userland_file = no_free_ptr(file);
	args->userland = userland;
	args->userland_bootstrapping = bootstrapping;
	return 0;
}

int userland_finish_fork(struct kernel_clone_args *args,
			 struct task_struct *p)
{
	struct file *file __free(fput) = args->userland_file;
	struct userland *userland = args->userland;
	struct pid_namespace *pid_ns = userland->ns->pid_ns_for_children;
	int ret;

	args->userland_file = NULL;
	args->userland = NULL;
	if (!IS_ERR(p)) {
		if (args->userland_bootstrapping)
			wake_up_all(&userland->waitq);
		if (current->nsproxy->time_ns != userland->ns->time_ns)
			timens_commit(p, userland->ns->time_ns);
		return 0;
	}

	ret = PTR_ERR(p);
	if (args->userland_bootstrapping) {
		scoped_guard(spinlock, &userland->lock) {
			if (userland->state == USERLAND_FORKING)
				WRITE_ONCE(userland->state, USERLAND_INIT);
		}
		wake_up_all(&userland->waitq);
		if (ret == -EINVAL && !args->set_tid_size &&
		    (READ_ONCE(pid_ns->child_reaper) ||
		     (READ_ONCE(pid_ns->pid_allocated) & ~PIDNS_ADDING)))
			ret = -EBUSY;
	}
	if ((ret == -ENOMEM || ret == -EBUSY) &&
	    !userland_pidns_alive(pid_ns))
		return -ESRCH;

	return ret;
}
