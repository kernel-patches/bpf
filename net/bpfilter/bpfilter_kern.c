// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/init.h>
#include <linux/module.h>
#include <linux/umh.h>
#include <linux/bpfilter.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include "msgfmt.h"

extern char bpfilter_umh_start;
extern char bpfilter_umh_end;

static void shutdown_umh(void)
{
	struct umd_info *info = &bpfilter_ops.info;
	struct pid *tgid = info->tgid;

	if (tgid) {
		kill_pid(tgid, SIGKILL, 1);
		wait_event(tgid->wait_pidfd, thread_group_exited(tgid));
		bpfilter_umh_cleanup(info);
	}
}

static int bpfilter_process_sockopt(struct sock *sk, int optname,
				    sockptr_t optval, unsigned int optlen,
				    bool is_set)
{
	struct mbox_request req = {
		.is_set		= is_set,
		.pid		= current->pid,
		.cmd		= optname,
		.addr		= (uintptr_t)optval.user,
		.len		= optlen,
	};
	struct mbox_reply reply;
	int err;

	if (sockptr_is_kernel(optval)) {
		pr_err("kernel access not supported\n");
		return -EFAULT;
	}
	err = umd_send_recv(&bpfilter_ops.info, &req, sizeof(req), &reply,
			    sizeof(reply));
	if (err) {
		shutdown_umh();
		return err;
	}

	return reply.status;
}

static int start_umh(void)
{
	struct mbox_request req = { .pid = current->pid };
	struct mbox_reply reply;
	int err;

	/* fork usermode process */
	err = fork_usermode_driver(&bpfilter_ops.info);
	if (err)
		return err;
	pr_info("Loaded bpfilter_umh pid %d\n", pid_nr(bpfilter_ops.info.tgid));

	/* health check that usermode process started correctly */
	if (umd_send_recv(&bpfilter_ops.info, &req, sizeof(req), &reply,
			  sizeof(reply)) != 0 || reply.status != 0) {
		shutdown_umh();
		return -EFAULT;
	}

	return 0;
}

static int __init load_umh(void)
{
	int err;

	err = umd_load_blob(&bpfilter_ops.info,
			    &bpfilter_umh_start,
			    &bpfilter_umh_end - &bpfilter_umh_start);
	if (err)
		return err;

	mutex_lock(&bpfilter_ops.lock);
	err = start_umh();
	if (!err && IS_ENABLED(CONFIG_INET)) {
		bpfilter_ops.sockopt = &bpfilter_process_sockopt;
		bpfilter_ops.start = &start_umh;
	}
	mutex_unlock(&bpfilter_ops.lock);
	if (err)
		umd_unload_blob(&bpfilter_ops.info);
	return err;
}

static void __exit fini_umh(void)
{
	mutex_lock(&bpfilter_ops.lock);
	if (IS_ENABLED(CONFIG_INET)) {
		shutdown_umh();
		bpfilter_ops.start = NULL;
		bpfilter_ops.sockopt = NULL;
	}
	mutex_unlock(&bpfilter_ops.lock);

	umd_unload_blob(&bpfilter_ops.info);
}
module_init(load_umh);
module_exit(fini_umh);
MODULE_LICENSE("GPL");
