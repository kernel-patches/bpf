// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/bpfilter.h>
#include <uapi/linux/bpf.h>
#include <linux/wait.h>
#include <linux/kmod.h>
#include <linux/fs.h>
#include <linux/file.h>
#include "../../bpfilter/msgfmt.h"

struct umd_mgmt bpfilter_ops;
EXPORT_SYMBOL_GPL(bpfilter_ops);

void bpfilter_umh_cleanup(struct umd_info *info)
{
	fput(info->pipe_to_umh);
	fput(info->pipe_from_umh);
	put_pid(info->tgid);
	info->tgid = NULL;
}
EXPORT_SYMBOL_GPL(bpfilter_umh_cleanup);

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
	err = umd_mgmt_send_recv(&bpfilter_ops, &req, sizeof(req), &reply,
				 sizeof(reply));
	if (err)
		return err;

	return reply.status;
}

static int bpfilter_post_start_umh(struct umd_mgmt *mgmt)
{
	struct mbox_request req = { .pid = current->pid };
	struct mbox_reply reply;

	/* health check that usermode process started correctly */
	if (umd_send_recv(&bpfilter_ops.info, &req, sizeof(req), &reply,
			  sizeof(reply)) != 0 || reply.status != 0)
		return -EFAULT;

	return 0;
}

int bpfilter_ip_set_sockopt(struct sock *sk, int optname, sockptr_t optval,
			    unsigned int optlen)
{
	return bpfilter_process_sockopt(sk, optname, optval, optlen, true);
}

int bpfilter_ip_get_sockopt(struct sock *sk, int optname, char __user *optval,
			    int __user *optlen)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	return bpfilter_process_sockopt(sk, optname, USER_SOCKPTR(optval), len,
					false);
}

static int __init bpfilter_sockopt_init(void)
{
	mutex_init(&bpfilter_ops.lock);
	bpfilter_ops.info.tgid = NULL;
	bpfilter_ops.info.driver_name = "bpfilter_umh";
	bpfilter_ops.post_start = bpfilter_post_start_umh;
	bpfilter_ops.kmod = "bpfilter";
	bpfilter_ops.kmod_loaded = false;

	return 0;
}
device_initcall(bpfilter_sockopt_init);
