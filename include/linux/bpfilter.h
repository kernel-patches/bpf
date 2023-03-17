/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPFILTER_H
#define _LINUX_BPFILTER_H

#include <uapi/linux/bpfilter.h>
#include <linux/usermode_driver_mgmt.h>
#include <linux/sockptr.h>

struct sock;
int bpfilter_ip_set_sockopt(struct sock *sk, int optname, sockptr_t optval,
			    unsigned int optlen);
int bpfilter_ip_get_sockopt(struct sock *sk, int optname, char __user *optval,
			    int __user *optlen);
void bpfilter_umh_cleanup(struct umd_info *info);

extern struct umd_mgmt bpfilter_ops;
#endif
