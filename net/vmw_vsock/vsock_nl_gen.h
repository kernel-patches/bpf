/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/vsock.yaml */
/* YNL-GEN kernel header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_VSOCK_GEN_H
#define _LINUX_VSOCK_GEN_H

#include <net/netlink.h>
#include <net/genetlink.h>

#include <uapi/linux/vsock_netlink.h>

int vsock_nl_dev_netns_set_doit(struct sk_buff *skb, struct genl_info *info);
int vsock_nl_dev_netns_get_doit(struct sk_buff *skb, struct genl_info *info);

extern struct genl_family vsock_nl_family;

#endif /* _LINUX_VSOCK_GEN_H */
