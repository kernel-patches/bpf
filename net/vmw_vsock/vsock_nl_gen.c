// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/vsock.yaml */
/* YNL-GEN kernel source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <net/netlink.h>
#include <net/genetlink.h>

#include "vsock_nl_gen.h"

#include <uapi/linux/vsock_netlink.h>

/* VSOCK_CMD_DEV_NETNS_SET - do */
static const struct nla_policy vsock_dev_netns_set_nl_policy[VSOCK_A_NETNS_PID + 1] = {
	[VSOCK_A_NETNS_FD] = { .type = NLA_U32, },
	[VSOCK_A_NETNS_PID] = { .type = NLA_U32, },
};

/* Ops table for vsock */
static const struct genl_split_ops vsock_nl_ops[] = {
	{
		.cmd		= VSOCK_CMD_DEV_NETNS_SET,
		.doit		= vsock_nl_dev_netns_set_doit,
		.policy		= vsock_dev_netns_set_nl_policy,
		.maxattr	= VSOCK_A_NETNS_PID,
		.flags		= GENL_ADMIN_PERM | GENL_CMD_CAP_DO,
	},
	{
		.cmd	= VSOCK_CMD_DEV_NETNS_GET,
		.doit	= vsock_nl_dev_netns_get_doit,
		.flags	= GENL_CMD_CAP_DO,
	},
};

struct genl_family vsock_nl_family __ro_after_init = {
	.name		= VSOCK_FAMILY_NAME,
	.version	= VSOCK_FAMILY_VERSION,
	.netnsok	= true,
	.parallel_ops	= true,
	.module		= THIS_MODULE,
	.split_ops	= vsock_nl_ops,
	.n_split_ops	= ARRAY_SIZE(vsock_nl_ops),
};
