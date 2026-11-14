/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/vsock.yaml */
/* YNL-GEN uapi header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _UAPI_LINUX_VSOCK_NETLINK_H
#define _UAPI_LINUX_VSOCK_NETLINK_H

#define VSOCK_FAMILY_NAME	"vsock"
#define VSOCK_FAMILY_VERSION	1

enum {
	VSOCK_A_NETNS_ID = 1,
	VSOCK_A_NETNS_FD,
	VSOCK_A_NETNS_PID,

	__VSOCK_A_MAX,
	VSOCK_A_MAX = (__VSOCK_A_MAX - 1)
};

enum {
	VSOCK_CMD_DEV_NETNS_SET = 1,
	VSOCK_CMD_DEV_NETNS_GET,

	__VSOCK_CMD_MAX,
	VSOCK_CMD_MAX = (__VSOCK_CMD_MAX - 1)
};

#endif /* _UAPI_LINUX_VSOCK_NETLINK_H */
