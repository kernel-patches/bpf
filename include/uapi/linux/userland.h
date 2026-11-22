/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

#ifndef _UAPI_LINUX_USERLAND_H
#define _UAPI_LINUX_USERLAND_H

#include <linux/ioctl.h>

/**
 * enum userland_flags - Flags for userland_open()
 * @USERLAND_KILL_ON_CLOSE: Send %SIGKILL to userland init on final fd release.
 * @USERLAND_CLOSE_ON_EXEC: Set %O_CLOEXEC on the returned control fd.
 * @USERLAND_ALL_FLAGS: Mask of all valid flags accepted by userland_open().
 *
 * Every userland created by userland_open() allocates a full set of
 * detached namespaces owned by a fresh user namespace.
 */
enum userland_flags {
	USERLAND_KILL_ON_CLOSE	= 0x00000001,
	USERLAND_CLOSE_ON_EXEC	= 0x00000002,
	USERLAND_ALL_FLAGS	= 0x00000003,
};

#define USERLAND_IOCTL_MAGIC	0xB9

/**
 * DOC: USERLAND_GET_NSFD
 *
 * ``ioctl(userland_fd, USERLAND_GET_NSFD, nstype)`` opens an ``nsfs`` file
 * descriptor (with ``O_CLOEXEC``) for the member namespace identified by
 * ``nstype`` (one of ``CLONE_NEWNS``, ``CLONE_NEWCGROUP``,
 * ``CLONE_NEWUTS``, ``CLONE_NEWIPC``, ``CLONE_NEWUSER``, ``CLONE_NEWPID``,
 * ``CLONE_NEWNET``, or ``CLONE_NEWTIME``).
 *
 * Requires ``CAP_SYS_ADMIN`` in the userland's user namespace.
 * Opening ``CLONE_NEWPID`` additionally requires running in an ancestor
 * active PID namespace and that userland init is running.
 */
#define USERLAND_GET_NSFD	_IO(USERLAND_IOCTL_MAGIC, 0x01)

/**
 * DOC: USERLAND_SHARE_NSFD
 *
 * ``ioctl(userland_fd, USERLAND_SHARE_NSFD, ns_fd)`` replaces the corresponding
 * member namespace of ``userland_fd`` with ``ns_fd`` (``CLONE_NEWCGROUP``,
 * ``CLONE_NEWIPC``, ``CLONE_NEWUTS``, ``CLONE_NEWNET``, or ``CLONE_NEWTIME``)
 * while ``userland_fd`` is in ``USERLAND_INIT``.
 *
 * Requires ``CAP_SYS_ADMIN`` in the userland's user namespace, plus
 * ``CAP_SYS_ADMIN`` in ``ns_fd``'s owning user namespace when the caller is
 * not already a member of ``ns_fd``.
 */
#define USERLAND_SHARE_NSFD	_IO(USERLAND_IOCTL_MAGIC, 0x02)

#endif /* _UAPI_LINUX_USERLAND_H */
