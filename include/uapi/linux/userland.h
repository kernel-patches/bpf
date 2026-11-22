/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2017-2019 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2026 Opinsys Oy
 */

#ifndef _UAPI_LINUX_USERLAND_H
#define _UAPI_LINUX_USERLAND_H

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

#endif /* _UAPI_LINUX_USERLAND_H */
