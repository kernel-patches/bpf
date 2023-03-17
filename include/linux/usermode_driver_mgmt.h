/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * User mode driver management API.
 */
#ifndef __LINUX_USERMODE_DRIVER_MGMT_H__
#define __LINUX_USERMODE_DRIVER_MGMT_H__

#include <linux/usermode_driver.h>

/**
 * struct umd_mgmt - user mode driver management structure
 * @info: user mode driver information
 * @lock: lock to serialize requests to the UMD Handler
 * @post_start: function with additional operations after UMD Handler is started
 * @kmod: kernel module acting as UMD Loader, to start the UMD Handler
 * @kmod_loaded: whether @kmod is loaded or not
 *
 * Information necessary to manage the UMD during its lifecycle.
 */
struct umd_mgmt {
	struct umd_info info;
	struct mutex lock;
	int (*post_start)(struct umd_mgmt *mgmt);
	const char *kmod;
	bool kmod_loaded;
};

int umd_mgmt_send_recv(struct umd_mgmt *mgmt, void *in, size_t in_len,
		       void *out, size_t out_len);
int umd_mgmt_load(struct umd_mgmt *mgmt, char *start, char *end);
void umd_mgmt_unload(struct umd_mgmt *mgmt);

#endif /* __LINUX_USERMODE_DRIVER_MGMT_H__ */
