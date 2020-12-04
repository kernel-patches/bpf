/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/*
 * Copyright (c) 2020 Intel
 */

#ifndef __UAPI_LINUX_XDP_PROPERTIES__
#define __UAPI_LINUX_XDP_PROPERTIES__

/* ETH_GSTRING_LEN define is needed. */
#include <linux/ethtool.h>

#define XDP_PROPERTIES_ABORTED_STR	"xdp-aborted"
#define XDP_PROPERTIES_DROP_STR		"xdp-drop"
#define XDP_PROPERTIES_PASS_STR		"xdp-pass"
#define XDP_PROPERTIES_TX_STR		"xdp-tx"
#define XDP_PROPERTIES_REDIRECT_STR	"xdp-redirect"
#define XDP_PROPERTIES_ZEROCOPY_STR	"xdp-zerocopy"
#define XDP_PROPERTIES_HW_OFFLOAD_STR	"xdp-hw-offload"

#define	DECLARE_XDP_PROPERTIES_TABLE(name)		\
	const char name[][ETH_GSTRING_LEN] = {		\
		XDP_PROPERTIES_ABORTED_STR,		\
		XDP_PROPERTIES_DROP_STR,		\
		XDP_PROPERTIES_PASS_STR,		\
		XDP_PROPERTIES_TX_STR,			\
		XDP_PROPERTIES_REDIRECT_STR,		\
		XDP_PROPERTIES_ZEROCOPY_STR,		\
		XDP_PROPERTIES_HW_OFFLOAD_STR,		\
	}

#endif  /* __UAPI_LINUX_XDP_PROPERTIES__ */
