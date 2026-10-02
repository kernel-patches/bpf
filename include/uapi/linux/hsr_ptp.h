/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
#ifndef __UAPI_HSR_PTP_H
#define __UAPI_HSR_PTP_H

#include <linux/types.h>

#define HSR_INLINE_HDR  0xaf485352
#define HSR_INLINE_HDR_PORT_A	1
#define HSR_INLINE_HDR_PORT_B	2

struct hsr_inline_header {
	__u8 tx_port;
	__u8 hsr_hdr;
	__u8 __pad0[4];
	__be32 magic;
	__u8 __pad1[2];
	__be16 eth_type;
} __attribute__ ((packed));

#endif
