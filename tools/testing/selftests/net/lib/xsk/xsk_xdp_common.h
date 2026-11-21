/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XSK_XDP_COMMON_H_
#define XSK_XDP_COMMON_H_

#define MAX_SOCKETS 2
/* Pads the UDP header of a test packet so that the payload is 4-byte aligned */
#define PKT_HDR_PAD 2

struct xdp_info {
	__u64 count;
} __attribute__((aligned(32)));

#endif /* XSK_XDP_COMMON_H_ */
