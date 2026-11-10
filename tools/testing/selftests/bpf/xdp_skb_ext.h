/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef XDP_PACKET_HEADROOM
#define XDP_PACKET_HEADROOM 256
#endif

/* Metadata in BPF_PROG_RUN must be this size or smaller */
#define MAX_META_LEN (XDP_PACKET_HEADROOM - (int)sizeof(struct xdp_frame))

#define SKB_MAX_CSUM_LEVEL 3
