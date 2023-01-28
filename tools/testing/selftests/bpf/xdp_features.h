/* SPDX-License-Identifier: GPL-2.0 */

/* test commands */
enum test_commands {
	CMD_STOP,		/* CMD */
	CMD_START,		/* CMD + xdp feature */
	CMD_ECHO,		/* CMD */
	CMD_ACK,		/* CMD + data */
	CMD_GET_XDP_CAP,	/* CMD */
	CMD_GET_STATS,		/* CMD */
};

#define DUT_CTRL_PORT	12345
#define DUT_ECHO_PORT	12346

struct tlv_hdr {
	__be16 type;
	__be16 len;
	__be32 data[];
};

enum {
	XDP_FEATURE_ABORTED,
	XDP_FEATURE_DROP,
	XDP_FEATURE_PASS,
	XDP_FEATURE_TX,
	XDP_FEATURE_REDIRECT,
	XDP_FEATURE_NDO_XMIT,
	XDP_FEATURE_XSK_ZEROCOPY,
	XDP_FEATURE_HW_OFFLOAD,
	XDP_FEATURE_RX_SG,
	XDP_FEATURE_NDO_XMIT_SG,
};
