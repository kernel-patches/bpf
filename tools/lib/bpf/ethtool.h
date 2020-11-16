/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Generic netlink ethtool family required defines
 *
 * Copyright (c) 2020 Intel
 */

#ifndef __LIBBPF_ETHTOOL_H_
#define __LIBBPF_ETHTOOL_H_

#include <linux/ethtool_netlink.h>

#define DIV_ROUND_UP(n, d)  (((n) + (d) - 1) / (d))
#define FEATURE_BITS_TO_BLOCKS(n_bits)      DIV_ROUND_UP(n_bits, 32U)

#define FEATURE_WORD(blocks, index)  ((blocks)[(index) / 32U])
#define FEATURE_FIELD_FLAG(index)       (1U << (index) % 32U)
#define FEATURE_BIT_IS_SET(blocks, index)        \
		(FEATURE_WORD(blocks, index) & FEATURE_FIELD_FLAG(index))

#define NETDEV_XDP_STR			"xdp"
#define NETDEV_XDP_LEN			4

#define NETDEV_AF_XDP_ZC_STR		"af-xdp-zc"
#define NETDEV_AF_XDP_ZC_LEN		10

#define BUF_SIZE_4096			4096
#define BUF_SIZE_8192			8192

#define MAX_FEATURES			500

struct ethnl_params {
	const char *ifname;
	const char *nl_family;
	int features;
	int xdp_idx;
	int xdp_zc_idx;
	int xdp_flags;
	int xdp_zc_flags;
	__u16 fam_id;
};

int libbpf_ethnl_get_ethtool_family_id(struct ethnl_params *param);
int libbpf_ethnl_get_netdev_features(struct ethnl_params *param);
int libbpf_ethnl_get_active_bits(struct ethnl_params *param);

#endif /* __LIBBPF_ETHTOOL_H_ */

