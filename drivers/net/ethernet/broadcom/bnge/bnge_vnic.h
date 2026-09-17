/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Broadcom */

#ifndef _BNGE_VNIC_H_
#define _BNGE_VNIC_H_

struct bnge_net;
struct bnge_l2_filter;

#define BNGE_RSS_TABLE_ENTRIES		64
#define BNGE_RSS_TABLE_SIZE		(BNGE_RSS_TABLE_ENTRIES * 4)
#define BNGE_RSS_TABLE_MAX_TBL		8
#define BNGE_MAX_RSS_TABLE_SIZE			\
	(BNGE_RSS_TABLE_SIZE * BNGE_RSS_TABLE_MAX_TBL)
#define BNGE_MAX_RSS_TABLE_ENTRIES				\
	(BNGE_RSS_TABLE_ENTRIES * BNGE_RSS_TABLE_MAX_TBL)

#define BNGE_MAX_ETH_RSS_CTX	32
#define BNGE_MAX_CTX_PER_VNIC	8

#define BNGE_MAX_MC_ADDRS	16
#define BNGE_MAX_UC_ADDRS	4

enum {
	BNGE_VNIC_DEFAULT	= 0,
	BNGE_VNIC_NTUPLE	= 1
};

enum {
	BNGE_VNIC_RSS_FLAG	= BIT(0),
	BNGE_VNIC_MCAST_FLAG	= BIT(1),
	BNGE_VNIC_UCAST_FLAG	= BIT(2),
	BNGE_VNIC_NTUPLE_FLAG	= BIT(3)
};

struct bnge_vnic_info {
	u16		fw_vnic_id;
	u16		fw_rss_cos_lb_ctx[BNGE_MAX_CTX_PER_VNIC];
	u16		mru;
	/* index 0 always dev_addr */
	struct bnge_l2_filter *l2_filters[BNGE_MAX_UC_ADDRS];
	u16		uc_filter_count;
	u8		*uc_list;
	dma_addr_t	rss_table_dma_addr;
	__le16		*rss_table;
	dma_addr_t	rss_hash_key_dma_addr;
	u64		*rss_hash_key;
	int		rss_table_size;
	u32		rx_mask;

	u8		*mc_list;
	int		mc_list_size;
	int		mc_list_count;
	dma_addr_t	mc_list_mapping;

	u32		flags;
	u32		vnic_id;
};

struct bnge_rss_ctx {
	struct bnge_vnic_info vnic;
	u32 index;
};

void bnge_fill_hw_rss_tbl(struct bnge_net *bn, struct bnge_vnic_info *vnic);
int bnge_hwrm_vnic_rss_cfg(struct bnge_net *bn,
			   struct bnge_vnic_info *vnic);
int bnge_setup_vnic(struct bnge_net *bn, struct bnge_vnic_info *vnic);
void bnge_set_dflt_rss_indir_tbl(struct bnge_dev *bd);
int bnge_alloc_rfs_vnic(struct bnge_net *bn);
int bnge_alloc_vnic_rss_table(struct bnge_net *bn,
			      struct bnge_vnic_info *vnic);
struct bnge_rss_ctx *bnge_get_rss_ctx_from_index(struct bnge_net *bn, u32 idx);
void bnge_modify_rss(struct bnge_net *bn, struct ethtool_rxfh_context *ctx,
		     struct bnge_rss_ctx *rss_ctx,
		     const struct ethtool_rxfh_param *rxfh);
void bnge_del_one_rss_ctx(struct bnge_net *bn, struct bnge_rss_ctx *rss_ctx,
			  bool all);
void bnge_hwrm_realloc_rss_ctx_vnic(struct bnge_net *bn);
void bnge_clear_rss_ctxs(struct bnge_net *bn);
#endif /* _BNGE_VNIC_H_ */
