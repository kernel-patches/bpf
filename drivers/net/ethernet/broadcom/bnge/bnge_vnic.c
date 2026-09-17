// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2026 Broadcom.

#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <linux/ethtool.h>

#include "bnge.h"
#include "bnge_netdev.h"
#include "bnge_vnic.h"
#include "bnge_hwrm_lib.h"
#include "bnge_filter.h"
#include "bnge_ethtool.h"

void bnge_set_dflt_rss_indir_tbl(struct bnge_dev *bd,
				 struct ethtool_rxfh_context *rss_ctx)
{
	u16 max_entries, pad;
	u32 *rss_indir_tbl;
	u16 i;

	max_entries = bnge_get_rxfh_indir_size(bd);

	if (rss_ctx)
		rss_indir_tbl = ethtool_rxfh_context_indir(rss_ctx);
	else
		rss_indir_tbl = &bd->rss_indir_tbl[0];

	for (i = 0; i < max_entries; i++)
		rss_indir_tbl[i] = ethtool_rxfh_indir_default(i,
							      bd->rx_nr_rings);

	pad = bd->rss_indir_tbl_entries - max_entries;
	if (pad && !rss_ctx)
		memset(&rss_indir_tbl[i], 0, pad * sizeof(*rss_indir_tbl));
}

void bnge_fill_hw_rss_tbl(struct bnge_net *bn, struct bnge_vnic_info *vnic)
{
	__le16 *ring_tbl = vnic->rss_table;
	struct bnge_rx_ring_info *rxr;
	struct bnge_dev *bd = bn->bd;
	u16 tbl_size, i;

	tbl_size = bnge_get_rxfh_indir_size(bd);

	for (i = 0; i < tbl_size; i++) {
		u16 ring_id, j;

		if (vnic->flags & BNGE_VNIC_NTUPLE_FLAG)
			j = ethtool_rxfh_indir_default(i, bd->rx_nr_rings);
		else if (vnic->flags & BNGE_VNIC_RSSCTX_FLAG)
			j = ethtool_rxfh_context_indir(vnic->rss_ctx)[i];
		else
			j = bd->rss_indir_tbl[i];

		rxr = &bn->rx_ring[j];

		ring_id = rxr->rx_ring_struct.fw_ring_id;
		*ring_tbl++ = cpu_to_le16(ring_id);
		ring_id = bnge_cp_ring_for_rx(rxr);
		*ring_tbl++ = cpu_to_le16(ring_id);
	}
}

int bnge_hwrm_vnic_rss_cfg(struct bnge_net *bn,
			   struct bnge_vnic_info *vnic)
{
	int rc;

	rc = bnge_hwrm_vnic_set_rss(bn, vnic, true);
	if (rc) {
		netdev_err(bn->netdev, "hwrm vnic %d set rss failure rc: %d\n",
			   vnic->vnic_id, rc);
		return rc;
	}
	rc = bnge_hwrm_vnic_cfg(bn, vnic);
	if (rc)
		netdev_err(bn->netdev, "hwrm vnic %d cfg failure rc: %d\n",
			   vnic->vnic_id, rc);
	return rc;
}

int bnge_setup_vnic(struct bnge_net *bn, struct bnge_vnic_info *vnic)
{
	struct bnge_dev *bd = bn->bd;
	int rc, i, nr_ctxs;

	nr_ctxs = bnge_cal_nr_rss_ctxs(bd->rx_nr_rings);
	for (i = 0; i < nr_ctxs; i++) {
		rc = bnge_hwrm_vnic_ctx_alloc(bd, vnic, i);
		if (rc) {
			netdev_err(bn->netdev, "hwrm vnic %d ctx %d alloc failure rc: %d\n",
				   vnic->vnic_id, i, rc);
			return -ENOMEM;
		}
		bn->rsscos_nr_ctxs++;
	}

	rc = bnge_hwrm_vnic_rss_cfg(bn, vnic);
	if (rc)
		return rc;

	if (bnge_is_agg_reqd(bd)) {
		rc = bnge_hwrm_vnic_set_hds(bn, vnic);
		if (rc)
			netdev_err(bn->netdev, "hwrm vnic %d set hds failure rc: %d\n",
				   vnic->vnic_id, rc);
	}
	return rc;
}

static int bnge_alloc_and_setup_vnic(struct bnge_net *bn,
				     struct bnge_vnic_info *vnic,
				     u16 rx_rings)
{
	int rc;

	rc = bnge_hwrm_vnic_alloc(bn->bd, vnic, rx_rings);
	if (rc) {
		netdev_err(bn->netdev, "hwrm vnic %u alloc failure rc: %d\n",
			   vnic->vnic_id, rc);
		return rc;
	}

	/* If bnge_setup_vnic() fails, the VNIC allocated above is not freed
	 * here; the caller (bnge_open_core) unwinds via its err_out path,
	 */
	return bnge_setup_vnic(bn, vnic);
}

int bnge_alloc_rfs_vnic(struct bnge_net *bn)
{
	struct bnge_vnic_info *vnic;

	vnic = &bn->vnic_info[BNGE_VNIC_NTUPLE];
	return bnge_alloc_and_setup_vnic(bn, vnic, bn->bd->rx_nr_rings);
}

void bnge_modify_rss(struct bnge_net *bn, struct ethtool_rxfh_context *ctx,
		     struct bnge_rss_ctx *rss_ctx,
		     const struct ethtool_rxfh_param *rxfh)
{
	struct bnge_dev *bd = bn->bd;

	if (rxfh->key) {
		if (rss_ctx) {
			memcpy(rss_ctx->vnic.rss_hash_key, rxfh->key,
			       HW_HASH_KEY_SIZE);
		} else {
			memcpy(bn->rss_hash_key, rxfh->key, HW_HASH_KEY_SIZE);
			bn->rss_hash_key_updated = true;
		}
	}

	if (rxfh->indir) {
		u32 i, pad, tbl_size = bnge_get_rxfh_indir_size(bd);
		u32 *indir_tbl = bd->rss_indir_tbl;

		if (rss_ctx)
			indir_tbl = ethtool_rxfh_context_indir(ctx);
		for (i = 0; i < tbl_size; i++)
			indir_tbl[i] = rxfh->indir[i];
		pad = bd->rss_indir_tbl_entries - tbl_size;
		if (pad && !rss_ctx)
			memset(&indir_tbl[i], 0, pad * sizeof(*indir_tbl));
	}
}

void bnge_del_one_rss_ctx(struct bnge_net *bn, struct bnge_rss_ctx *rss_ctx,
			  bool all)
{
	struct bnge_vnic_info *vnic = &rss_ctx->vnic;
	int i;

	bnge_hwrm_vnic_free_one(bn->bd, &rss_ctx->vnic);
	for (i = 0; i < BNGE_MAX_CTX_PER_VNIC; i++) {
		if (vnic->fw_rss_cos_lb_ctx[i] != INVALID_HW_RING_ID)
			bnge_hwrm_vnic_ctx_free_one(bn->bd, vnic, i);
	}

	if (!all)
		return;

	if (vnic->rss_table)
		dma_free_coherent(bn->bd->dev, vnic->rss_table_size,
				  vnic->rss_table,
				  vnic->rss_table_dma_addr);
	bn->num_rss_ctx--;
}

void bnge_hwrm_realloc_rss_ctx_vnic(struct bnge_net *bn)
{
	bool set_tpa = !!(bn->priv_flags & BNGE_NET_EN_TPA);
	struct ethtool_rxfh_context *ctx;
	unsigned long context;

	/* Erasing lost contexts touches netdev->ethtool->rss_ctx and calls
	 * ethtool_rxfh_context_lost(), which requires the ethtool rss_lock.
	 */
	mutex_lock(&bn->netdev->ethtool->rss_lock);
	xa_for_each(&bn->netdev->ethtool->rss_ctx, context, ctx) {
		struct bnge_rss_ctx *rss_ctx = ethtool_rxfh_context_priv(ctx);
		struct bnge_vnic_info *vnic = &rss_ctx->vnic;

		if (bnge_hwrm_vnic_alloc(bn->bd, vnic, bn->bd->rx_nr_rings) ||
		    bnge_hwrm_vnic_set_tpa(bn->bd, vnic, set_tpa) ||
		    bnge_setup_vnic(bn, vnic)) {
			netdev_err(bn->netdev, "Failed to restore RSS ctx %d\n",
				   rss_ctx->index);
			bnge_del_one_rss_ctx(bn, rss_ctx, true);
			ethtool_rxfh_context_lost(bn->netdev, rss_ctx->index);
		}
	}
	mutex_unlock(&bn->netdev->ethtool->rss_lock);
}

void bnge_clear_rss_ctxs(struct bnge_net *bn)
{
	struct ethtool_rxfh_context *ctx;
	unsigned long context;

	xa_for_each(&bn->netdev->ethtool->rss_ctx, context, ctx) {
		struct bnge_rss_ctx *rss_ctx = ethtool_rxfh_context_priv(ctx);

		bnge_del_one_rss_ctx(bn, rss_ctx, false);
	}
}

struct bnge_rss_ctx *bnge_get_rss_ctx_from_index(struct bnge_net *bn, u32 idx)
{
	struct ethtool_rxfh_context *ctx;

	ctx = xa_load(&bn->netdev->ethtool->rss_ctx, idx);
	if (!ctx)
		return NULL;
	return ethtool_rxfh_context_priv(ctx);
}

int bnge_alloc_vnic_rss_table(struct bnge_net *bn,
			      struct bnge_vnic_info *vnic)
{
	unsigned int size = L1_CACHE_ALIGN(BNGE_MAX_RSS_TABLE_SIZE);

	vnic->rss_table_size = size + HW_HASH_KEY_SIZE;
	vnic->rss_table = dma_alloc_coherent(bn->bd->dev,
					     vnic->rss_table_size,
					     &vnic->rss_table_dma_addr,
					     GFP_KERNEL);
	if (!vnic->rss_table)
		return -ENOMEM;

	vnic->rss_hash_key = ((void *)vnic->rss_table) + size;
	vnic->rss_hash_key_dma_addr = vnic->rss_table_dma_addr + size;
	return 0;
}

void bnge_init_vnic_mem(struct bnge_vnic_info *vnic)
{
	int i;

	vnic->fw_vnic_id = INVALID_HW_RING_ID;
	vnic->vnic_id = BNGE_VNIC_ID_INVALID;

	for (i = 0; i < BNGE_MAX_CTX_PER_VNIC; i++)
		vnic->fw_rss_cos_lb_ctx[i] = INVALID_HW_RING_ID;
}
