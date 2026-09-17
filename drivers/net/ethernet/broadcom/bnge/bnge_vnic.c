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

void bnge_set_dflt_rss_indir_tbl(struct bnge_dev *bd)
{
	u16 max_entries, pad;
	u32 *rss_indir_tbl;
	u16 i;

	max_entries = bnge_get_rxfh_indir_size(bd);
	rss_indir_tbl = &bd->rss_indir_tbl[0];

	for (i = 0; i < max_entries; i++)
		rss_indir_tbl[i] = ethtool_rxfh_indir_default(i,
							      bd->rx_nr_rings);

	pad = bd->rss_indir_tbl_entries - max_entries;
	if (pad)
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
