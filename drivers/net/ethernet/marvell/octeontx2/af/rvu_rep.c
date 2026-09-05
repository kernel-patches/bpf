// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/bitfield.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "rvu.h"
#include "rvu_reg.h"

#define M(_name, _id, _fn_name, _req_type, _rsp_type)			\
static struct _req_type __maybe_unused					\
*otx2_mbox_alloc_msg_ ## _fn_name(struct rvu *rvu, int devid)		\
{									\
	struct _req_type *req;						\
									\
	req = (struct _req_type *)otx2_mbox_alloc_msg_rsp(		\
		&rvu->afpf_wq_info.mbox_up, devid, sizeof(struct _req_type), \
		sizeof(struct _rsp_type));				\
	if (!req)							\
		return NULL;						\
	req->hdr.sig = OTX2_MBOX_REQ_SIG;				\
	req->hdr.id = _id;						\
	return req;							\
}

MBOX_UP_REP_MESSAGES
#undef M

static int rvu_rep_up_notify(struct rvu *rvu, struct rep_event *event)
{
	struct rvu_pfvf *pfvf = rvu_get_pfvf(rvu, event->pcifunc);
	struct rep_event *msg;
	int pf;

	pf = rvu_get_pf(rvu->pdev, event->pcifunc);

	if (event->event & RVU_EVENT_MAC_ADDR_CHANGE)
		ether_addr_copy(pfvf->mac_addr, event->evt_data.mac);

	if (event->event & RVU_EVENT_PFVF_STATE)
		pf = rvu_get_pf(rvu->pdev, event->hdr.pcifunc);
	mutex_lock(&rvu->mbox_lock);
	msg = otx2_mbox_alloc_msg_rep_event_up_notify(rvu, pf);
	if (!msg) {
		mutex_unlock(&rvu->mbox_lock);
		return -ENOMEM;
	}

	msg->hdr.pcifunc = event->pcifunc;
	msg->event = event->event;
	msg->pcifunc = event->pcifunc;

	if (event->event & RVU_EVENT_PFVF_STATE)
		msg->hdr.pcifunc = event->hdr.pcifunc;

	memcpy(&msg->evt_data, &event->evt_data, sizeof(struct rep_evt_data));

	otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, pf);

	otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, pf);

	otx2_mbox_wait_for_rsp(&rvu->afpf_wq_info.mbox_up, pf);

	mutex_unlock(&rvu->mbox_lock);
	return 0;
}

static void rvu_rep_wq_handler(struct work_struct *work)
{
	struct rvu *rvu = container_of(work, struct rvu, rep_evt_work);
	struct rep_evtq_ent *qentry;
	struct rep_event *event;
	unsigned long flags;

	do {
		spin_lock_irqsave(&rvu->rep_evtq_lock, flags);
		qentry = list_first_entry_or_null(&rvu->rep_evtq_head,
						  struct rep_evtq_ent,
						  node);
		if (qentry)
			list_del(&qentry->node);

		spin_unlock_irqrestore(&rvu->rep_evtq_lock, flags);
		if (!qentry)
			break; /* nothing more to process */

		event = &qentry->event;

		rvu_rep_up_notify(rvu, event);
		kfree(qentry);
	} while (1);
}

int rvu_mbox_handler_rep_event_notify(struct rvu *rvu, struct rep_event *req,
				      struct msg_rsp *rsp)
{
	struct workqueue_struct *wq;
	struct rep_evtq_ent *qentry;

	wq = READ_ONCE(rvu->rep_evt_wq);
	if (!wq)
		return -EINVAL;

	/* Only the registered representor PF may send REP_EVENT_NOTIFY. */
	if (req->hdr.pcifunc != rvu->rep_pcifunc)
		return -EPERM;

	/* The mailbox dispatcher normalises only the header pcifunc; the
	 * nested struct rep_event::pcifunc body field is sender-controlled
	 * and is later used by rvu_rep_up_notify() to index rvu->pf[] /
	 * rvu->hwvf[].  Reject out-of-range body selectors before queueing.
	 */
	if (!is_pf_func_valid(rvu, req->pcifunc))
		return -EINVAL;

	/* Only CGX-mapped PFs are present in the representor map. */
	if (!is_pf_cgxmapped(rvu, rvu_get_pf(rvu->pdev, req->pcifunc)))
		return -EINVAL;

	if ((req->event & RVU_EVENT_PFVF_STATE) &&
	    rvu_get_pf(rvu->pdev, req->hdr.pcifunc) >= rvu->hw->total_pfs)
		return -EINVAL;

	qentry = kmalloc_obj(*qentry, GFP_ATOMIC);
	if (!qentry)
		return -ENOMEM;

	qentry->event = *req;
	spin_lock(&rvu->rep_evtq_lock);
	list_add_tail(&qentry->node, &rvu->rep_evtq_head);
	spin_unlock(&rvu->rep_evtq_lock);
	queue_work(wq, &rvu->rep_evt_work);
	return 0;
}

int rvu_rep_notify_pfvf_state(struct rvu *rvu, u16 pcifunc, bool enable)
{
	struct rep_event req = { 0 };
	struct msg_rsp rsp;

	if (!is_pf_cgxmapped(rvu, rvu_get_pf(rvu->pdev, pcifunc)))
		return 0;

	req.hdr.pcifunc = rvu->rep_pcifunc;
	req.event = RVU_EVENT_PFVF_STATE;
	req.pcifunc = pcifunc;
	req.evt_data.vf_state = enable;
	return rvu_mbox_handler_rep_event_notify(rvu, &req, &rsp);
}

#define RVU_LF_RX_STATS(reg) \
		rvu_read64(rvu, blkaddr, NIX_AF_LFX_RX_STATX(nixlf, reg))

#define RVU_LF_TX_STATS(reg) \
		rvu_read64(rvu, blkaddr, NIX_AF_LFX_TX_STATX(nixlf, reg))

int rvu_mbox_handler_nix_lf_stats(struct rvu *rvu,
				  struct nix_stats_req *req,
				  struct nix_stats_rsp *rsp)
{
	u16 pcifunc = req->pcifunc;
	int nixlf, blkaddr, err;
	struct msg_req rst_req;
	struct msg_rsp rst_rsp;

	err = nix_get_nixlf(rvu, pcifunc, &nixlf, &blkaddr);
	if (err)
		return 0;

	if (req->reset) {
		rst_req.hdr.pcifunc = pcifunc;
		return rvu_mbox_handler_nix_stats_rst(rvu, &rst_req, &rst_rsp);
	}
	rsp->rx.octs = RVU_LF_RX_STATS(RX_OCTS);
	rsp->rx.ucast = RVU_LF_RX_STATS(RX_UCAST);
	rsp->rx.bcast = RVU_LF_RX_STATS(RX_BCAST);
	rsp->rx.mcast = RVU_LF_RX_STATS(RX_MCAST);
	rsp->rx.drop = RVU_LF_RX_STATS(RX_DROP);
	rsp->rx.err = RVU_LF_RX_STATS(RX_ERR);
	rsp->rx.drop_octs = RVU_LF_RX_STATS(RX_DROP_OCTS);
	rsp->rx.drop_mcast = RVU_LF_RX_STATS(RX_DRP_MCAST);
	rsp->rx.drop_bcast = RVU_LF_RX_STATS(RX_DRP_BCAST);

	rsp->tx.octs = RVU_LF_TX_STATS(TX_OCTS);
	rsp->tx.ucast = RVU_LF_TX_STATS(TX_UCAST);
	rsp->tx.bcast = RVU_LF_TX_STATS(TX_BCAST);
	rsp->tx.mcast = RVU_LF_TX_STATS(TX_MCAST);
	rsp->tx.drop = RVU_LF_TX_STATS(TX_DROP);

	rsp->pcifunc = req->pcifunc;
	return 0;
}

static u16 rvu_rep_get_vlan_id(struct rvu *rvu, u16 pcifunc)
{
	int id;

	for (id = 0; id < rvu->rep_cnt; id++)
		if (rvu->rep2pfvf_map[id] == pcifunc)
			return id;
	return 0;
}

static int rvu_rep_tx_vlan_cfg(struct rvu *rvu,  u16 pcifunc,
			       u16 vlan_tci, int *vidx)
{
	struct nix_vtag_config_rsp rsp = {};
	struct nix_vtag_config req = {};
	u64 etype = ETH_P_8021Q;
	int err;

	/* Insert vlan tag */
	req.hdr.pcifunc = pcifunc;
	req.vtag_size = VTAGSIZE_T4;
	req.cfg_type = 0; /* tx vlan cfg */
	req.tx.cfg_vtag0 = true;
	req.tx.vtag0 = FIELD_PREP(NIX_VLAN_ETYPE_MASK, etype) | vlan_tci;

	err = rvu_mbox_handler_nix_vtag_cfg(rvu, &req, &rsp);
	if (err) {
		dev_err(rvu->dev, "Tx vlan config failed\n");
		return err;
	}
	*vidx = rsp.vtag0_idx;
	return 0;
}

static int rvu_rep_rx_vlan_cfg(struct rvu *rvu, u16 pcifunc)
{
	struct nix_vtag_config req = {};
	struct nix_vtag_config_rsp rsp;

	/* config strip, capture and size */
	req.hdr.pcifunc = pcifunc;
	req.vtag_size = VTAGSIZE_T4;
	req.cfg_type = 1; /* rx vlan cfg */
	req.rx.vtag_type = NIX_AF_LFX_RX_VTAG_TYPE0;
	req.rx.strip_vtag = true;
	req.rx.capture_vtag = false;

	return rvu_mbox_handler_nix_vtag_cfg(rvu, &req, &rsp);
}

static int rvu_rep_install_rx_rule(struct rvu *rvu, u16 pcifunc,
				   u16 entry, bool rte)
{
	struct npc_install_flow_req req = {};
	struct npc_install_flow_rsp rsp = {};
	struct rvu_pfvf *pfvf;
	u16 vlan_tci, rep_id;

	pfvf = rvu_get_pfvf(rvu, pcifunc);

	/* To steer the traffic from Representee to Representor */
	rep_id = rvu_rep_get_vlan_id(rvu, pcifunc);
	if (rte) {
		vlan_tci = rep_id | BIT_ULL(8);
		req.vf = rvu->rep_pcifunc;
		req.op = NIX_RX_ACTIONOP_UCAST;
		req.index = rep_id;
	} else {
		vlan_tci = rep_id;
		req.vf = pcifunc;
		req.op = NIX_RX_ACTION_DEFAULT;
	}

	rvu_rep_rx_vlan_cfg(rvu, req.vf);
	req.entry = entry;
	req.hdr.pcifunc = 0; /* AF is requester */
	req.features = BIT_ULL(NPC_OUTER_VID) | BIT_ULL(NPC_VLAN_ETYPE_CTAG);
	req.vtag0_valid = true;
	req.vtag0_type = NIX_AF_LFX_RX_VTAG_TYPE0;
	req.packet.vlan_etype = cpu_to_be16(ETH_P_8021Q);
	req.mask.vlan_etype = cpu_to_be16(ETH_P_8021Q);
	req.packet.vlan_tci = cpu_to_be16(vlan_tci);
	req.mask.vlan_tci = cpu_to_be16(0xffff);

	req.channel = RVU_SWITCH_LBK_CHAN;
	req.chan_mask = 0xffff;
	req.intf = pfvf->nix_rx_intf;

	return rvu_mbox_handler_npc_install_flow(rvu, &req, &rsp);
}

static int rvu_rep_install_tx_rule(struct rvu *rvu, u16 pcifunc, u16 entry,
				   bool rte)
{
	struct npc_install_flow_req req = {};
	struct npc_install_flow_rsp rsp = {};
	struct rvu_pfvf *pfvf;
	int vidx, err;
	u16 vlan_tci;
	u8 lbkid;

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	vlan_tci = rvu_rep_get_vlan_id(rvu, pcifunc);
	if (rte)
		vlan_tci |= BIT_ULL(8);

	err = rvu_rep_tx_vlan_cfg(rvu, pcifunc, vlan_tci, &vidx);
	if (err)
		return err;

	lbkid = pfvf->nix_blkaddr == BLKADDR_NIX0 ? 0 : 1;
	req.hdr.pcifunc = 0; /* AF is requester */
	if (rte) {
		req.vf = pcifunc;
	} else {
		req.vf = rvu->rep_pcifunc;
		req.packet.sq_id = vlan_tci;
		req.mask.sq_id = 0xffff;
	}

	req.entry = entry;
	req.intf = pfvf->nix_tx_intf;
	req.op = NIX_TX_ACTIONOP_UCAST_CHAN;
	req.index = (lbkid << 8) | RVU_SWITCH_LBK_CHAN;
	req.set_cntr = 1;
	req.vtag0_def = vidx;
	req.vtag0_op = 1;
	return rvu_mbox_handler_npc_install_flow(rvu, &req, &rsp);
}

int rvu_rep_install_mcam_rules(struct rvu *rvu)
{
	struct rvu_switch *rswitch = &rvu->rswitch;
	u16 start = rswitch->start_entry;
	struct rvu_hwinfo *hw = rvu->hw;
	u16 pcifunc, entry = 0;
	struct rvu_pfvf *pfvf;
	int pf, vf, numvfs;
	int err, nixlf, i;
	u8 rep;

	for (pf = 1; pf < hw->total_pfs; pf++) {
		if (!is_pf_cgxmapped(rvu, pf))
			continue;

		pcifunc = rvu_make_pcifunc(rvu->pdev, pf, 0);
		pfvf = rvu_get_pfvf(rvu, pcifunc);
		rvu_get_nix_blkaddr(rvu, pcifunc);
		if (test_bit(NIXLF_INITIALIZED, &pfvf->flags))
			rvu_switch_enable_lbk_link(rvu, pcifunc, true);
		rep = true;
		for (i = 0; i < 2; i++) {
			err = rvu_rep_install_rx_rule(rvu, pcifunc,
						      start + entry, rep);
			if (err)
				goto err_disable_lbk;
			rswitch->entry2pcifunc[entry++] = pcifunc;

			err = rvu_rep_install_tx_rule(rvu, pcifunc,
						      start + entry, rep);
			if (err)
				goto err_disable_lbk;
			rswitch->entry2pcifunc[entry++] = pcifunc;
			rep = false;
		}

		rvu_get_pf_numvfs(rvu, pf, &numvfs, NULL);
		for (vf = 0; vf < numvfs; vf++) {
			pcifunc = rvu_make_pcifunc(rvu->pdev, pf, vf + 1);
			pfvf = rvu_get_pfvf(rvu, pcifunc);
			if (test_bit(NIXLF_INITIALIZED, &pfvf->flags))
				rvu_switch_enable_lbk_link(rvu, pcifunc, true);
			rvu_get_nix_blkaddr(rvu, pcifunc);

			/* Skip installing rules if nixlf is not attached */
			err = nix_get_nixlf(rvu, pcifunc, &nixlf, NULL);
			if (err)
				continue;
			rep = true;
			for (i = 0; i < 2; i++) {
				err = rvu_rep_install_rx_rule(rvu, pcifunc,
							      start + entry,
							      rep);
				if (err)
					goto err_disable_lbk;
				rswitch->entry2pcifunc[entry++] = pcifunc;

				err = rvu_rep_install_tx_rule(rvu, pcifunc,
							      start + entry,
							      rep);
				if (err)
					goto err_disable_lbk;
				rswitch->entry2pcifunc[entry++] = pcifunc;
				rep = false;
			}
		}
	}
	return 0;

err_disable_lbk:
	/* Undo any LBK links enabled above before the MCAM rule failure.
	 * Disabling a link that was never enabled is a safe no-op.
	 */
	for (pf = 1; pf < hw->total_pfs; pf++) {
		if (!is_pf_cgxmapped(rvu, pf))
			continue;
		pcifunc = rvu_make_pcifunc(rvu->pdev, pf, 0);
		rvu_switch_enable_lbk_link(rvu, pcifunc, false);
		rvu_get_pf_numvfs(rvu, pf, &numvfs, NULL);
		for (vf = 0; vf < numvfs; vf++) {
			pcifunc = rvu_make_pcifunc(rvu->pdev, pf, vf + 1);
			rvu_switch_enable_lbk_link(rvu, pcifunc, false);
		}
	}
	return err;
}

void rvu_rep_update_rules(struct rvu *rvu, u16 pcifunc, bool ena)
{
	struct rvu_switch *rswitch = &rvu->rswitch;
	struct npc_mcam *mcam = &rvu->hw->mcam;
	u32 max = rswitch->used_entries;
	int blkaddr;
	u16 entry;

	if (!rswitch->used_entries)
		return;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NPC, 0);

	if (blkaddr < 0)
		return;

	rvu_switch_enable_lbk_link(rvu, pcifunc, ena);
	mutex_lock(&mcam->lock);
	for (entry = 0; entry < max; entry++) {
		if (rswitch->entry2pcifunc[entry] == pcifunc)
			npc_enable_mcam_entry(rvu, mcam, blkaddr, entry, ena);
	}
	mutex_unlock(&mcam->lock);
}

int rvu_rep_pf_init(struct rvu *rvu)
{
	u16 pcifunc = rvu->rep_pcifunc;
	struct rvu_pfvf *pfvf;

	pfvf = rvu_get_pfvf(rvu, pcifunc);
	set_bit(NIXLF_INITIALIZED, &pfvf->flags);
	rvu_switch_enable_lbk_link(rvu, pcifunc, true);
	rvu_rep_rx_vlan_cfg(rvu, pcifunc);
	return 0;
}

int rvu_mbox_handler_esw_cfg(struct rvu *rvu, struct esw_cfg_req *req,
			     struct msg_rsp *rsp)
{
	if (req->hdr.pcifunc != rvu->rep_pcifunc)
		return 0;

	rvu->rep_mode = req->ena;

	if (!rvu->rep_mode)
		rvu_npc_free_mcam_entries(rvu, req->hdr.pcifunc, -1);

	return 0;
}

static int rvu_rep_get_rep_map(struct rvu *rvu, struct msg_req *req,
			       struct get_rep_cnt_rsp *rsp)
{
	int rep;

	if (req->hdr.pcifunc != rvu->rep_pcifunc)
		return -EPERM;

	rsp->rep_cnt = rvu->rep_cnt;
	for (rep = 0; rep < rvu->rep_cnt; rep++)
		rsp->rep_pf_map[rep] = rvu->rep2pfvf_map[rep];

	return 0;
}

int rvu_mbox_handler_get_rep_cnt(struct rvu *rvu, struct msg_req *req,
				 struct get_rep_cnt_rsp *rsp)
{
	int pf, vf, numvfs, hwvf, rep = 0, cnt;
	int ret = 0;
	u16 pcifunc;
	u16 *map;

	/* Serialize first-time initialization. mbox_wq is WQ_PERCPU so
	 * handlers for different PFs can run concurrently; without this
	 * lock two callers could both observe rep2pfvf_map == NULL and
	 * double-allocate the workqueue, leaking one permanently.
	 */
	mutex_lock(&rvu->rsrc_lock);

	if (rvu->rep2pfvf_map) {
		ret = rvu_rep_get_rep_map(rvu, req, rsp);
		goto unlock;
	}

	rvu->rep_pcifunc = req->hdr.pcifunc;
	cnt = min_t(int, rvu->cgx_mapped_pfs + rvu->cgx_mapped_vfs,
		    RVU_MAX_REP);

	/* Allocate at least one element so the pointer is always non-NULL
	 * once published, keeping the fast-path check above reliable.
	 */
	map = devm_kzalloc(rvu->dev, (cnt ?: 1) * sizeof(u16), GFP_KERNEL);
	if (!map) {
		ret = -ENOMEM;
		goto unlock;
	}

	for (pf = 0; pf < rvu->hw->total_pfs; pf++) {
		if (!is_pf_cgxmapped(rvu, pf))
			continue;
		if (rep >= cnt)
			break;
		pcifunc = rvu_make_pcifunc(rvu->pdev, pf, 0);
		map[rep] = pcifunc;
		rsp->rep_pf_map[rep] = pcifunc;
		rep++;
		rvu_get_pf_numvfs(rvu, pf, &numvfs, &hwvf);
		for (vf = 0; vf < numvfs && rep < cnt; vf++) {
			map[rep] = pcifunc | ((vf + 1) & RVU_PFVF_FUNC_MASK);
			rsp->rep_pf_map[rep] = map[rep];
			rep++;
		}
	}

	if (!cnt) {
		rvu->rep2pfvf_map = map;
		goto unlock;
	}

	/* Initialize the wq for handling REP events */
	spin_lock_init(&rvu->rep_evtq_lock);
	INIT_LIST_HEAD(&rvu->rep_evtq_head);
	INIT_WORK(&rvu->rep_evt_work, rvu_rep_wq_handler);
	rvu->rep_evt_wq = alloc_workqueue("rep_evt_wq", WQ_UNBOUND, 0);
	if (!rvu->rep_evt_wq) {
		dev_err(rvu->dev, "REP workqueue allocation failed\n");
		devm_kfree(rvu->dev, map);
		ret = -ENOMEM;
		goto unlock;
	}

	rvu->rep_cnt = cnt;
	rsp->rep_cnt = cnt;
	rvu->rep2pfvf_map = map;
unlock:
	mutex_unlock(&rvu->rsrc_lock);
	return ret;
}
