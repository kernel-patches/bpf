// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Ethernet driver
 *
 * Copyright (C) 2021 Marvell.
 *
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/rhashtable.h>
#include <linux/bitfield.h>
#include <net/flow_dissector.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include <net/ipv6.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>

#include "cn10k.h"
#include "otx2_common.h"
#include "qos.h"

#define CN10K_MAX_BURST_MANTISSA	0x7FFFULL
#define CN10K_MAX_BURST_SIZE		8453888ULL

#define CN10K_TLX_BURST_MANTISSA	GENMASK_ULL(43, 29)
#define CN10K_TLX_BURST_EXPONENT	GENMASK_ULL(47, 44)

#define OTX2_UNSUPP_LSE_DEPTH		GENMASK(6, 4)

#define MCAST_INVALID_GRP		(-1U)
#define RATE_MANTISSA_BITS		8
/* Min per-queue egress shaping rate the NIX TLX encoder supports (2 Mbps). */
#define OTX2_MQPRIO_MIN_RATE_BYTES_PS	250000ULL
/* Max egress shaping rate the NIX TLX encoder supports (130816 Mbps). */
#define OTX2_MQPRIO_MAX_RATE_BYTES_PS	((MAX_BURST_SIZE * 1000000ULL) / 8ULL)

static void otx2_get_egress_burst_cfg(struct otx2_nic *nic, u32 burst,
				      u32 *burst_exp, u32 *burst_mantissa)
{
	int max_burst, max_mantissa;
	unsigned int tmp;

	if (is_dev_otx2(nic->pdev)) {
		max_burst = MAX_BURST_SIZE;
		max_mantissa = MAX_BURST_MANTISSA;
	} else {
		max_burst = CN10K_MAX_BURST_SIZE;
		max_mantissa = CN10K_MAX_BURST_MANTISSA;
	}

	/* Burst is calculated as
	 * ((256 + BURST_MANTISSA) << (1 + BURST_EXPONENT)) / 256
	 * Max supported burst size is 130,816 bytes.
	 */
	burst = min_t(u32, burst, max_burst);
	if (burst) {
		*burst_exp = ilog2(burst) ? ilog2(burst) - 1 : 0;
		tmp = burst - rounddown_pow_of_two(burst);
		if (burst <= max_mantissa) {
			*burst_mantissa = tmp * 2;
		} else {
			WARN_ON(*burst_exp < 7);
			*burst_mantissa = tmp / (1ULL << (*burst_exp - 7));
		}
	} else {
		/* burst 0: largest encodable burst (CN10K_MAX_BURST_SIZE on
		 * CN10K), not a minimal burst.
		 */
		*burst_exp = MAX_BURST_EXPONENT;
		*burst_mantissa = max_mantissa;
	}
}

static void otx2_get_egress_rate_cfg(u64 maxrate, u32 *exp,
				     u32 *mantissa, u32 *div_exp)
{
	/* Rate calculation by hardware
	 *
	 * PIR_ADD = ((256 + mantissa) << exp) / 256
	 * rate = (2 * PIR_ADD) / ( 1 << div_exp)
	 * The resultant rate is in Mbps.
	 *
	 * Use div_exp = 0 and compute exp/mantissa for maxrate / 2; the
	 * leading factor of two yields the full rate. Rates below 2 Mbps
	 * are floored to the smallest step (exp = 0, mantissa = 0).
	 */

	*div_exp = 0;
	if (maxrate) {
		maxrate = maxrate / 2;
		if (!maxrate) {
			/* Rates below 2 Mbps map to the smallest step */
			*exp = 0;
			*mantissa = 0;
		} else {
			*exp = ilog2(maxrate);
			/* Clear MSB and derive fractional bits */
			maxrate &= ~BIT(*exp);
			*mantissa = (maxrate << RATE_MANTISSA_BITS) >> *exp;
		}
	} else {
		/* Instead of disabling rate limiting, set all values to max */
		*exp = MAX_RATE_EXPONENT;
		*mantissa = MAX_RATE_MANTISSA;
	}
}

u64 otx2_get_txschq_rate_regval(struct otx2_nic *nic,
				u64 maxrate, u32 burst)
{
	u32 burst_exp, burst_mantissa;
	u32 exp, mantissa, div_exp;
	u64 regval = 0;

	/* Get exponent and mantissa values from the desired rate */
	otx2_get_egress_burst_cfg(nic, burst, &burst_exp, &burst_mantissa);
	otx2_get_egress_rate_cfg(maxrate, &exp, &mantissa, &div_exp);

	if (is_dev_otx2(nic->pdev)) {
		regval = FIELD_PREP(TLX_BURST_EXPONENT, (u64)burst_exp) |
				FIELD_PREP(TLX_BURST_MANTISSA, (u64)burst_mantissa) |
				FIELD_PREP(TLX_RATE_DIVIDER_EXPONENT, div_exp) |
				FIELD_PREP(TLX_RATE_EXPONENT, exp) |
				FIELD_PREP(TLX_RATE_MANTISSA, mantissa) | BIT_ULL(0);
	} else {
		regval = FIELD_PREP(CN10K_TLX_BURST_EXPONENT, (u64)burst_exp) |
				FIELD_PREP(CN10K_TLX_BURST_MANTISSA, (u64)burst_mantissa) |
				FIELD_PREP(TLX_RATE_DIVIDER_EXPONENT, div_exp) |
				FIELD_PREP(TLX_RATE_EXPONENT, exp) |
				FIELD_PREP(TLX_RATE_MANTISSA, mantissa) | BIT_ULL(0);
	}

	return regval;
}

static int otx2_set_matchall_egress_rate(struct otx2_nic *nic,
					 u32 burst, u64 maxrate)
{
	struct otx2_hw *hw = &nic->hw;
	struct nix_txschq_config *req;
	int txschq, err;

	/* All SQs share the same TL4, so pick the first scheduler */
	txschq = hw->txschq_list[NIX_TXSCH_LVL_TL4][0];

	mutex_lock(&nic->mbox.lock);
	req = otx2_mbox_alloc_msg_nix_txschq_cfg(&nic->mbox);
	if (!req) {
		mutex_unlock(&nic->mbox.lock);
		return -ENOMEM;
	}

	req->lvl = NIX_TXSCH_LVL_TL4;
	req->num_regs = 1;
	req->reg[0] = NIX_AF_TL4X_PIR(txschq);
	req->regval[0] = otx2_get_txschq_rate_regval(nic, maxrate, burst);

	err = otx2_sync_mbox_msg(&nic->mbox);
	mutex_unlock(&nic->mbox.lock);
	return err;
}

static int otx2_tc_validate_flow(struct otx2_nic *nic,
				 struct flow_action *actions,
				 struct netlink_ext_ack *extack)
{
	if (nic->flags & OTX2_FLAG_INTF_DOWN) {
		NL_SET_ERR_MSG_MOD(extack, "Interface not initialized");
		return -EINVAL;
	}

	if (!flow_action_has_entries(actions)) {
		NL_SET_ERR_MSG_MOD(extack, "MATCHALL offload called with no action");
		return -EINVAL;
	}

	if (!flow_offload_has_one_action(actions)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Egress MATCHALL offload supports only 1 policing action");
		return -EINVAL;
	}
	return 0;
}

static int otx2_policer_validate(const struct flow_action *action,
				 const struct flow_action_entry *act,
				 struct netlink_ext_ack *extack)
{
	if (act->police.exceed.act_id != FLOW_ACTION_DROP) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Offload not supported when exceed action is not drop");
		return -EOPNOTSUPP;
	}

	if (act->police.notexceed.act_id != FLOW_ACTION_PIPE &&
	    act->police.notexceed.act_id != FLOW_ACTION_ACCEPT) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Offload not supported when conform action is not pipe or ok");
		return -EOPNOTSUPP;
	}

	if (act->police.notexceed.act_id == FLOW_ACTION_ACCEPT &&
	    !flow_action_is_last_entry(action, act)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Offload not supported when conform action is ok, but action is not last");
		return -EOPNOTSUPP;
	}

	if (act->police.peakrate_bytes_ps ||
	    act->police.avrate || act->police.overhead) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Offload not supported when peakrate/avrate/overhead is configured");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int otx2_tc_egress_matchall_install(struct otx2_nic *nic,
					   struct tc_cls_matchall_offload *cls)
{
	struct netlink_ext_ack *extack = cls->common.extack;
	struct flow_action *actions = &cls->rule->action;
	struct flow_action_entry *entry;
	int err;

	err = otx2_tc_validate_flow(nic, actions, extack);
	if (err)
		return err;

	if (nic->flags & OTX2_FLAG_TC_MATCHALL_EGRESS_ENABLED) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Only one Egress MATCHALL ratelimiter can be offloaded");
		return -ENOMEM;
	}

	entry = &cls->rule->action.entries[0];
	switch (entry->id) {
	case FLOW_ACTION_POLICE:
		err = otx2_policer_validate(&cls->rule->action, entry, extack);
		if (err)
			return err;

		if (entry->police.rate_pkt_ps) {
			NL_SET_ERR_MSG_MOD(extack, "QoS offload not support packets per second");
			return -EOPNOTSUPP;
		}
		err = otx2_set_matchall_egress_rate(nic, entry->police.burst,
						    otx2_convert_rate(entry->police.rate_bytes_ps));
		if (err)
			return err;
		nic->flags |= OTX2_FLAG_TC_MATCHALL_EGRESS_ENABLED;
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack,
				   "Only police action is supported with Egress MATCHALL offload");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int otx2_tc_egress_matchall_delete(struct otx2_nic *nic,
					  struct tc_cls_matchall_offload *cls)
{
	struct netlink_ext_ack *extack = cls->common.extack;
	int err;

	if (nic->flags & OTX2_FLAG_INTF_DOWN) {
		NL_SET_ERR_MSG_MOD(extack, "Interface not initialized");
		return -EINVAL;
	}

	err = otx2_set_matchall_egress_rate(nic, 0, 0);
	nic->flags &= ~OTX2_FLAG_TC_MATCHALL_EGRESS_ENABLED;
	return err;
}

static int otx2_tc_act_set_hw_police(struct otx2_nic *nic,
				     struct otx2_tc_flow *node)
{
	int rc;

	mutex_lock(&nic->mbox.lock);

	rc = cn10k_alloc_leaf_profile(nic, &node->leaf_profile);
	if (rc) {
		mutex_unlock(&nic->mbox.lock);
		return rc;
	}

	rc = cn10k_set_ipolicer_rate(nic, node->leaf_profile,
				     node->burst, node->rate, node->is_pps);
	if (rc)
		goto free_leaf;

	rc = cn10k_map_unmap_rq_policer(nic, node->rq, node->leaf_profile, true);
	if (rc)
		goto free_leaf;

	mutex_unlock(&nic->mbox.lock);

	return 0;

free_leaf:
	if (cn10k_free_leaf_profile(nic, node->leaf_profile))
		netdev_err(nic->netdev,
			   "Unable to free leaf bandwidth profile(%d)\n",
			   node->leaf_profile);
	mutex_unlock(&nic->mbox.lock);
	return rc;
}

static int otx2_tc_act_set_police(struct otx2_nic *nic,
				  struct otx2_tc_flow *node,
				  struct flow_cls_offload *f,
				  u64 rate, u32 burst, u32 mark,
				  struct npc_install_flow_req *req, bool pps)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct otx2_hw *hw = &nic->hw;
	int rq_idx, rc;

	rq_idx = find_first_zero_bit(&nic->rq_bmap, hw->rx_queues);
	if (rq_idx >= hw->rx_queues) {
		NL_SET_ERR_MSG_MOD(extack, "Police action rules exceeded");
		return -EINVAL;
	}

	req->match_id = mark & 0xFFFFULL;
	req->index = rq_idx;
	req->op = NIX_RX_ACTIONOP_UCAST;

	node->is_act_police = true;
	node->rq = rq_idx;
	node->burst = burst;
	node->rate = rate;
	node->is_pps = pps;

	rc = otx2_tc_act_set_hw_police(nic, node);
	if (!rc)
		set_bit(rq_idx, &nic->rq_bmap);

	return rc;
}

static int otx2_tc_update_mcast(struct otx2_nic *nic,
				struct npc_install_flow_req *req,
				struct netlink_ext_ack *extack,
				struct otx2_tc_flow *node,
				struct nix_mcast_grp_update_req *ureq,
				u8 num_intf)
{
	struct nix_mcast_grp_update_req *grp_update_req;
	struct nix_mcast_grp_create_req *creq;
	struct nix_mcast_grp_create_rsp *crsp;
	u32 grp_index;
	int rc;

	mutex_lock(&nic->mbox.lock);
	creq = otx2_mbox_alloc_msg_nix_mcast_grp_create(&nic->mbox);
	if (!creq) {
		rc = -ENOMEM;
		goto error;
	}

	creq->dir = NIX_MCAST_INGRESS;
	/* Send message to AF */
	rc = otx2_sync_mbox_msg(&nic->mbox);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to create multicast group");
		goto error;
	}

	crsp = (struct nix_mcast_grp_create_rsp *)otx2_mbox_get_rsp(&nic->mbox.mbox,
			0,
			&creq->hdr);
	if (IS_ERR(crsp)) {
		rc = PTR_ERR(crsp);
		goto error;
	}

	grp_index = crsp->mcast_grp_idx;
	grp_update_req = otx2_mbox_alloc_msg_nix_mcast_grp_update(&nic->mbox);
	if (!grp_update_req) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to update multicast group");
		rc = -ENOMEM;
		goto error;
	}

	ureq->op = NIX_MCAST_OP_ADD_ENTRY;
	ureq->mcast_grp_idx = grp_index;
	ureq->num_mce_entry = num_intf;
	ureq->pcifunc[0] = nic->pcifunc;
	ureq->channel[0] = nic->hw.tx_chan_base;

	ureq->dest_type[0] = NIX_RX_RSS;
	ureq->rq_rss_index[0] = 0;
	memcpy(&ureq->hdr, &grp_update_req->hdr, sizeof(struct mbox_msghdr));
	memcpy(grp_update_req, ureq, sizeof(struct nix_mcast_grp_update_req));

	/* Send message to AF */
	rc = otx2_sync_mbox_msg(&nic->mbox);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to update multicast group");
		goto error;
	}

	mutex_unlock(&nic->mbox.lock);
	req->op = NIX_RX_ACTIONOP_MCAST;
	req->index = grp_index;
	node->mcast_grp_idx = grp_index;
	return 0;

error:
	mutex_unlock(&nic->mbox.lock);
	return rc;
}

static int otx2_tc_parse_actions(struct otx2_nic *nic,
				 struct flow_action *flow_action,
				 struct npc_install_flow_req *req,
				 struct flow_cls_offload *f,
				 struct otx2_tc_flow *node)
{
	struct nix_mcast_grp_update_req dummy_grp_update_req = { 0 };
	struct netlink_ext_ack *extack = f->common.extack;
	bool pps = false, mcast = false;
	struct flow_action_entry *act;
	struct net_device *target;
	struct otx2_nic *priv;
	struct rep_dev *rdev;
	u32 burst, mark = 0;
	u8 nr_police = 0;
	u8 num_intf = 1;
	int err, i;
	u64 rate;

	if (!flow_action_has_entries(flow_action)) {
		NL_SET_ERR_MSG_MOD(extack, "no tc actions specified");
		return -EINVAL;
	}

	flow_action_for_each(i, act, flow_action) {
		switch (act->id) {
		case FLOW_ACTION_DROP:
			req->op = NIX_RX_ACTIONOP_DROP;
			return 0;
		case FLOW_ACTION_ACCEPT:
			req->op = NIX_RX_ACTION_DEFAULT;
			return 0;
		case FLOW_ACTION_REDIRECT_INGRESS:
			target = act->dev;
			if (target->dev.parent) {
				priv = netdev_priv(target);
				if (rvu_get_pf(nic->pdev, nic->pcifunc) !=
					rvu_get_pf(nic->pdev, priv->pcifunc)) {
					NL_SET_ERR_MSG_MOD(extack,
							   "can't redirect to other pf/vf");
					return -EOPNOTSUPP;
				}
				req->vf = priv->pcifunc & RVU_PFVF_FUNC_MASK;
			} else {
				rdev = netdev_priv(target);
				req->vf = rdev->pcifunc & RVU_PFVF_FUNC_MASK;
			}

			/* if op is already set; avoid overwriting the same */
			if (!req->op)
				req->op = NIX_RX_ACTION_DEFAULT;
			break;

		case FLOW_ACTION_VLAN_POP:
			req->vtag0_valid = true;
			/* use RX_VTAG_TYPE7 which is initialized to strip vlan tag */
			req->vtag0_type = NIX_AF_LFX_RX_VTAG_TYPE7;
			break;
		case FLOW_ACTION_POLICE:
			/* Ingress ratelimiting is not supported on OcteonTx2 */
			if (is_dev_otx2(nic->pdev)) {
				NL_SET_ERR_MSG_MOD(extack,
					"Ingress policing not supported on this platform");
				return -EOPNOTSUPP;
			}

			err = otx2_policer_validate(flow_action, act, extack);
			if (err)
				return err;

			if (act->police.rate_bytes_ps > 0) {
				rate = act->police.rate_bytes_ps * 8;
				burst = act->police.burst;
			} else if (act->police.rate_pkt_ps > 0) {
				/* The algorithm used to calculate rate
				 * mantissa, exponent values for a given token
				 * rate (token can be byte or packet) requires
				 * token rate to be mutiplied by 8.
				 */
				rate = act->police.rate_pkt_ps * 8;
				burst = act->police.burst_pkt;
				pps = true;
			}
			nr_police++;
			break;
		case FLOW_ACTION_MARK:
			if (act->mark & ~OTX2_RX_MATCH_ID_MASK) {
				NL_SET_ERR_MSG_MOD(extack, "Bad flow mark, only 16 bit supported");
				return -EOPNOTSUPP;
			}
			mark = act->mark;
			req->match_id = mark & OTX2_RX_MATCH_ID_MASK;
			req->op = NIX_RX_ACTION_DEFAULT;
			nic->flags |= OTX2_FLAG_TC_MARK_ENABLED;
			refcount_inc(&nic->flow_cfg->mark_flows);
			break;

		case FLOW_ACTION_RX_QUEUE_MAPPING:
			req->op = NIX_RX_ACTIONOP_UCAST;
			req->index = act->rx_queue;
			break;

		case FLOW_ACTION_MIRRED_INGRESS:
			target = act->dev;
			priv = netdev_priv(target);
			dummy_grp_update_req.pcifunc[num_intf] = priv->pcifunc;
			dummy_grp_update_req.channel[num_intf] = priv->hw.tx_chan_base;
			dummy_grp_update_req.dest_type[num_intf] = NIX_RX_RSS;
			dummy_grp_update_req.rq_rss_index[num_intf] = 0;
			mcast = true;
			num_intf++;
			break;

		default:
			return -EOPNOTSUPP;
		}
	}

	if (mcast) {
		err = otx2_tc_update_mcast(nic, req, extack, node,
					   &dummy_grp_update_req,
					   num_intf);
		if (err)
			return err;
	}

	if (nr_police > 1) {
		NL_SET_ERR_MSG_MOD(extack,
				   "rate limit police offload requires a single action");
		return -EOPNOTSUPP;
	}

	if (nr_police)
		return otx2_tc_act_set_police(nic, node, f, rate, burst,
					      mark, req, pps);

	return 0;
}

static int otx2_tc_process_vlan(struct otx2_nic *nic, struct flow_msg *flow_spec,
				struct flow_msg *flow_mask, struct flow_rule *rule,
				struct npc_install_flow_req *req, bool is_inner)
{
	struct flow_match_vlan match;
	u16 vlan_tci, vlan_tci_mask;

	if (is_inner)
		flow_rule_match_cvlan(rule, &match);
	else
		flow_rule_match_vlan(rule, &match);

	if (!eth_type_vlan(match.key->vlan_tpid)) {
		netdev_err(nic->netdev, "vlan tpid 0x%x not supported\n",
			   ntohs(match.key->vlan_tpid));
		return -EOPNOTSUPP;
	}

	if (!match.mask->vlan_id) {
		struct flow_action_entry *act;
		int i;

		flow_action_for_each(i, act, &rule->action) {
			if (act->id == FLOW_ACTION_DROP) {
				netdev_err(nic->netdev,
					   "vlan tpid 0x%x with vlan_id %d is not supported for DROP rule.\n",
					   ntohs(match.key->vlan_tpid), match.key->vlan_id);
				return -EOPNOTSUPP;
			}
		}
	}

	if (match.mask->vlan_id ||
	    match.mask->vlan_dei ||
	    match.mask->vlan_priority) {
		vlan_tci = match.key->vlan_id |
			   match.key->vlan_dei << 12 |
			   match.key->vlan_priority << 13;

		vlan_tci_mask = match.mask->vlan_id |
				match.mask->vlan_dei << 12 |
				match.mask->vlan_priority << 13;
		if (is_inner) {
			flow_spec->vlan_itci = htons(vlan_tci);
			flow_mask->vlan_itci = htons(vlan_tci_mask);
			req->features |= BIT_ULL(NPC_INNER_VID);
		} else {
			flow_spec->vlan_tci = htons(vlan_tci);
			flow_mask->vlan_tci = htons(vlan_tci_mask);
			req->features |= BIT_ULL(NPC_OUTER_VID);
		}
	}

	return 0;
}

static int otx2_tc_prepare_flow(struct otx2_nic *nic, struct otx2_tc_flow *node,
				struct flow_cls_offload *f,
				struct npc_install_flow_req *req)
{
	struct netlink_ext_ack *extack = f->common.extack;
	struct flow_msg *flow_spec = &req->packet;
	struct flow_msg *flow_mask = &req->mask;
	struct flow_dissector *dissector;
	struct flow_rule *rule;
	u8 ip_proto = 0;

	rule = flow_cls_offload_flow_rule(f);
	dissector = rule->match.dissector;

	if ((dissector->used_keys &
	    ~(BIT_ULL(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT(FLOW_DISSECTOR_KEY_CVLAN) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_IPSEC) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_MPLS) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_ICMP) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_TCP) |
	      BIT_ULL(FLOW_DISSECTOR_KEY_IP))))  {
		netdev_info(nic->netdev, "unsupported flow used key 0x%llx",
			    dissector->used_keys);
		return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(rule, &match);

		/* All EtherTypes can be matched, no hw limitation */
		flow_spec->etype = match.key->n_proto;
		flow_mask->etype = match.mask->n_proto;
		req->features |= BIT_ULL(NPC_ETYPE);

		if (match.mask->ip_proto &&
		    (match.key->ip_proto != IPPROTO_TCP &&
		     match.key->ip_proto != IPPROTO_UDP &&
		     match.key->ip_proto != IPPROTO_SCTP &&
		     match.key->ip_proto != IPPROTO_ICMP &&
		     match.key->ip_proto != IPPROTO_ESP &&
		     match.key->ip_proto != IPPROTO_AH &&
		     match.key->ip_proto != IPPROTO_ICMPV6)) {
			netdev_info(nic->netdev,
				    "ip_proto=0x%x not supported\n",
				    match.key->ip_proto);
			return -EOPNOTSUPP;
		}
		if (match.mask->ip_proto)
			ip_proto = match.key->ip_proto;

		if (ip_proto == IPPROTO_UDP)
			req->features |= BIT_ULL(NPC_IPPROTO_UDP);
		else if (ip_proto == IPPROTO_TCP)
			req->features |= BIT_ULL(NPC_IPPROTO_TCP);
		else if (ip_proto == IPPROTO_SCTP)
			req->features |= BIT_ULL(NPC_IPPROTO_SCTP);
		else if (ip_proto == IPPROTO_ICMP)
			req->features |= BIT_ULL(NPC_IPPROTO_ICMP);
		else if (ip_proto == IPPROTO_ICMPV6)
			req->features |= BIT_ULL(NPC_IPPROTO_ICMP6);
		else if (ip_proto == IPPROTO_ESP)
			req->features |= BIT_ULL(NPC_IPPROTO_ESP);
		else if (ip_proto == IPPROTO_AH)
			req->features |= BIT_ULL(NPC_IPPROTO_AH);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;
		u32 val;

		flow_rule_match_control(rule, &match);

		if (match.mask->flags & FLOW_DIS_IS_FRAGMENT) {
			val = match.key->flags & FLOW_DIS_IS_FRAGMENT;
			if (ntohs(flow_spec->etype) == ETH_P_IP) {
				flow_spec->ip_flag = val ? IPV4_FLAG_MORE : 0;
				flow_mask->ip_flag = IPV4_FLAG_MORE;
				req->features |= BIT_ULL(NPC_IPFRAG_IPV4);
			} else if (ntohs(flow_spec->etype) == ETH_P_IPV6) {
				flow_spec->next_header = val ?
							 IPPROTO_FRAGMENT : 0;
				flow_mask->next_header = 0xff;
				req->features |= BIT_ULL(NPC_IPFRAG_IPV6);
			} else {
				NL_SET_ERR_MSG_MOD(extack, "flow-type should be either IPv4 and IPv6");
				return -EOPNOTSUPP;
			}
		}

		if (!flow_rule_is_supp_control_flags(FLOW_DIS_IS_FRAGMENT,
						     match.mask->flags, extack))
			return -EOPNOTSUPP;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(rule, &match);
		if (!is_zero_ether_addr(match.mask->src)) {
			NL_SET_ERR_MSG_MOD(extack, "src mac match not supported");
			return -EOPNOTSUPP;
		}

		if (!is_zero_ether_addr(match.mask->dst)) {
			ether_addr_copy(flow_spec->dmac, (u8 *)&match.key->dst);
			ether_addr_copy(flow_mask->dmac,
					(u8 *)&match.mask->dst);
			req->features |= BIT_ULL(NPC_DMAC);
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPSEC)) {
		struct flow_match_ipsec match;

		flow_rule_match_ipsec(rule, &match);
		if (!match.mask->spi) {
			NL_SET_ERR_MSG_MOD(extack, "spi index not specified");
			return -EOPNOTSUPP;
		}
		if (ip_proto != IPPROTO_ESP &&
		    ip_proto != IPPROTO_AH) {
			NL_SET_ERR_MSG_MOD(extack,
					   "SPI index is valid only for ESP/AH proto");
			return -EOPNOTSUPP;
		}

		flow_spec->spi = match.key->spi;
		flow_mask->spi = match.mask->spi;
		req->features |= BIT_ULL(NPC_IPSEC_SPI);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IP)) {
		struct flow_match_ip match;

		flow_rule_match_ip(rule, &match);
		if ((ntohs(flow_spec->etype) != ETH_P_IP) &&
		    match.mask->tos) {
			NL_SET_ERR_MSG_MOD(extack, "tos not supported");
			return -EOPNOTSUPP;
		}
		if (match.mask->ttl) {
			NL_SET_ERR_MSG_MOD(extack, "ttl not supported");
			return -EOPNOTSUPP;
		}
		flow_spec->tos = match.key->tos;
		flow_mask->tos = match.mask->tos;
		req->features |= BIT_ULL(NPC_TOS);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_VLAN)) {
		int ret;

		ret = otx2_tc_process_vlan(nic, flow_spec, flow_mask, rule, req, false);
		if (ret)
			return ret;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_CVLAN)) {
		int ret;

		ret = otx2_tc_process_vlan(nic, flow_spec, flow_mask, rule, req, true);
		if (ret)
			return ret;
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS)) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(rule, &match);

		flow_spec->ip4dst = match.key->dst;
		flow_mask->ip4dst = match.mask->dst;
		req->features |= BIT_ULL(NPC_DIP_IPV4);

		flow_spec->ip4src = match.key->src;
		flow_mask->ip4src = match.mask->src;
		req->features |= BIT_ULL(NPC_SIP_IPV4);
	} else if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS)) {
		struct flow_match_ipv6_addrs match;

		flow_rule_match_ipv6_addrs(rule, &match);

		if (ipv6_addr_loopback(&match.key->dst) ||
		    ipv6_addr_loopback(&match.key->src)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Flow matching IPv6 loopback addr not supported");
			return -EOPNOTSUPP;
		}

		if (!ipv6_addr_any(&match.mask->dst)) {
			memcpy(&flow_spec->ip6dst,
			       (struct in6_addr *)&match.key->dst,
			       sizeof(flow_spec->ip6dst));
			memcpy(&flow_mask->ip6dst,
			       (struct in6_addr *)&match.mask->dst,
			       sizeof(flow_spec->ip6dst));
			req->features |= BIT_ULL(NPC_DIP_IPV6);
		}

		if (!ipv6_addr_any(&match.mask->src)) {
			memcpy(&flow_spec->ip6src,
			       (struct in6_addr *)&match.key->src,
			       sizeof(flow_spec->ip6src));
			memcpy(&flow_mask->ip6src,
			       (struct in6_addr *)&match.mask->src,
			       sizeof(flow_spec->ip6src));
			req->features |= BIT_ULL(NPC_SIP_IPV6);
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		flow_rule_match_ports(rule, &match);

		flow_spec->dport = match.key->dst;
		flow_mask->dport = match.mask->dst;

		if (flow_mask->dport) {
			if (ip_proto == IPPROTO_UDP)
				req->features |= BIT_ULL(NPC_DPORT_UDP);
			else if (ip_proto == IPPROTO_TCP)
				req->features |= BIT_ULL(NPC_DPORT_TCP);
			else if (ip_proto == IPPROTO_SCTP)
				req->features |= BIT_ULL(NPC_DPORT_SCTP);
		}

		flow_spec->sport = match.key->src;
		flow_mask->sport = match.mask->src;

		if (flow_mask->sport) {
			if (ip_proto == IPPROTO_UDP)
				req->features |= BIT_ULL(NPC_SPORT_UDP);
			else if (ip_proto == IPPROTO_TCP)
				req->features |= BIT_ULL(NPC_SPORT_TCP);
			else if (ip_proto == IPPROTO_SCTP)
				req->features |= BIT_ULL(NPC_SPORT_SCTP);
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_TCP)) {
		struct flow_match_tcp match;

		flow_rule_match_tcp(rule, &match);

		flow_spec->tcp_flags = match.key->flags;
		flow_mask->tcp_flags = match.mask->flags;
		req->features |= BIT_ULL(NPC_TCP_FLAGS);
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_MPLS)) {
		struct flow_match_mpls match;
		u8 bit;

		flow_rule_match_mpls(rule, &match);

		if (match.mask->used_lses & OTX2_UNSUPP_LSE_DEPTH) {
			NL_SET_ERR_MSG_MOD(extack,
					   "unsupported LSE depth for MPLS match offload");
			return -EOPNOTSUPP;
		}

		for_each_set_bit(bit, (unsigned long *)&match.mask->used_lses,
				 FLOW_DIS_MPLS_MAX)  {
			/* check if any of the fields LABEL,TC,BOS are set */
			if (*((u32 *)&match.mask->ls[bit]) &
			    OTX2_FLOWER_MASK_MPLS_NON_TTL) {
				/* Hardware will capture 4 byte MPLS header into
				 * two fields NPC_MPLSX_LBTCBOS and NPC_MPLSX_TTL.
				 * Derive the associated NPC key based on header
				 * index and offset.
				 */

				req->features |= BIT_ULL(NPC_MPLS1_LBTCBOS +
							 2 * bit);
				flow_spec->mpls_lse[bit] =
					FIELD_PREP(OTX2_FLOWER_MASK_MPLS_LB,
						   match.key->ls[bit].mpls_label) |
					FIELD_PREP(OTX2_FLOWER_MASK_MPLS_TC,
						   match.key->ls[bit].mpls_tc) |
					FIELD_PREP(OTX2_FLOWER_MASK_MPLS_BOS,
						   match.key->ls[bit].mpls_bos);

				flow_mask->mpls_lse[bit] =
					FIELD_PREP(OTX2_FLOWER_MASK_MPLS_LB,
						   match.mask->ls[bit].mpls_label) |
					FIELD_PREP(OTX2_FLOWER_MASK_MPLS_TC,
						   match.mask->ls[bit].mpls_tc) |
					FIELD_PREP(OTX2_FLOWER_MASK_MPLS_BOS,
						   match.mask->ls[bit].mpls_bos);
			}

			if (match.mask->ls[bit].mpls_ttl) {
				req->features |= BIT_ULL(NPC_MPLS1_TTL +
							 2 * bit);
				flow_spec->mpls_lse[bit] |=
					FIELD_PREP(OTX2_FLOWER_MASK_MPLS_TTL,
						   match.key->ls[bit].mpls_ttl);
				flow_mask->mpls_lse[bit] |=
					FIELD_PREP(OTX2_FLOWER_MASK_MPLS_TTL,
						   match.mask->ls[bit].mpls_ttl);
			}
		}
	}

	if (flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_ICMP)) {
		struct flow_match_icmp match;

		flow_rule_match_icmp(rule, &match);

		flow_spec->icmp_type = match.key->type;
		flow_mask->icmp_type = match.mask->type;
		req->features |= BIT_ULL(NPC_TYPE_ICMP);

		flow_spec->icmp_code = match.key->code;
		flow_mask->icmp_code = match.mask->code;
		req->features |= BIT_ULL(NPC_CODE_ICMP);
	}
	return otx2_tc_parse_actions(nic, &rule->action, req, f, node);
}

static void otx2_destroy_tc_flow_list(struct otx2_nic *pfvf)
{
	struct otx2_flow_config *flow_cfg = pfvf->flow_cfg;
	struct otx2_tc_flow *iter, *tmp;

	if (!(pfvf->flags & OTX2_FLAG_MCAM_ENTRIES_ALLOC))
		return;

	list_for_each_entry_safe(iter, tmp, &flow_cfg->flow_list_tc, list) {
		list_del(&iter->list);
		kfree(iter);
		flow_cfg->nr_flows--;
	}
}

static struct otx2_tc_flow *
otx2_tc_get_entry_by_cookie(struct otx2_flow_config *flow_cfg,
			    unsigned long cookie)
{
	struct otx2_tc_flow *tmp;

	list_for_each_entry(tmp, &flow_cfg->flow_list_tc, list) {
		if (tmp->cookie == cookie)
			return tmp;
	}

	return NULL;
}

struct otx2_tc_flow *
otx2_tc_get_entry_by_index(struct otx2_flow_config *flow_cfg, int index)
{
	struct otx2_tc_flow *tmp;
	int i = 0;

	list_for_each_entry(tmp, &flow_cfg->flow_list_tc, list) {
		if (i == index)
			return tmp;
		i++;
	}

	return NULL;
}

static void otx2_tc_del_from_flow_list(struct otx2_flow_config *flow_cfg,
				       struct otx2_tc_flow *node)
{
	struct list_head *pos, *n;
	struct otx2_tc_flow *tmp;

	list_for_each_safe(pos, n, &flow_cfg->flow_list_tc) {
		tmp = list_entry(pos, struct otx2_tc_flow, list);
		if (node == tmp) {
			list_del(&node->list);
			return;
		}
	}
}

int otx2_tc_add_to_flow_list(struct otx2_flow_config *flow_cfg,
			     struct otx2_tc_flow *node)
{
	struct list_head *pos, *n;
	struct otx2_tc_flow *tmp;
	int index = 0;

	/* If the flow list is empty then add the new node */
	if (list_empty(&flow_cfg->flow_list_tc)) {
		list_add(&node->list, &flow_cfg->flow_list_tc);
		return index;
	}

	list_for_each_safe(pos, n, &flow_cfg->flow_list_tc) {
		tmp = list_entry(pos, struct otx2_tc_flow, list);
		if (node->prio < tmp->prio)
			break;
		index++;
	}

	list_add(&node->list, pos->prev);
	return index;
}

int otx2_add_mcam_flow_entry(struct otx2_nic *nic,
			     struct npc_install_flow_req *req)
{
	struct npc_install_flow_req *tmp_req;
	int err;

	mutex_lock(&nic->mbox.lock);
	tmp_req = otx2_mbox_alloc_msg_npc_install_flow(&nic->mbox);
	if (!tmp_req) {
		mutex_unlock(&nic->mbox.lock);
		return -ENOMEM;
	}

	memcpy(tmp_req, req, sizeof(struct npc_install_flow_req));
	/* Send message to AF */
	err = otx2_sync_mbox_msg(&nic->mbox);
	if (err) {
		netdev_err(nic->netdev, "Failed to install MCAM flow entry %d\n",
			   req->entry);
		mutex_unlock(&nic->mbox.lock);
		return -EFAULT;
	}

	mutex_unlock(&nic->mbox.lock);
	return 0;
}

int otx2_del_mcam_flow_entry(struct otx2_nic *nic, u16 entry, u16 *cntr_val)
{
	struct npc_delete_flow_rsp *rsp;
	struct npc_delete_flow_req *req;
	int err;

	mutex_lock(&nic->mbox.lock);
	req = otx2_mbox_alloc_msg_npc_delete_flow(&nic->mbox);
	if (!req) {
		mutex_unlock(&nic->mbox.lock);
		return -ENOMEM;
	}

	req->entry = entry;

	/* Send message to AF */
	err = otx2_sync_mbox_msg(&nic->mbox);
	if (err) {
		netdev_err(nic->netdev, "Failed to delete MCAM flow entry %d\n",
			   entry);
		mutex_unlock(&nic->mbox.lock);
		return -EFAULT;
	}

	if (cntr_val) {
		rsp = (struct npc_delete_flow_rsp *)otx2_mbox_get_rsp(&nic->mbox.mbox,
								      0, &req->hdr);
		if (IS_ERR(rsp)) {
			netdev_err(nic->netdev, "Failed to get MCAM delete response for entry %d\n",
				   entry);
			mutex_unlock(&nic->mbox.lock);
			return -EFAULT;
		}

		*cntr_val = rsp->cntr_val;
	}

	mutex_unlock(&nic->mbox.lock);
	return 0;
}

static int otx2_tc_update_mcam_table_del_req(struct otx2_nic *nic,
					     struct otx2_flow_config *flow_cfg,
					     struct otx2_tc_flow *node)
{
	struct list_head *pos, *n;
	struct otx2_tc_flow *tmp;
	int i = 0, index = 0;
	u16 cntr_val = 0;

	if (is_cn20k(nic->pdev)) {
		cn20k_tc_update_mcam_table_del_req(nic, flow_cfg, node);
		return 0;
	}

	/* Find and delete the entry from the list and re-install
	 * all the entries from beginning to the index of the
	 * deleted entry to higher mcam indexes.
	 */
	list_for_each_safe(pos, n, &flow_cfg->flow_list_tc) {
		tmp = list_entry(pos, struct otx2_tc_flow, list);
		if (node == tmp) {
			list_del(&tmp->list);
			break;
		}

		otx2_del_mcam_flow_entry(nic, tmp->entry, &cntr_val);
		tmp->entry++;
		tmp->req.entry = tmp->entry;
		tmp->req.cntr_val = cntr_val;
		index++;
	}

	list_for_each_safe(pos, n, &flow_cfg->flow_list_tc) {
		if (i == index)
			break;

		tmp = list_entry(pos, struct otx2_tc_flow, list);
		otx2_add_mcam_flow_entry(nic, &tmp->req);
		i++;
	}

	return 0;
}

static int otx2_tc_update_mcam_table_add_req(struct otx2_nic *nic,
					     struct otx2_flow_config *flow_cfg,
					     struct otx2_tc_flow *node)
{
	int mcam_idx = flow_cfg->max_flows - flow_cfg->nr_flows - 1;
	struct otx2_tc_flow *tmp;
	int list_idx, i;
	u16 cntr_val = 0;

	if (is_cn20k(nic->pdev))
		return cn20k_tc_update_mcam_table_add_req(nic, flow_cfg, node);

	/* Find the index of the entry(list_idx) whose priority
	 * is greater than the new entry and re-install all
	 * the entries from beginning to list_idx to higher
	 * mcam indexes.
	 */
	list_idx = otx2_tc_add_to_flow_list(flow_cfg, node);
	for (i = 0; i < list_idx; i++) {
		tmp = otx2_tc_get_entry_by_index(flow_cfg, i);
		if (!tmp)
			return -ENOMEM;

		otx2_del_mcam_flow_entry(nic, tmp->entry, &cntr_val);
		tmp->entry = flow_cfg->flow_ent[mcam_idx];
		tmp->req.entry = tmp->entry;
		tmp->req.cntr_val = cntr_val;
		otx2_add_mcam_flow_entry(nic, &tmp->req);
		mcam_idx++;
	}

	return flow_cfg->flow_ent[mcam_idx];
}

static int otx2_tc_update_mcam_table(struct otx2_nic *nic,
				     struct otx2_flow_config *flow_cfg,
				     struct otx2_tc_flow *node,
				     bool add_req)
{
	if (add_req)
		return otx2_tc_update_mcam_table_add_req(nic, flow_cfg, node);

	return otx2_tc_update_mcam_table_del_req(nic, flow_cfg, node);
}

static int otx2_tc_del_flow(struct otx2_nic *nic,
			    struct flow_cls_offload *tc_flow_cmd)
{
	struct otx2_flow_config *flow_cfg = nic->flow_cfg;
	struct nix_mcast_grp_destroy_req *grp_destroy_req;
	struct otx2_tc_flow *flow_node;
	int err;

	flow_node = otx2_tc_get_entry_by_cookie(flow_cfg, tc_flow_cmd->cookie);
	if (!flow_node) {
		netdev_err(nic->netdev, "tc flow not found for cookie 0x%lx\n",
			   tc_flow_cmd->cookie);
		return -EINVAL;
	}

	/* Disable TC MARK flag if they are no rules with skbedit mark action */
	if (flow_node->req.match_id)
		if (!refcount_dec_and_test(&flow_cfg->mark_flows))
			nic->flags &= ~OTX2_FLAG_TC_MARK_ENABLED;

	if (flow_node->is_act_police) {
		__clear_bit(flow_node->rq, &nic->rq_bmap);

		if (nic->flags & OTX2_FLAG_INTF_DOWN)
			goto free_mcam_flow;

		mutex_lock(&nic->mbox.lock);

		err = cn10k_map_unmap_rq_policer(nic, flow_node->rq,
						 flow_node->leaf_profile, false);
		if (err)
			netdev_err(nic->netdev,
				   "Unmapping RQ %d & profile %d failed\n",
				   flow_node->rq, flow_node->leaf_profile);

		err = cn10k_free_leaf_profile(nic, flow_node->leaf_profile);
		if (err)
			netdev_err(nic->netdev,
				   "Unable to free leaf bandwidth profile(%d)\n",
				   flow_node->leaf_profile);

		mutex_unlock(&nic->mbox.lock);
	}
	/* Remove the multicast/mirror related nodes */
	if (flow_node->mcast_grp_idx != MCAST_INVALID_GRP) {
		mutex_lock(&nic->mbox.lock);
		grp_destroy_req = otx2_mbox_alloc_msg_nix_mcast_grp_destroy(&nic->mbox);
		grp_destroy_req->mcast_grp_idx = flow_node->mcast_grp_idx;
		otx2_sync_mbox_msg(&nic->mbox);
		mutex_unlock(&nic->mbox.lock);
	}

free_mcam_flow:
	otx2_del_mcam_flow_entry(nic, flow_node->entry, NULL);
	otx2_tc_update_mcam_table(nic, flow_cfg, flow_node, false);
	kfree_rcu(flow_node, rcu);
	flow_cfg->nr_flows--;
	return 0;
}

static int otx2_tc_add_flow(struct otx2_nic *nic,
			    struct flow_cls_offload *tc_flow_cmd)
{
	struct netlink_ext_ack *extack = tc_flow_cmd->common.extack;
	struct otx2_flow_config *flow_cfg = nic->flow_cfg;
	struct otx2_tc_flow *new_node, *old_node;
	struct npc_install_flow_req *req, dummy;
	int rc, err, entry;

	if (!(nic->flags & OTX2_FLAG_TC_FLOWER_SUPPORT))
		return -ENOMEM;

	if (nic->flags & OTX2_FLAG_INTF_DOWN) {
		NL_SET_ERR_MSG_MOD(extack, "Interface not initialized");
		return -EINVAL;
	}

	if (!is_cn20k(nic->pdev) && flow_cfg->nr_flows == flow_cfg->max_flows) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Free MCAM entry not available to add the flow");
		return -ENOMEM;
	}

	/* allocate memory for the new flow and it's node */
	new_node = kzalloc_obj(*new_node);
	if (!new_node)
		return -ENOMEM;
	spin_lock_init(&new_node->lock);
	new_node->cookie = tc_flow_cmd->cookie;
	new_node->prio = tc_flow_cmd->common.prio;
	new_node->mcast_grp_idx = MCAST_INVALID_GRP;

	memset(&dummy, 0, sizeof(struct npc_install_flow_req));

	rc = otx2_tc_prepare_flow(nic, new_node, tc_flow_cmd, &dummy);
	if (rc) {
		kfree_rcu(new_node, rcu);
		return rc;
	}

	/* If a flow exists with the same cookie, delete it */
	old_node = otx2_tc_get_entry_by_cookie(flow_cfg, tc_flow_cmd->cookie);
	if (old_node)
		otx2_tc_del_flow(nic, tc_flow_cmd);

	if (is_cn20k(nic->pdev)) {
		rc = cn20k_tc_alloc_entry(nic, tc_flow_cmd, new_node, &dummy);
		if (rc) {
			NL_SET_ERR_MSG_MOD(extack,
					   "MCAM rule allocation failed");
			kfree_rcu(new_node, rcu);
			return rc;
		}
	}

	entry = otx2_tc_update_mcam_table(nic, flow_cfg, new_node, true);
	if (entry < 0) {
		NL_SET_ERR_MSG_MOD(extack, "Adding rule failed");
		rc = entry;
		goto free_leaf;
	}

	mutex_lock(&nic->mbox.lock);
	req = otx2_mbox_alloc_msg_npc_install_flow(&nic->mbox);
	if (!req) {
		mutex_unlock(&nic->mbox.lock);
		rc = -ENOMEM;
		goto free_leaf;
	}

	memcpy(&dummy.hdr, &req->hdr, sizeof(struct mbox_msghdr));
	memcpy(req, &dummy, sizeof(struct npc_install_flow_req));
	req->channel = nic->hw.rx_chan_base;
	req->entry = (u16)entry;
	req->intf = NIX_INTF_RX;
	req->vf = nic->pcifunc;
	req->set_cntr = 1;
	new_node->entry = req->entry;

	/* Send message to AF */
	rc = otx2_sync_mbox_msg(&nic->mbox);
	if (rc) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to install MCAM flow entry");
		mutex_unlock(&nic->mbox.lock);
		goto free_leaf;
	}

	mutex_unlock(&nic->mbox.lock);
	memcpy(&new_node->req, req, sizeof(struct npc_install_flow_req));

	flow_cfg->nr_flows++;
	return 0;

free_leaf:
	if (is_cn20k(nic->pdev))
		cn20k_tc_free_mcam_entry(nic, new_node->entry);
	otx2_tc_del_from_flow_list(flow_cfg, new_node);
	if (new_node->is_act_police) {
		mutex_lock(&nic->mbox.lock);

		err = cn10k_map_unmap_rq_policer(nic, new_node->rq,
						 new_node->leaf_profile, false);
		if (err)
			netdev_err(nic->netdev,
				   "Unmapping RQ %d & profile %d failed\n",
				   new_node->rq, new_node->leaf_profile);
		err = cn10k_free_leaf_profile(nic, new_node->leaf_profile);
		if (err)
			netdev_err(nic->netdev,
				   "Unable to free leaf bandwidth profile(%d)\n",
				   new_node->leaf_profile);

		__clear_bit(new_node->rq, &nic->rq_bmap);

		mutex_unlock(&nic->mbox.lock);
	}
	kfree_rcu(new_node, rcu);

	return rc;
}

static int otx2_tc_get_flow_stats(struct otx2_nic *nic,
				  struct flow_cls_offload *tc_flow_cmd)
{
	struct npc_mcam_get_stats_req *req;
	struct npc_mcam_get_stats_rsp *rsp;
	struct otx2_tc_flow_stats *stats;
	struct otx2_tc_flow *flow_node;
	int err;

	flow_node = otx2_tc_get_entry_by_cookie(nic->flow_cfg, tc_flow_cmd->cookie);
	if (!flow_node) {
		netdev_info(nic->netdev, "tc flow not found for cookie %lx",
			    tc_flow_cmd->cookie);
		return -EINVAL;
	}

	mutex_lock(&nic->mbox.lock);

	req = otx2_mbox_alloc_msg_npc_mcam_entry_stats(&nic->mbox);
	if (!req) {
		mutex_unlock(&nic->mbox.lock);
		return -ENOMEM;
	}

	req->entry = flow_node->entry;

	err = otx2_sync_mbox_msg(&nic->mbox);
	if (err) {
		netdev_err(nic->netdev, "Failed to get stats for MCAM flow entry %d\n",
			   req->entry);
		mutex_unlock(&nic->mbox.lock);
		return -EFAULT;
	}

	rsp = (struct npc_mcam_get_stats_rsp *)otx2_mbox_get_rsp
		(&nic->mbox.mbox, 0, &req->hdr);
	if (IS_ERR(rsp)) {
		mutex_unlock(&nic->mbox.lock);
		return PTR_ERR(rsp);
	}

	mutex_unlock(&nic->mbox.lock);

	if (!rsp->stat_ena)
		return -EINVAL;

	stats = &flow_node->stats;

	spin_lock(&flow_node->lock);
	flow_stats_update(&tc_flow_cmd->stats, 0x0, rsp->stat - stats->pkts, 0x0, 0x0,
			  FLOW_ACTION_HW_STATS_IMMEDIATE);
	stats->pkts = rsp->stat;
	spin_unlock(&flow_node->lock);

	return 0;
}

int otx2_setup_tc_cls_flower(struct otx2_nic *nic,
			     struct flow_cls_offload *cls_flower)
{
	switch (cls_flower->command) {
	case FLOW_CLS_REPLACE:
		return otx2_tc_add_flow(nic, cls_flower);
	case FLOW_CLS_DESTROY:
		return otx2_tc_del_flow(nic, cls_flower);
	case FLOW_CLS_STATS:
		return otx2_tc_get_flow_stats(nic, cls_flower);
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(otx2_setup_tc_cls_flower);

static int otx2_tc_ingress_matchall_install(struct otx2_nic *nic,
					    struct tc_cls_matchall_offload *cls)
{
	struct netlink_ext_ack *extack = cls->common.extack;
	struct flow_action *actions = &cls->rule->action;
	struct flow_action_entry *entry;
	u64 rate;
	int err;

	err = otx2_tc_validate_flow(nic, actions, extack);
	if (err)
		return err;

	if (nic->flags & OTX2_FLAG_TC_MATCHALL_INGRESS_ENABLED) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Only one ingress MATCHALL ratelimitter can be offloaded");
		return -ENOMEM;
	}

	entry = &cls->rule->action.entries[0];
	switch (entry->id) {
	case FLOW_ACTION_POLICE:
		/* Ingress ratelimiting is not supported on OcteonTx2 */
		if (is_dev_otx2(nic->pdev)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Ingress policing not supported on this platform");
			return -EOPNOTSUPP;
		}

		err = cn10k_alloc_matchall_ipolicer(nic);
		if (err)
			return err;

		/* Convert to bits per second */
		rate = entry->police.rate_bytes_ps * 8;
		err = cn10k_set_matchall_ipolicer_rate(nic, entry->police.burst, rate);
		if (err)
			return err;
		nic->flags |= OTX2_FLAG_TC_MATCHALL_INGRESS_ENABLED;
		break;
	default:
		NL_SET_ERR_MSG_MOD(extack,
				   "Only police action supported with Ingress MATCHALL offload");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int otx2_tc_ingress_matchall_delete(struct otx2_nic *nic,
					   struct tc_cls_matchall_offload *cls)
{
	struct netlink_ext_ack *extack = cls->common.extack;
	int err;

	if (nic->flags & OTX2_FLAG_INTF_DOWN) {
		NL_SET_ERR_MSG_MOD(extack, "Interface not initialized");
		return -EINVAL;
	}

	err = cn10k_free_matchall_ipolicer(nic);
	nic->flags &= ~OTX2_FLAG_TC_MATCHALL_INGRESS_ENABLED;
	return err;
}

static int otx2_setup_tc_ingress_matchall(struct otx2_nic *nic,
					  struct tc_cls_matchall_offload *cls_matchall)
{
	switch (cls_matchall->command) {
	case TC_CLSMATCHALL_REPLACE:
		return otx2_tc_ingress_matchall_install(nic, cls_matchall);
	case TC_CLSMATCHALL_DESTROY:
		return otx2_tc_ingress_matchall_delete(nic, cls_matchall);
	case TC_CLSMATCHALL_STATS:
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static int otx2_setup_tc_block_ingress_cb(enum tc_setup_type type,
					  void *type_data, void *cb_priv)
{
	struct otx2_nic *nic = cb_priv;
	bool ntuple;

	if (!tc_cls_can_offload_and_chain0(nic->netdev, type_data))
		return -EOPNOTSUPP;

	ntuple = nic->netdev->features & NETIF_F_NTUPLE;
	switch (type) {
	case TC_SETUP_CLSFLOWER:
		if (ntuple) {
			netdev_warn(nic->netdev,
				    "Can't install TC flower offload rule when NTUPLE is active");
			return -EOPNOTSUPP;
		}

		return otx2_setup_tc_cls_flower(nic, type_data);
	case TC_SETUP_CLSMATCHALL:
		return otx2_setup_tc_ingress_matchall(nic, type_data);
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static int otx2_setup_tc_egress_matchall(struct otx2_nic *nic,
					 struct tc_cls_matchall_offload *cls_matchall)
{
	switch (cls_matchall->command) {
	case TC_CLSMATCHALL_REPLACE:
		return otx2_tc_egress_matchall_install(nic, cls_matchall);
	case TC_CLSMATCHALL_DESTROY:
		return otx2_tc_egress_matchall_delete(nic, cls_matchall);
	case TC_CLSMATCHALL_STATS:
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static int otx2_setup_tc_block_egress_cb(enum tc_setup_type type,
					 void *type_data, void *cb_priv)
{
	struct otx2_nic *nic = cb_priv;

	if (!tc_cls_can_offload_and_chain0(nic->netdev, type_data))
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_CLSMATCHALL:
		return otx2_setup_tc_egress_matchall(nic, type_data);
	default:
		break;
	}

	return -EOPNOTSUPP;
}

static LIST_HEAD(otx2_block_cb_list);

static int otx2_setup_tc_block(struct net_device *netdev,
			       struct flow_block_offload *f)
{
	struct otx2_nic *nic = netdev_priv(netdev);
	flow_setup_cb_t *cb;
	bool ingress;

	if (f->block_shared)
		return -EOPNOTSUPP;

	if (f->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS) {
		cb = otx2_setup_tc_block_ingress_cb;
		ingress = true;
	} else if (f->binder_type == FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS) {
		cb = otx2_setup_tc_block_egress_cb;
		ingress = false;
	} else {
		return -EOPNOTSUPP;
	}

	return flow_block_cb_setup_simple(f, &otx2_block_cb_list, cb,
					  nic, nic, ingress);
}

/* Free the per-queue min/max rate caches. */
static void otx2_mqprio_free_cache(struct otx2_nic *pfvf)
{
	devm_kfree(pfvf->dev, pfvf->mqprio.min_rate);
	devm_kfree(pfvf->dev, pfvf->mqprio.max_rate);
	pfvf->mqprio.min_rate = NULL;
	pfvf->mqprio.max_rate = NULL;
	pfvf->mqprio.flags = 0;
}

static int otx2_mqprio_alloc_cache(struct otx2_nic *pfvf, bool replacing)
{
	u16 num_txq = pfvf->hw.non_qos_queues;

	if (replacing && pfvf->mqprio.min_rate && pfvf->mqprio.max_rate) {
		memset(pfvf->mqprio.min_rate, 0,
		       num_txq * sizeof(*pfvf->mqprio.min_rate));
		memset(pfvf->mqprio.max_rate, 0,
		       num_txq * sizeof(*pfvf->mqprio.max_rate));
		pfvf->mqprio.flags = 0;
		return 0;
	}

	otx2_mqprio_free_cache(pfvf);

	pfvf->mqprio.min_rate = devm_kcalloc(pfvf->dev, num_txq,
					     sizeof(*pfvf->mqprio.min_rate),
					     GFP_KERNEL);
	pfvf->mqprio.max_rate = devm_kcalloc(pfvf->dev, num_txq,
					     sizeof(*pfvf->mqprio.max_rate),
					     GFP_KERNEL);
	if (!pfvf->mqprio.min_rate || !pfvf->mqprio.max_rate) {
		otx2_mqprio_free_cache(pfvf);
		return -ENOMEM;
	}

	return 0;
}

static void otx2_mqprio_snap_free(struct otx2_nic *pfvf,
				  struct mq_offload_snap **snap)
{
	if (!*snap)
		return;

	devm_kfree(pfvf->dev, *snap);
	*snap = NULL;
}

static int otx2_mqprio_snap_copy(struct otx2_nic *pfvf,
				 struct mq_offload_snap **dst,
				 const struct tc_mqprio_qopt_offload *mqprio)
{
	const struct tc_mqprio_qopt *qopt = &mqprio->qopt;
	struct mq_offload_snap *snap;
	int tc;

	if (!*dst) {
		snap = devm_kzalloc(pfvf->dev, sizeof(*snap), GFP_KERNEL);
		if (!snap)
			return -ENOMEM;
		*dst = snap;
	} else {
		snap = *dst;
	}

	snap->num_tc = qopt->num_tc;
	for (tc = 0; tc < TC_QOPT_MAX_QUEUE; tc++) {
		snap->count[tc] = qopt->count[tc];
		snap->offset[tc] = qopt->offset[tc];
		snap->min_rate[tc] = 0;
		snap->max_rate[tc] = 0;
	}

	for (tc = 0; tc < qopt->num_tc; tc++) {
		if (mqprio->flags & TC_MQPRIO_F_MIN_RATE)
			snap->min_rate[tc] = mqprio->min_rate[tc];
		if (mqprio->flags & TC_MQPRIO_F_MAX_RATE)
			snap->max_rate[tc] = mqprio->max_rate[tc];
	}

	return 0;
}

static int otx2_mqprio_stage_cur(struct otx2_nic *pfvf,
				 const struct tc_mqprio_qopt_offload *mqprio)
{
	return otx2_mqprio_snap_copy(pfvf, &pfvf->cur_mq_snap, mqprio);
}

static void otx2_mqprio_snap_commit(struct otx2_nic *pfvf)
{
	otx2_mqprio_snap_free(pfvf, &pfvf->old_mq_snap);
	pfvf->old_mq_snap = pfvf->cur_mq_snap;
	pfvf->cur_mq_snap = NULL;
}

static void otx2_mqprio_clear_replace_state(struct otx2_nic *pfvf)
{
	pfvf->mqprio.replace_setup_done = false;
	pfvf->mqprio.replace_graft_done = false;
}

static bool otx2_mqprio_mdq_allocated(struct otx2_nic *pfvf)
{
	return pfvf->hw.txschq_cnt[NIX_TXSCH_LVL_MDQ] != 0;
}

static int otx2_mqprio_restore_old(struct otx2_nic *pfvf)
{
	struct mq_offload_snap *snap = pfvf->old_mq_snap;
	struct net_device *netdev = pfvf->netdev;
	u16 num_txq = pfvf->hw.non_qos_queues;
	int tc, txq, err;

	if (!snap)
		return 0;

	err = otx2_mqprio_alloc_cache(pfvf, false);
	if (err)
		return err;

	memset(pfvf->mqprio.min_rate, 0, num_txq * sizeof(*pfvf->mqprio.min_rate));
	memset(pfvf->mqprio.max_rate, 0, num_txq * sizeof(*pfvf->mqprio.max_rate));
	pfvf->mqprio.flags = 0;

	for (tc = 0; tc < snap->num_tc; tc++) {
		u64 min_rate = snap->min_rate[tc];
		u64 max_rate = snap->max_rate[tc];

		if (min_rate)
			pfvf->mqprio.flags |= TC_MQPRIO_F_MIN_RATE;
		if (max_rate)
			pfvf->mqprio.flags |= TC_MQPRIO_F_MAX_RATE;

		for (txq = snap->offset[tc];
		     txq < snap->offset[tc] + snap->count[tc]; txq++) {
			pfvf->mqprio.min_rate[txq] = min_rate;
			pfvf->mqprio.max_rate[txq] = max_rate;
		}
	}

	netdev_set_num_tc(netdev, snap->num_tc);
	for (tc = 0; tc < snap->num_tc; tc++)
		netdev_set_tc_queue(netdev, tc, snap->count[tc],
				    snap->offset[tc]);

	if (otx2_mqprio_mdq_allocated(pfvf)) {
		err = otx2_nix_tm_clear_queue_shaper(pfvf);
		if (err)
			return err;
	}

	/* otx2_mqprio_restart_netdev() clears rate_limit when ndo_open() fails.
	 * If open failed, TX schedulers were freed; defer shaper restore to the
	 * next successful ndo_open() via otx2_mqprio_up().
	 */
	pfvf->mqprio.rate_limit = true;

	if (pfvf->hw.txschq_cnt[NIX_TXSCH_LVL_SMQ]) {
		err = otx2_mqprio_up(pfvf);
		if (err)
			return err;
	}

	otx2_mqprio_snap_free(pfvf, &pfvf->cur_mq_snap);

	return 0;
}

static void otx2_mqprio_snap_destroy(struct otx2_nic *pfvf)
{
	otx2_mqprio_snap_free(pfvf, &pfvf->cur_mq_snap);
	otx2_mqprio_snap_free(pfvf, &pfvf->old_mq_snap);
}

static void otx2_mqprio_clear_sw(struct otx2_nic *pfvf)
{
	struct net_device *netdev = pfvf->netdev;

	pfvf->mqprio.rate_limit = false;
	otx2_mqprio_clear_replace_state(pfvf);
	netdev_set_num_tc(netdev, 0);
	otx2_mqprio_free_cache(pfvf);
}

/* Tear down mqprio bandwidth offload: clear per-queue shapers,
 * mqprio_rate_limit, netdev TC mappings, and the cached rates.  Called on
 * explicit mqprio teardown (tc qdisc del) and error cleanup, not on
 * routine netdev stop/open cycles where the offload stays active.
 */
int otx2_mqprio_down(struct otx2_nic *pfvf)
{
	int err = 0;

	if (!pfvf->mqprio.rate_limit)
		return 0;

	if (netif_running(pfvf->netdev) &&
	    otx2_mqprio_mdq_allocated(pfvf))
		err = otx2_nix_tm_clear_queue_shaper(pfvf);

	otx2_mqprio_clear_sw(pfvf);

	if (err) {
		netdev_err(pfvf->netdev,
			   "mqprio: failed to clear hardware shapers: %d; some TX queues may retain bandwidth limits\n",
			   err);
	}

	return err;
}

int otx2_mqprio_up(struct otx2_nic *pfvf)
{
	struct net_device *netdev = pfvf->netdev;
	int txq, err;

	if (!pfvf->mqprio.rate_limit)
		return 0;

	if (!pfvf->mqprio.min_rate || !pfvf->mqprio.max_rate)
		return 0;

	for (txq = 0; txq < pfvf->hw.non_qos_queues; txq++) {
		u64 min_rate = 0, max_rate = 0;

		if (pfvf->mqprio.flags & TC_MQPRIO_F_MIN_RATE)
			min_rate = pfvf->mqprio.min_rate[txq];
		if (pfvf->mqprio.flags & TC_MQPRIO_F_MAX_RATE)
			max_rate = pfvf->mqprio.max_rate[txq];

		if (!min_rate && !max_rate)
			continue;

		err = otx2_nix_tm_set_queue_shaper(pfvf, txq, min_rate,
						   max_rate);
		if (err) {
			netdev_err(netdev,
				   "mqprio: failed to restore shaper for txq %d: %d\n",
				   txq, err);
			return err;
		}
	}

	return 0;
}

/* Restart the netdev to reprogram the TX scheduler hierarchy for mqprio
 * bandwidth offload.  Both mqprio add and delete (when offload was active)
 * take this path via ndo_stop()/ndo_open() so VF-specific open logic (e.g.
 * LBK carrier on) runs correctly.  The full stop/open cycle clears
 * carrier, stops all TX queues, tears down IRQs/NAPI and drops in-flight
 * traffic.  If open fails, the interface is left administratively down
 * without calling ndo_stop() again on resources already torn down by
 * the open error path.
 *
 * Do not call dev_deactivate()/dev_activate() here: this runs from
 * ndo_setup_tc() while qdisc_graft() may already hold the device
 * deactivated and must perform the final dev_activate().
 */
static int otx2_mqprio_restart_netdev(struct net_device *netdev, bool rate_limit)
{
	struct otx2_nic *pfvf = netdev_priv(netdev);
	const struct net_device_ops *ops = netdev->netdev_ops;
	int err;

	/* TODO: Explore live TX scheduler reprogramming to avoid a full
	 * ndo_stop()/ndo_open() bounce on every mqprio change.
	 */
	netdev_info(netdev,
		    "mqprio: restarting interface to reprogram TX scheduler; in-flight traffic will be dropped\n");

	err = ops->ndo_stop(netdev);
	if (err)
		return err;

	/* Set before ndo_open() so otx2_txsch_alloc() widens SMQ allocation.
	 * On teardown, drop mqprio software state so ndo_open() does not
	 * re-apply bandwidth limits via otx2_mqprio_up() after the kernel
	 * removed the qdisc.
	 */
	if (rate_limit)
		pfvf->mqprio.rate_limit = true;
	else
		otx2_mqprio_clear_sw(pfvf);

	err = ops->ndo_open(netdev);
	if (err) {
		netdev_err(netdev,
			   "Failed to restart device after mqprio change: %d\n",
			   err);
		/* ndo_open() already freed the TX schedulers on failure while
		 * netif_running() may still be true; drop mqprio software state
		 * only instead of sending shaper clears to freed queues.
		 */
		otx2_mqprio_clear_sw(pfvf);
		/* ndo_open() rolls back on failure; mark the interface down so
		 * netif_close() does not invoke ndo_stop() on freed NAPI/queue
		 * state. Caller holds RTNL; dev_close() would deadlock.
		 */
		pfvf->flags |= OTX2_FLAG_INTF_DOWN;
		/* visible to otx2_stop() on other cpus */
		smp_wmb();
		netif_close(netdev);
	}

	return err;
}

static int otx2_mqprio_validate_tc_rate(struct net_device *netdev,
					struct netlink_ext_ack *extack,
					u64 rate, u32 qcount, int tc,
					const char *name)
{
	if (!rate)
		return 0;

	if (qcount <= 1)
		return 0;

	/* TODO: mqprio min_rate/max_rate are per traffic class, but bandwidth
	 * offload shapes on per-queue MDQ nodes parented under a single TL4.
	 * Without per-TC TL4 shapers the driver cannot honor TC-level limits
	 * for a traffic class that spans multiple queues without either
	 * dividing the rate across queues (uAPI mismatch) or exceeding the TC
	 * cap when every member queue is active. Reject until per-TC TL4
	 * shaping can be implemented without allocating additional TL4 nodes
	 * beyond the existing hierarchy.
	 */
	netdev_err(netdev,
		   "mqprio: %s rate for tc %d not supported with %u queues\n",
		   name, tc, qcount);
	NL_SET_ERR_MSG_FMT_MOD(extack,
			       "mqprio: %s rate for tc %d not supported with %u queues",
			       name, tc, qcount);
	return -EOPNOTSUPP;
}

static int otx2_mqprio_validate_txqs(struct net_device *netdev,
				     struct netlink_ext_ack *extack,
				     struct tc_mqprio_qopt *qopt)
{
	struct otx2_nic *pfvf = netdev_priv(netdev);
	u16 num_txq = pfvf->hw.non_qos_queues;
	int tc, txq;

	if (qopt->num_tc > num_txq) {
		netdev_err(netdev, "Number of TCs (%u) exceeds hw queues %u\n",
			   qopt->num_tc, num_txq);
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "Number of TCs (%u) exceeds hw queues %u",
				       qopt->num_tc, num_txq);
		return -EINVAL;
	}

	if (num_txq > MAX_TXSCHQ_PER_FUNC) {
		netdev_err(netdev,
			   "Number of queues (%u) exceeds max scheduler queues %u\n",
			   num_txq, MAX_TXSCHQ_PER_FUNC);
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "Number of queues (%u) exceeds max scheduler queues %u",
				       num_txq, MAX_TXSCHQ_PER_FUNC);
		return -EINVAL;
	}

	for (tc = 0; tc < qopt->num_tc; tc++) {
		u32 qcount = qopt->count[tc];

		for (txq = qopt->offset[tc];
		     txq < qopt->offset[tc] + qcount; txq++) {
			if (txq >= num_txq) {
				netdev_err(netdev,
					   "mqprio: txq %d exceeds offload queue count %u\n",
					   txq, num_txq);
				NL_SET_ERR_MSG_FMT_MOD(extack,
						       "mqprio: txq %d exceeds offload queue count %u",
						       txq, num_txq);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static bool otx2_mqprio_rate_valid(u64 rate_bytes_ps)
{
	u64 mbps;

	if (!rate_bytes_ps)
		return true;

	if (rate_bytes_ps < OTX2_MQPRIO_MIN_RATE_BYTES_PS)
		return false;

	if (rate_bytes_ps > OTX2_MQPRIO_MAX_RATE_BYTES_PS)
		return false;

	if (rate_bytes_ps > div_u64(U64_MAX, 8))
		return false;

	mbps = otx2_convert_rate(rate_bytes_ps);
	return ilog2(mbps / 2) <= MAX_RATE_EXPONENT;
}

static int otx2_teardown_tc_mqprio(struct otx2_nic *pfvf,
				   struct tc_mqprio_qopt_offload *mqprio)
{
	struct tc_mqprio_qopt *qopt = &mqprio->qopt;
	bool had_mqprio = pfvf->mqprio.rate_limit;
	struct net_device *netdev = pfvf->netdev;
	bool if_up = netif_running(netdev);
	int err;

	qopt->hw = 0;

	/* tc qdisc replace runs setup on the new mqprio before destroying the
	 * old one. replace_setup_done and TC_ROOT_GRAFT distinguish stale
	 * old-instance teardown from graft failure after setup.
	 */
	if (pfvf->mqprio.replace_setup_done && pfvf->cur_mq_snap) {
		err = 0;
		if (pfvf->mqprio.replace_graft_done)
			otx2_mqprio_snap_commit(pfvf);
		else
			err = otx2_mqprio_restore_old(pfvf);
		otx2_mqprio_clear_replace_state(pfvf);
		return err;
	}

	/* Skip the netdev restart when mqprio offload was not active. */
	if (!had_mqprio)
		return 0;

	if (if_up) {
		int down_err, err;

		down_err = otx2_mqprio_down(pfvf);
		err = otx2_mqprio_restart_netdev(netdev, false);
		if (err)
			return err;
		return down_err;
	}

	/* ndo_stop() already freed the TX scheduler TL nodes; drop software
	 * state only.
	 */
	otx2_mqprio_clear_sw(pfvf);
	return 0;
}

static int otx2_setup_tc_mqprio(struct net_device *netdev,
				struct tc_mqprio_qopt_offload *mqprio)
{
	struct netlink_ext_ack *extack = mqprio->extack;
	struct otx2_nic *pfvf = netdev_priv(netdev);
	struct tc_mqprio_qopt *qopt = &mqprio->qopt;
	bool replacing = pfvf->mqprio.rate_limit;
	bool if_up = netif_running(netdev);
	int tc, txq, err, i;

	if (!qopt->hw)
		return otx2_teardown_tc_mqprio(pfvf, mqprio);

	if (!if_up) {
		netdev_err(netdev, "mqprio: setup requires interface UP\n");
		NL_SET_ERR_MSG_MOD(extack, "mqprio: setup requires interface UP");
		return -EOPNOTSUPP;
	}

	if (mqprio->shaper != TC_MQPRIO_SHAPER_BW_RATE) {
		netdev_err(netdev, "Unsupported mqprio shaper %#x\n", mqprio->shaper);
		NL_SET_ERR_MSG_FMT_MOD(extack, "Unsupported mqprio shaper %#x",
				       mqprio->shaper);
		return -EOPNOTSUPP;
	}

	if (!test_bit(QOS_CIR_PIR_SUPPORT, &pfvf->hw.cap_flag)) {
		netdev_err(netdev,
			   "mqprio: bandwidth offload requires CIR+PIR support\n");
		NL_SET_ERR_MSG_MOD(extack,
				   "mqprio: bandwidth offload requires CIR+PIR support");
		return -EOPNOTSUPP;
	}

	if (is_otx2_sdp_rep(pfvf->pdev)) {
		netdev_err(netdev, "mqprio: bandwidth offload not supported on SDP rep\n");
		NL_SET_ERR_MSG_MOD(extack,
				   "mqprio: bandwidth offload not supported on SDP rep");
		return -EOPNOTSUPP;
	}

	if (pfvf->pfc_en) {
		netdev_err(netdev,
			   "mqprio: cannot enable offload while PFC is enabled\n");
		NL_SET_ERR_MSG_MOD(extack,
				   "mqprio: cannot enable offload while PFC is enabled");
		return -EOPNOTSUPP;
	}

	if (pfvf->xdp_prog) {
		netdev_err(netdev,
			   "mqprio: cannot enable offload while XDP is active\n");
		NL_SET_ERR_MSG_MOD(extack,
				   "mqprio: cannot enable offload while XDP is active");
		return -EOPNOTSUPP;
	}

	for (tc = 0; tc < qopt->num_tc; tc++) {
		u64 min_rate = 0, max_rate = 0;
		u32 qcount = qopt->count[tc];

		if (mqprio->flags & TC_MQPRIO_F_MIN_RATE)
			min_rate = mqprio->min_rate[tc];
		if (mqprio->flags & TC_MQPRIO_F_MAX_RATE)
			max_rate = mqprio->max_rate[tc];

		if (min_rate && max_rate && min_rate > max_rate) {
			netdev_err(netdev,
				   "min_rate %llu exceeds max_rate %llu for tc %d\n",
				   min_rate, max_rate, tc);
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "min_rate %llu exceeds max_rate %llu for tc %d",
					       min_rate, max_rate, tc);
			return -EINVAL;
		}

		if (mqprio->flags & TC_MQPRIO_F_MIN_RATE) {
			err = otx2_mqprio_validate_tc_rate(netdev, extack, min_rate,
							   qcount, tc, "min");
			if (err)
				return err;
		}

		if (mqprio->flags & TC_MQPRIO_F_MAX_RATE) {
			err = otx2_mqprio_validate_tc_rate(netdev, extack, max_rate,
							   qcount, tc, "max");
			if (err)
				return err;
		}

		if (mqprio->flags & TC_MQPRIO_F_MIN_RATE &&
		    !otx2_mqprio_rate_valid(min_rate)) {
			netdev_err(netdev,
				   "mqprio: min_rate %llu for tc %d is outside hardware limits\n",
				   min_rate, tc);
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "mqprio: min_rate %llu for tc %d is outside hardware limits",
					       min_rate, tc);
			return -EINVAL;
		}

		if (mqprio->flags & TC_MQPRIO_F_MAX_RATE &&
		    !otx2_mqprio_rate_valid(max_rate)) {
			netdev_err(netdev,
				   "mqprio: max_rate %llu for tc %d is outside hardware limits\n",
				   max_rate, tc);
			NL_SET_ERR_MSG_FMT_MOD(extack,
					       "mqprio: max_rate %llu for tc %d is outside hardware limits",
					       max_rate, tc);
			return -EINVAL;
		}
	}

	err = otx2_mqprio_validate_txqs(netdev, extack, qopt);
	if (err)
		return err;

	err = otx2_mqprio_stage_cur(pfvf, mqprio);
	if (err)
		return err;

	err = otx2_mqprio_restart_netdev(pfvf->netdev, true);
	if (err)
		goto cleanup;

	err = otx2_mqprio_alloc_cache(pfvf, replacing);
	if (err)
		goto cleanup;

	/* otx2_mqprio_up() may have restored the previous configuration during
	 * the restart above. Clear every MDQ shaper before applying the new
	 * mapping so queues dropped from the TC layout do not keep stale
	 * limits in hardware.
	 */
	if (otx2_mqprio_mdq_allocated(pfvf)) {
		err = otx2_nix_tm_clear_queue_shaper(pfvf);
		if (err)
			goto cleanup;
	}

	pfvf->mqprio.flags = mqprio->flags;

	for (tc = 0; tc < qopt->num_tc; tc++) {
		u64 min_rate = 0, max_rate = 0;
		u32 qcount = qopt->count[tc];

		/* Rates omitted from tc mqprio are passed as zero and both MDQ
		 * shaper registers are programmed; see
		 * otx2_nix_tm_set_queue_shaper(). Multi-queue TCs with rates
		 * are rejected above.
		 */
		if (mqprio->flags & TC_MQPRIO_F_MIN_RATE)
			min_rate = mqprio->min_rate[tc];
		if (mqprio->flags & TC_MQPRIO_F_MAX_RATE)
			max_rate = mqprio->max_rate[tc];

		for (txq = qopt->offset[tc];
		     txq < qopt->offset[tc] + qcount; txq++) {
			netdev_dbg(netdev,
				   "mqprio: tc %d txq %d min_rate %llu max_rate %llu\n",
				   tc, txq, min_rate, max_rate);

			pfvf->mqprio.min_rate[txq] = min_rate;
			pfvf->mqprio.max_rate[txq] = max_rate;

			err = otx2_nix_tm_set_queue_shaper(pfvf, txq,
							   min_rate, max_rate);
			if (err)
				goto cleanup;
		}
	}

	netdev_set_num_tc(netdev, pfvf->cur_mq_snap->num_tc);
	for (i = 0; i < pfvf->cur_mq_snap->num_tc; i++)
		netdev_set_tc_queue(netdev, i, pfvf->cur_mq_snap->count[i],
				    qopt->offset[i]);

	qopt->hw = TC_MQPRIO_HW_OFFLOAD_TCS;

	if (replacing) {
		pfvf->mqprio.replace_setup_done = true;
		pfvf->mqprio.replace_graft_done = false;
	} else {
		otx2_mqprio_snap_commit(pfvf);
	}

	return 0;

cleanup:
	qopt->hw = 0;
	if (replacing) {
		int restore_err = otx2_mqprio_restore_old(pfvf);

		otx2_mqprio_clear_replace_state(pfvf);
		if (restore_err) {
			netdev_err(netdev,
				   "mqprio: replace failed and prior configuration rollback failed: %d\n",
				   restore_err);
			if (extack)
				NL_SET_ERR_MSG_FMT_MOD(extack,
						       "mqprio: replace failed and prior configuration rollback failed: %d",
						       restore_err);
		} else {
			netdev_err(netdev,
				   "mqprio: replace failed; prior configuration restored\n");
			if (extack)
				NL_SET_ERR_MSG_MOD(extack,
						   "mqprio: replace failed; prior configuration restored");
		}
		return err ? err : -EIO;
	}
	otx2_teardown_tc_mqprio(pfvf, mqprio);
	return err;
}

static int otx2_setup_tc_root(struct otx2_nic *pfvf,
			      struct tc_root_qopt_offload *root)
{
	switch (root->command) {
	case TC_ROOT_GRAFT:
		if (pfvf->mqprio.replace_setup_done)
			pfvf->mqprio.replace_graft_done = true;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int otx2_setup_tc_query_caps(void *type_data)
{
	struct tc_query_caps_base *base = type_data;
	struct tc_mqprio_caps *caps;

	if (base->type != TC_SETUP_QDISC_MQPRIO)
		return -EOPNOTSUPP;

	caps = base->caps;
	caps->validate_queue_counts = true;

	return 0;
}

int otx2_setup_tc(struct net_device *netdev, enum tc_setup_type type,
		  void *type_data)
{
	switch (type) {
	case TC_QUERY_CAPS:
		return otx2_setup_tc_query_caps(type_data);
	case TC_SETUP_BLOCK:
		return otx2_setup_tc_block(netdev, type_data);
	case TC_SETUP_QDISC_HTB:
		return otx2_setup_tc_htb(netdev, type_data);
	case TC_SETUP_QDISC_MQPRIO:
		return otx2_setup_tc_mqprio(netdev, type_data);
	case TC_SETUP_ROOT_QDISC:
		return otx2_setup_tc_root(netdev_priv(netdev), type_data);
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(otx2_setup_tc);

int otx2_init_tc(struct otx2_nic *nic)
{
	/* Exclude receive queue 0 being used for police action */
	set_bit(0, &nic->rq_bmap);

	if (!nic->flow_cfg) {
		netdev_err(nic->netdev,
			   "Can't init TC, nic->flow_cfg is not setup\n");
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL(otx2_init_tc);

void otx2_shutdown_tc(struct otx2_nic *nic)
{
	otx2_destroy_tc_flow_list(nic);
	otx2_mqprio_snap_destroy(nic);
}
EXPORT_SYMBOL(otx2_shutdown_tc);

static void otx2_tc_config_ingress_rule(struct otx2_nic *nic,
					struct otx2_tc_flow *node)
{
	struct npc_install_flow_req *req;

	if (otx2_tc_act_set_hw_police(nic, node))
		return;

	mutex_lock(&nic->mbox.lock);

	req = otx2_mbox_alloc_msg_npc_install_flow(&nic->mbox);
	if (!req)
		goto err;

	memcpy(req, &node->req, sizeof(struct npc_install_flow_req));

	if (otx2_sync_mbox_msg(&nic->mbox))
		netdev_err(nic->netdev,
			   "Failed to install MCAM flow entry for ingress rule");
err:
	mutex_unlock(&nic->mbox.lock);
}

void otx2_tc_apply_ingress_police_rules(struct otx2_nic *nic)
{
	struct otx2_flow_config *flow_cfg = nic->flow_cfg;
	struct otx2_tc_flow *node;

	/* If any ingress policer rules exist for the interface then
	 * apply those rules. Ingress policer rules depend on bandwidth
	 * profiles linked to the receive queues. Since no receive queues
	 * exist when interface is down, ingress policer rules are stored
	 * and configured in hardware after all receive queues are allocated
	 * in otx2_open.
	 */
	list_for_each_entry(node, &flow_cfg->flow_list_tc, list) {
		if (node->is_act_police)
			otx2_tc_config_ingress_rule(nic, node);
	}
}
EXPORT_SYMBOL(otx2_tc_apply_ingress_police_rules);
