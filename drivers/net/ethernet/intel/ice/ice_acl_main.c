// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2026, Intel Corporation. */

#include "ice.h"
#include "ice_lib.h"
#include "ice_acl_main.h"

/* Default ACL Action priority */
#define ICE_ACL_ACT_PRIO	3

/* Number of action */
#define ICE_ACL_NUM_ACT		1

/**
 * ice_acl_set_ip4_addr_seg - set flow segment IPv4 addresses masks
 * @seg: flow segment for programming
 */
static void ice_acl_set_ip4_addr_seg(struct ice_flow_seg_info *seg)
{
	u16 val_loc, mask_loc;

	/* IP source address */
	val_loc = offsetof(struct ice_ntuple_fltr, ip.v4.src_ip);
	mask_loc = offsetof(struct ice_ntuple_fltr, mask.v4.src_ip);

	ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_SA, val_loc,
			 mask_loc, ICE_FLOW_FLD_OFF_INVAL, false);

	/* IP destination address */
	val_loc = offsetof(struct ice_ntuple_fltr, ip.v4.dst_ip);
	mask_loc = offsetof(struct ice_ntuple_fltr, mask.v4.dst_ip);

	ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_DA, val_loc,
			 mask_loc, ICE_FLOW_FLD_OFF_INVAL, false);
}

/**
 * ice_acl_set_ip4_port_seg - set flow segment port masks based on L4 port
 * @seg: flow segment for programming
 * @l4_proto: Layer 4 protocol to program
 *
 * Return: 0 on success, negative on error
 */
static int ice_acl_set_ip4_port_seg(struct ice_flow_seg_info *seg,
				    enum ice_flow_seg_hdr l4_proto)
{
	enum ice_flow_field src_port, dst_port;
	u16 val_loc, mask_loc;
	int err;

	err = ice_ntuple_l4_proto_to_port(l4_proto, &src_port, &dst_port);
	if (err)
		return err;

	/* Layer 4 source port */
	val_loc = offsetof(struct ice_ntuple_fltr, ip.v4.src_port);
	mask_loc = offsetof(struct ice_ntuple_fltr, mask.v4.src_port);

	ice_flow_set_fld(seg, src_port, val_loc, mask_loc,
			 ICE_FLOW_FLD_OFF_INVAL, false);

	/* Layer 4 destination port */
	val_loc = offsetof(struct ice_ntuple_fltr, ip.v4.dst_port);
	mask_loc = offsetof(struct ice_ntuple_fltr, mask.v4.dst_port);

	ice_flow_set_fld(seg, dst_port, val_loc, mask_loc,
			 ICE_FLOW_FLD_OFF_INVAL, false);

	return 0;
}

/**
 * ice_acl_set_ip4_seg - set flow segment IPv4 and L4 masks
 * @seg: flow segment for programming
 * @tcp_ip4_spec: mask data from ethtool
 * @l4_proto: Layer 4 protocol to program
 *
 * Set the mask data into the flow segment to be used to program HW
 * table based on provided L4 protocol for IPv4
 *
 * Return: 0 on success, negative on error
 */
static int ice_acl_set_ip4_seg(struct ice_flow_seg_info *seg,
			       struct ethtool_tcpip4_spec *tcp_ip4_spec,
			       enum ice_flow_seg_hdr l4_proto)
{
	int err;

	err = ice_ntuple_check_ip4_seg(tcp_ip4_spec);
	if (err)
		return err;

	ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV4 | l4_proto);
	ice_acl_set_ip4_addr_seg(seg);

	return ice_acl_set_ip4_port_seg(seg, l4_proto);
}

/**
 * ice_acl_set_ip4_usr_seg - set flow segment IPv4 masks
 * @seg: flow segment for programming
 * @usr_ip4_spec: ethtool userdef packet offset
 *
 * Set the offset data into the flow segment to be used to program HW
 * table for IPv4
 *
 * Return: 0 on success, negative on error
 */
static int ice_acl_set_ip4_usr_seg(struct ice_flow_seg_info *seg,
				   struct ethtool_usrip4_spec *usr_ip4_spec)
{
	int err;

	err = ice_ntuple_check_ip4_usr_seg(usr_ip4_spec);
	if (err)
		return err;

	ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV4);
	ice_acl_set_ip4_addr_seg(seg);

	return 0;
}

/**
 * ice_acl_prof_add_ethtool - Check ethtool input set and add ACL profile
 * @pf: ice PF structure
 * @fsp: pointer to ethtool Rx flow specification
 *
 * Return: 0 on success and negative values for failure
 */
static int ice_acl_prof_add_ethtool(struct ice_pf *pf,
				    struct ethtool_rx_flow_spec *fsp)
{
	struct ice_flow_prof *prof = NULL;
	struct ice_acl_hw_prof *hw_prof;
	struct ice_flow_seg_info *seg;
	enum ice_fltr_ptype fltr_type;
	struct ice_hw *hw = &pf->hw;
	int err;

	seg = kzalloc_obj(*seg);
	if (!seg)
		return -ENOMEM;

	switch (fsp->flow_type & ~FLOW_EXT) {
	case TCP_V4_FLOW:
		err = ice_acl_set_ip4_seg(seg, &fsp->m_u.tcp_ip4_spec,
					  ICE_FLOW_SEG_HDR_TCP);
		break;
	case UDP_V4_FLOW:
		err = ice_acl_set_ip4_seg(seg, &fsp->m_u.tcp_ip4_spec,
					  ICE_FLOW_SEG_HDR_UDP);
		break;
	case SCTP_V4_FLOW:
		err = ice_acl_set_ip4_seg(seg, &fsp->m_u.tcp_ip4_spec,
					  ICE_FLOW_SEG_HDR_SCTP);
		break;
	case IPV4_USER_FLOW:
		err = ice_acl_set_ip4_usr_seg(seg, &fsp->m_u.usr_ip4_spec);
		break;
	default:
		err = -EOPNOTSUPP;
	}
	if (err)
		goto free_seg;

	fltr_type = ice_ethtool_flow_to_fltr(fsp->flow_type & ~FLOW_EXT);

	hw_prof = hw->acl_prof[fltr_type];
	if (!hw_prof) {
		hw_prof = kzalloc_obj(**hw->acl_prof);
		if (!hw_prof) {
			err = -ENOMEM;
			goto free_seg;
		}
	}

	if (hw_prof->seg) {
		/* This flow_type already has an input set.
		 * If it matches the requested input set then we are
		 * done. If it's different then it's an error.
		 */
		if (!memcmp(hw_prof->seg, seg, sizeof(*seg))) {
			kfree(seg);
			return 0;
		}

		err = -EINVAL;
		goto free_seg;
	}

	/* Adding a profile for the given flow specification with no
	 * actions (NULL) and zero actions 0.
	 */
	err = ice_flow_add_prof(hw, ICE_BLK_ACL, ICE_FLOW_RX, seg, 1, false,
				&prof);
	if (err)
		goto free_acl_prof;

	hw_prof->seg = seg;
	hw_prof->prof_id = prof->id;
	hw->acl_prof[fltr_type] = hw_prof;
	return 0;

free_acl_prof:
	kfree(hw_prof);
free_seg:
	kfree(seg);

	return err;
}

/**
 * ice_acl_set_act_drop - setup drop action
 * @action: pointer to action
 */
static void ice_acl_set_act_drop(struct ice_flow_action *action)
{
	action->type = ICE_FLOW_ACT_DROP;
	action->data.acl_act.mdid = ICE_MDID_RX_PKT_DROP;
	action->data.acl_act.prio = ICE_ACL_ACT_PRIO;
	action->data.acl_act.value = cpu_to_le16(ICE_RX_PKT_DROP_DROP);
}

/**
 * ice_acl_set_act_fwd_queue - setup forward to queue action
 * @action: pointer to action
 * @queue_index: queue index
 */
static void ice_acl_set_act_fwd_queue(struct ice_flow_action *action,
				      s16 queue_index)
{
	action->type = ICE_FLOW_ACT_FWD_QUEUE;
	action->data.acl_act.mdid = ICE_MDID_RX_DST_Q;
	action->data.acl_act.prio = ICE_ACL_ACT_PRIO;
	action->data.acl_act.value = cpu_to_le16(queue_index);
}

/**
 * ice_acl_comp_rules - compare two ACL filters
 * @a: first ACL filter
 * @b: second ACL filter
 *
 * Return: true if a and b values and masks are identical, false otherwise
 */
static bool
ice_acl_comp_rules(struct ice_ntuple_fltr *a, struct ice_ntuple_fltr *b)
{
	bool base_equal;

	if (a->flow_type != b->flow_type)
		return false;

	base_equal = a->ip.v4.dst_ip == b->ip.v4.dst_ip &&
		     a->ip.v4.src_ip == b->ip.v4.src_ip &&
		     a->mask.v4.dst_ip == b->mask.v4.dst_ip &&
		     a->mask.v4.src_ip == b->mask.v4.src_ip;

	switch (a->flow_type) {
	case ICE_FLTR_PTYPE_NONF_IPV4_TCP:
	case ICE_FLTR_PTYPE_NONF_IPV4_UDP:
	case ICE_FLTR_PTYPE_NONF_IPV4_SCTP:
		return base_equal &&
		       a->ip.v4.dst_port == b->ip.v4.dst_port &&
		       a->ip.v4.src_port == b->ip.v4.src_port &&
		       a->mask.v4.dst_port == b->mask.v4.dst_port &&
		       a->mask.v4.src_port == b->mask.v4.src_port;
	case ICE_FLTR_PTYPE_NONF_IPV4_OTHER:
		return base_equal &&
		       a->ip.v4.l4_header == b->ip.v4.l4_header &&
		       a->ip.v4.proto == b->ip.v4.proto &&
		       a->ip.v4.ip_ver == b->ip.v4.ip_ver &&
		       a->ip.v4.tos == b->ip.v4.tos &&
		       a->mask.v4.l4_header == b->mask.v4.l4_header &&
		       a->mask.v4.proto == b->mask.v4.proto &&
		       a->mask.v4.ip_ver == b->mask.v4.ip_ver &&
		       a->mask.v4.tos == b->mask.v4.tos;
	default:
		return false;
	}
}

/**
 * ice_acl_is_dup_fltr - test if an ACL filter is already in the list
 * @hw: hardware data structure
 * @input: ACL filter to check
 *
 * Return: true if a filter with identical match criteria (same flow type,
 * values, and masks) already exists, unless it is at the same location with a
 * different queue (an update)
 */
static bool
ice_acl_is_dup_fltr(struct ice_hw *hw, struct ice_ntuple_fltr *input)
{
	struct ice_ntuple_fltr *rule;

	list_for_each_entry(rule, &hw->fdir_list_head, fltr_node) {
		if (!rule->acl_fltr)
			continue;

		if (!ice_acl_comp_rules(rule, input))
			continue;

		/* At this point rule and input have same match criteria.
		 * Same location with a different queue is an update, not a
		 * duplicate - skip it. Everything else is a duplicate.
		 */
		if (rule->fltr_id == input->fltr_id &&
		    rule->q_index != input->q_index)
			continue;

		return true;
	}

	return false;
}

/**
 * ice_acl_add_rule_ethtool - add an ACL rule
 * @vsi: pointer to target VSI
 * @cmd: command to add or delete ACL rule
 *
 * Return: 0 on success and negative values for failure
 */
int ice_acl_add_rule_ethtool(struct ice_vsi *vsi, struct ethtool_rxnfc *cmd)
{
	struct ice_flow_action acts[ICE_ACL_NUM_ACT];
	struct ethtool_rx_flow_spec *fsp;
	struct ice_acl_hw_prof *hw_prof;
	struct ice_ntuple_fltr *input;
	enum ice_fltr_ptype flow;
	struct device *dev;
	struct ice_pf *pf;
	struct ice_hw *hw;
	u64 entry_h = 0;
	int err;

	pf = vsi->back;
	hw = &pf->hw;
	dev = ice_pf_to_dev(pf);

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	err = ice_acl_prof_add_ethtool(pf, fsp);
	if (err)
		return err;

	/* Add new rule */
	input = kzalloc_obj(*input);
	if (!input)
		return -ENOMEM;

	err = ice_ntuple_set_input_set(vsi, ICE_BLK_ACL, fsp, input);
	if (err)
		goto free_input;

	mutex_lock(&hw->fdir_fltr_lock);
	if (ice_acl_is_dup_fltr(hw, input)) {
		mutex_unlock(&hw->fdir_fltr_lock);
		err = -EINVAL;
		goto free_input;
	}
	mutex_unlock(&hw->fdir_fltr_lock);

	memset(&acts, 0, sizeof(acts));
	if (fsp->ring_cookie == RX_CLS_FLOW_DISC)
		ice_acl_set_act_drop(&acts[0]);
	else
		ice_acl_set_act_fwd_queue(&acts[0], input->q_index);

	flow = ice_ethtool_flow_to_fltr(fsp->flow_type & ~FLOW_EXT);
	hw_prof = hw->acl_prof[flow];

	err = ice_flow_add_entry(hw, ICE_BLK_ACL, hw_prof->prof_id,
				 fsp->location, vsi->idx, ICE_FLOW_PRIO_NORMAL,
				 input, acts, ICE_ACL_NUM_ACT, &entry_h);
	if (err) {
		dev_err(dev, "Could not add flow entry %d\n", flow);
		goto free_input;
	}

	return 0;

free_input:
	kfree(input);

	return err;
}
