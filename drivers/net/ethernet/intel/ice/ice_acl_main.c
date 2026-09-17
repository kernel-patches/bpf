// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2026, Intel Corporation. */

#include "ice.h"
#include "ice_lib.h"
#include "ice_acl_main.h"

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
 * ice_acl_add_rule_ethtool - add an ACL rule
 * @vsi: pointer to target VSI
 * @cmd: command to add or delete ACL rule
 *
 * Return: 0 on success and negative values for failure
 */
int ice_acl_add_rule_ethtool(struct ice_vsi *vsi, struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp;
	struct ice_pf *pf;

	pf = vsi->back;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	return ice_acl_prof_add_ethtool(pf, fsp);
}
