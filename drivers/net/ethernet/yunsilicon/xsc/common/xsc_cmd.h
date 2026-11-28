/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021-2026, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_CMD_H
#define __XSC_CMD_H

#include <linux/if_ether.h>
#include <linux/types.h>

struct xsc_core_device;

#define XSC_CMDQ_VERSION	0x32

#define XSC_BOARD_SN_LEN		32
#define XSC_MAX_NUM_PCIE_INTF		2
#define XSC_MAX_PF_NUM_PER_PCIE		8

/* hca_cap mbox version */
#define XSC_CMD_QUERY_HCA_CAP_V1	1

enum {
	XSC_CMD_STAT_OK				= 0x0,
	XSC_CMD_STAT_BAD_OP_ERR			= 0x2,
	XSC_CMD_STAT_BAD_PARAM_ERR		= 0x3,
	XSC_CMD_STAT_RES_BUSY			= 0x6,
	XSC_CMD_STAT_IX_ERR			= 0xa,
	XSC_CMD_STAT_QP_FLUSH_BUSY		= 0x4b,
	XSC_CMD_STAT_QP_FLUSH_PENDING		= 0x4c,
	XSC_CMD_STAT_INVAL_FUNC			= 0x41,
};

enum {
	XSC_CMD_OP_QUERY_HCA_CAP		= 0x100,
	XSC_CMD_OP_QUERY_CMDQ_VERSION		= 0x10a,
	XSC_CMD_OP_FUNCTION_RESET		= 0x10c,

	XSC_CMD_OP_CREATE_EQ			= 0x301,
	XSC_CMD_OP_DESTROY_EQ			= 0x302,

	XSC_CMD_OP_CREATE_CQ			= 0x400,
	XSC_CMD_OP_DESTROY_CQ			= 0x401,

	XSC_CMD_OP_CREATE_QP			= 0x500,
	XSC_CMD_OP_DESTROY_QP			= 0x501,
	XSC_CMD_OP_2RST_QP			= 0x50a,
	XSC_CMD_OP_RTR2RTS_QP			= 0x504,

	XSC_CMD_OP_ENABLE_NIC_HCA		= 0x810,
	XSC_CMD_OP_DISABLE_NIC_HCA		= 0x811,
	XSC_CMD_OP_MODIFY_RAW_QP		= 0x81f,

	XSC_CMD_OP_QUERY_VPORT_STATE		= 0x822,
	XSC_CMD_OP_QUERY_EVENT_TYPE		= 0x831,

	XSC_CMD_OP_ENABLE_MSIX			= 0x850,

	XSC_CMD_OP_SET_MTU			= 0x1100,
	XSC_CMD_OP_QUERY_ETH_MAC		= 0x1101,

	XSC_CMD_OP_SET_PORT_ADMIN_STATUS	= 0x1801,
};

enum xsc_dma_direct {
	XSC_DMA_DIR_TO_MAC,
};

enum {
	XSC_TBM_CAP_HASH_PPH = 0,
	XSC_TBM_CAP_RSS,
	XSC_TBM_CAP_PCT_DROP_CONFIG,
};

struct xsc_inbox_hdr {
	__be16		opcode;
	u8		rsvd[4];
	__be16		ver;
};

struct xsc_outbox_hdr {
	u8		status;
	u8		rsvd[5];
	__be16		ver;
};

/* CQ mbox */
struct xsc_cq_context {
	__be16		eqn;
	__be16		pa_num;
	__be16		glb_func_id;
	u8		log_cq_sz;
	u8		cq_type;
};

struct xsc_create_cq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_cq_context	ctx;
	__be64			pas[];
};

struct xsc_create_cq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			cqn;
	u8			rsvd[4];
};

struct xsc_destroy_cq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			cqn;
	u8			rsvd[4];
};

struct xsc_destroy_cq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

/* QP mbox */
struct __packed xsc_create_qp_request {
	__be16		input_qpn;
	__be16		pa_num;
	u8		qp_type;
	u8		log_sq_sz;
	u8		log_rq_sz;
	u8		dma_direct;
	__be32		pdn;
	__be16		cqn_send;
	__be16		cqn_recv;
	__be16		glb_funcid;
	u8		page_shift;
	u8		rsvd[5];
	__be64		pas[];
};

struct xsc_create_qp_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_create_qp_request	req;
};

struct xsc_create_qp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			qpn;
	u8			rsvd[4];
};

struct xsc_destroy_qp_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			qpn;
	u8			rsvd[4];
};

struct xsc_destroy_qp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_qp_context {
	__be32		remote_qpn;
	__be32		cqn_send;
	__be32		cqn_recv;
	__be32		next_send_psn;
	__be32		next_recv_psn;
	__be32		pdn;
	__be16		src_udp_port;
	__be16		path_id;
	u8		mtu_mode;
	u8		lag_sel;
	u8		lag_sel_en;
	u8		retry_cnt;
	u8		rnr_retry;
	u8		dscp;
	u8		state;
	u8		hop_limit;
	u8		dmac[6];
	u8		smac[6];
	__be32		dip[4];
	__be32		sip[4];
	__be16		ip_type;
	__be16		grp_id;
	u8		vlan_valid;
	u8		dci_cfi_prio_sl;
	__be16		vlan_id;
	u8		qp_out_port;
	u8		pcie_no;
	__be16		lag_id;
	__be16		func_id;
	u8		max_sra;
	u8		max_rra;
	u8		no_need_wait;
	u8		swith_qp_type;
	u8		rsvd0[2];
	__be32		qp_access_flags;
};

struct xsc_modify_qp_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			qpn;
	struct xsc_qp_context	ctx;
	u8			no_need_wait;
};

struct xsc_modify_qp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_modify_raw_qp_request {
	__be16		qpn;
	__be16		lag_id;
	__be16		func_id;
	u8		dma_direct;
	u8		prio;
	u8		qp_out_port;
	u8		rsvd[7];
};

struct xsc_modify_raw_qp_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			pcie_no;
	u8			rsvd[7];
	struct xsc_modify_raw_qp_request	req;
};

struct xsc_modify_raw_qp_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

/* MSIX TABLE mbox */
struct xsc_msix_table_info_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			index;
	u8			rsvd[6];
};

struct xsc_msix_table_info_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			addr_lo;
	__be32			addr_hi;
	__be32			data;
};

/* EQ mbox */
struct xsc_eq_context {
	__be16			vecidx;
	__be16			pa_num;
	u8			log_eq_sz;
	u8			rsvd1;
	__be16			glb_func_id;
	u8			is_async_eq;
	u8			rsvd;
};

struct xsc_create_eq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_eq_context	ctx;
	u8			rsvd[6];
	__be64			pas[];
};

struct xsc_create_eq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			eqn;
	u8			rsvd[4];
};

struct xsc_destroy_eq_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be32			eqn;
	u8			rsvd[4];
};

struct xsc_destroy_eq_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_query_cmdq_ver_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_cmd_query_cmdq_ver_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be16			cmdq_ver;
	u8			rsvd[6];
};

/* fw mailbox layout, do not change */
struct xsc_fw_version {
	u8		rsvd[16];
};

struct __packed xsc_hca_cap {
	u8		rsvd1[12];
	u8		send_seg_num;
	u8		send_wqe_shift;
	u8		recv_seg_num;
	u8		recv_wqe_shift;
	u8		log_max_srq_sz;
	u8		log_max_qp_sz;
	u8		log_max_mtt;
	u8		log_max_qp;
	u8		log_max_strq_sz;
	u8		log_max_srqs;
	u8		rsvd4[2];
	u8		log_max_tso;
	u8		log_max_cq_sz;
	u8		rsvd6;
	u8		log_max_cq;
	u8		log_max_eq_sz;
	u8		log_max_mkey;
	u8		log_max_msix;
	u8		log_max_eq;
	u8		max_indirection;
	u8		log_max_mrw_sz;
	u8		log_max_bsf_list_sz;
	u8		log_max_klm_list_sz;
	u8		rsvd_8_0;
	u8		log_max_ra_req_dc;
	u8		rsvd_8_1;
	u8		log_max_ra_res_dc;
	u8		rsvd9;
	u8		log_max_ra_req_qp;
	u8		log_max_qp_depth;
	u8		log_max_ra_res_qp;
	__be16		max_vfs;
	__be16		raweth_qp_id_end;
	__be16		raw_tpe_qp_num;
	__be16		max_qp_count;
	__be16		raweth_qp_id_base;
	u8		rsvd13;
	u8		local_ca_ack_delay;
	u8		max_num_eqs;
	u8		num_ports;
	u8		log_max_msg;
	u8		mac_port;
	__be16		raweth_rss_qp_id_base;
	__be16		stat_rate_support;
	u8		rsvd16[8];
	__be64		flags;
	u8		rsvd17;
	u8		uar_sz;
	u8		rsvd18;
	u8		log_pg_sz;
	__be16		bf_log_bf_reg_size;
	__be16		msix_base;
	__be16		msix_num;
	__be16		max_desc_sz_sq;
	u8		rsvd20[2];
	__be16		max_desc_sz_rq;
	u8		rsvd21[2];
	__be16		max_desc_sz_sq_dc;
	u8		rsvd22[4];
	__be16		max_qp_mcg;
	u8		rsvd23;
	u8		log_max_mcg;
	u8		rsvd24;
	u8		log_max_pd;
	u8		rsvd25;
	u8		log_max_xrcd;
	u8		rsvd26[40];
	__be32		uar_page_sz;
	u8		rsvd27[8];
	__be32		hw_feature_flag;
	__be16		pf0_vf_funcid_base;
	__be16		pf0_vf_funcid_top;
	__be16		pf1_vf_funcid_base;
	__be16		pf1_vf_funcid_top;
	__be16		pcie0_pf_funcid_base;
	__be16		pcie0_pf_funcid_top;
	__be16		pcie1_pf_funcid_base;
	__be16		pcie1_pf_funcid_top;
	u8		log_msx_atomic_size_qp;
	u8		pcie_host;
	u8		rsvd28;
	u8		log_msx_atomic_size_dc;
	u8		board_sn[XSC_BOARD_SN_LEN];
	u8		max_tc;
	u8		mac_bit;
	__be16		funcid_to_logic_port;
	u8		rsvd29[6];
	u8		nif_port_num;
	u8		reg_mr_via_cmdq;
	__be32		hca_core_clock;
	__be32		max_rwq_indirection_tables;
	__be32		max_rwq_indirection_table_size;
	__be32		chip_ver_h;
	__be32		chip_ver_m;
	__be32		chip_ver_l;
	__be32		hotfix_num;
	__be32		feature_flag;
	__be32		rx_pkt_len_max;
	__be32		glb_func_id;
	__be64		tx_db;
	__be64		rx_db;
	__be64		complete_db;
	__be64		complete_reg;
	__be64		event_db;
	__be32		qp_rate_limit_min;
	__be32		qp_rate_limit_max;
	struct xsc_fw_version	fw_ver;
	u8		lag_logic_port_ofst;
	u8		rsvd32[7];
	/* V1 */
	__be64		max_mr_size;
	__be16		max_cmd_in_len;
	__be16		max_cmd_out_len;
	u8		rsvd_v2_v3[36];
	/* V4 */
	__be16		vf_funcid_base[XSC_MAX_NUM_PCIE_INTF][XSC_MAX_PF_NUM_PER_PCIE];
	__be16		vf_funcid_top[XSC_MAX_NUM_PCIE_INTF][XSC_MAX_PF_NUM_PER_PCIE];
	__be16		pf_funcid_base[XSC_MAX_NUM_PCIE_INTF];
	__be16		pf_funcid_top[XSC_MAX_NUM_PCIE_INTF];
	u8		pcie_no;
	u8		pf_id;
	__be16		vf_id;
	u8		pcie_host_num;
	u8		pf_num_per_pcie;
	u8		rsvd_v6[46];
};

struct xsc_cmd_query_hca_cap_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			cpu_num;
	u8			rsvd[6];
};

struct xsc_cmd_query_hca_cap_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd0[8];
	struct xsc_hca_cap	hca_cap;
};

struct xsc_query_vport_state_out {
	struct xsc_outbox_hdr	hdr;
	u8			state;
#define XSC_QUERY_VPORT_ADMIN_STATE_MASK	GENMASK(3, 0)
#define XSC_QUERY_VPORT_STATE_MASK		GENMASK(7, 4)
};

struct xsc_query_vport_state_in {
	struct xsc_inbox_hdr	hdr;
	__be32			data0;
#define XSC_QUERY_VPORT_OTHER_VPORT	BIT(0)
#define XSC_QUERY_VPORT_VPORT_NUM_MASK	GENMASK(16, 1)
};

enum {
	XSC_CMD_EVENT_RESP_CHANGE_LINK		= BIT(0),
};

struct xsc_event_resp {
	u8			resp_cmd_type;
};

struct xsc_event_query_type_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			rsvd[2];
};

struct xsc_event_query_type_mbox_out {
	struct xsc_outbox_hdr	hdr;
	struct xsc_event_resp	ctx;
};

struct xsc_set_mtu_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			mtu;
	__be16			rx_buf_sz_min;
	u8			mac_port;
	u8			rsvd;
};

struct xsc_set_mtu_mbox_out {
	struct xsc_outbox_hdr	hdr;
};

struct xsc_query_eth_mac_mbox_in {
	struct xsc_inbox_hdr	hdr;
	u8			index;
};

struct xsc_query_eth_mac_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			mac[ETH_ALEN];
};

struct xsc_nic_attr {
	__be16	caps;
	__be16	caps_mask;
	u8	mac_addr[ETH_ALEN];
};

struct xsc_rss_attr {
	u8	rss_en;
	u8	hfunc;
	__be16	rqn_base;
	__be16	rqn_num;
	u8	rsvd[2];
	__be32	hash_tmpl;
};

struct xsc_cmd_enable_nic_hca_mbox_in {
	struct xsc_inbox_hdr	hdr;
	struct xsc_nic_attr	nic;
	struct xsc_rss_attr	rss;
};

struct xsc_cmd_enable_nic_hca_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd0[2];
};

struct xsc_nic_dis_attr {
	__be16	caps;
};

struct xsc_cmd_disable_nic_hca_mbox_in {
	struct xsc_inbox_hdr		hdr;
	struct xsc_nic_dis_attr		nic;
};

struct xsc_cmd_disable_nic_hca_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd0[4];
};

struct xsc_function_reset_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			glb_func_id;
	u8			rsvd[6];
};

struct xsc_function_reset_mbox_out {
	struct xsc_outbox_hdr	hdr;
	u8			rsvd[8];
};

struct xsc_event_set_port_admin_status_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			status;
};

struct xsc_event_set_port_admin_status_mbox_out {
	struct xsc_outbox_hdr	hdr;
	__be32			status;
};

int xsc_cmd_init(struct xsc_core_device *xdev);
void xsc_cmd_cleanup(struct xsc_core_device *xdev);
int xsc_cmd_exec(struct xsc_core_device *xdev,
		 void *in, unsigned int in_size,
		 void *out, unsigned int out_size);
int xsc_cmd_version_check(struct xsc_core_device *xdev);

int xsc_cmd_status_to_err(struct xsc_outbox_hdr *hdr);

#endif
