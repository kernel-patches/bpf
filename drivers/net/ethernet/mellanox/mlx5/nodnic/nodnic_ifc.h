/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
// Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#ifndef __MLX5_IFC_NODNIC_H__
#define __MLX5_IFC_NODNIC_H__

#include <linux/mlx5/device.h>
#include <linux/types.h>

enum {
	MLX5_NODNIC_ISEG_NIC_INTERFACE_FULL_DRIVER,
	MLX5_NODNIC_ISEG_NIC_INTERFACE_DISABLED,
	MLX5_NODNIC_ISEG_NIC_INTERFACE_NO_DRAM_NIC,
	MLX5_NODNIC_ISEG_NIC_INTERFACE_SW_RESET = 0x7,
};

enum {
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_FW_INTERNAL_ERR	= 0x1,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_DEAD_IRISC		= 0x7,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_HW_FATAL_ERR,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_FW_CRC_ERR,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_ICM_FETCH_PCI_ERR,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_ICM_PAGE_ERR,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_ASYNCHRONOUS_EQ_BUF_OVERRUN,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_EQ_IN_ERR,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_EQ_INV,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_FFSER_ERR,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_HIGH_TEMP_ERR,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_ICM_PCI_POISONED_ERR = 0x12,
	MLX5_NODNIC_ISEG_HEALTH_SYNDROME_TRUST_LOCKDOWN_ERR,
};

/* ISEG */
#define MLX5_NODNIC_ISEG_NIC_INTERFACE MLX5_BYTE_OFF(nodnic_iseg, cmdq_addr_l)
#define MLX5_NODNIC_ISEG_INITIALIZING \
	MLX5_BYTE_OFF(nodnic_iseg, initializing_word)
#define MLX5_NODNIC_ISEG_NO_DRAM_NIC_OFFSET \
	MLX5_BYTE_OFF(nodnic_iseg, no_dram_nic_offset)
#define MLX5_NODNIC_ISEG_CMD_ADDR_L \
	MLX5_BYTE_OFF(nodnic_iseg_cmdq_addr_l, cmdq_addr_l)
#define MLX5_NODNIC_ISEG_CLEAR_INT MLX5_BYTE_OFF(nodnic_iseg, clear_int)

/* General configuration */
#define MLX5_NODNIC_GENERAL_CONFIG_CAPS MLX5_BYTE_OFF(nodnic_gen_cfg, caps)
#define MLX5_NODNIC_GENERAL_CONFIG_LOG_MAX_RING_SIZE \
	MLX5_BYTE_OFF(nodnic_gen_cfg, log_max_ring_size)
#define MLX5_NODNIC_GENERAL_CONFIG_LKEY MLX5_BYTE_OFF(nodnic_gen_cfg, lkey)
#define MLX5_NODNIC_GENERAL_CONFIG_CQE_FORMAT \
	MLX5_BYTE_OFF(nodnic_gen_cfg, cqe_format)
#define MLX5_NODNIC_GENERAL_CONFIG_FEATURE_CAPS \
	MLX5_BYTE_OFF(nodnic_gen_cfg, feature_caps)
#define MLX5_NODNIC_GENERAL_CONFIG_LOG_UAR_PAGE_SIZE \
	MLX5_BYTE_OFF(nodnic_gen_cfg, log_uar_page_size)

/* Port */
#define MLX5_NODNIC_PORT_OFFSET \
	MLX5_BYTE_OFF(nodnic_config_seg, port)
#define MLX5_NODNIC_PORT_FIELD_OFFSET(field) \
	(MLX5_NODNIC_PORT_OFFSET + MLX5_BYTE_OFF(nodnic_port_settings, field))

#define MLX5_NODNIC_PORT_EVENT		MLX5_NODNIC_PORT_FIELD_OFFSET(event)
#define MLX5_NODNIC_RECEIVE_RING_OFFSET	\
	MLX5_NODNIC_PORT_FIELD_OFFSET(receive_ring0)
#define MLX5_NODNIC_SEND_RING_OFFSET MLX5_NODNIC_PORT_FIELD_OFFSET(send_ring0)
#define MLX5_NODNIC_PORT_NETWORK	MLX5_NODNIC_PORT_FIELD_OFFSET(network)
#define MLX5_NODNIC_PORT_MAC_ADDR_H	MLX5_NODNIC_PORT_FIELD_OFFSET(mac_h)
#define MLX5_NODNIC_PORT_MAC_ADDR_L	MLX5_NODNIC_PORT_FIELD_OFFSET(mac_l)
#define MLX5_NODNIC_PORT_CQ_ADDR_H	MLX5_NODNIC_PORT_FIELD_OFFSET(cq_addr_h)
#define MLX5_NODNIC_PORT_CQ_ADDR_L	MLX5_NODNIC_PORT_FIELD_OFFSET(cq_addr_l)
#define MLX5_NODNIC_PORT_WORK_BUF_ADDR_H \
	MLX5_NODNIC_PORT_FIELD_OFFSET(working_buffer_addr_h)
#define MLX5_NODNIC_PORT_WORK_BUF_ADDR_L \
	MLX5_NODNIC_PORT_FIELD_OFFSET(working_buffer_addr_l)
#define MLX5_NODNIC_PORT_ARM_CQ		MLX5_NODNIC_PORT_FIELD_OFFSET(arm_cq)
#define MLX5_NODNIC_PORT_SEND_RING0_UAR_INDEX \
	MLX5_NODNIC_PORT_FIELD_OFFSET(send_ring0_uar_index)
#define MLX5_NODNIC_CQ_DBR_ADDR_H	\
	MLX5_NODNIC_PORT_FIELD_OFFSET(cq_dbr_addr_h)
#define MLX5_NODNIC_CQ_DBR_ADDR_L	\
	MLX5_NODNIC_PORT_FIELD_OFFSET(cq_dbr_addr_l)
#define MLX5_NODNIC_CQ_N		\
	MLX5_NODNIC_PORT_FIELD_OFFSET(cqn)

/* Port ring */
#define MLX5_NODNIC_RING_ADDR_H MLX5_BYTE_OFF(nodnic_ring_config, q_addr_h)
#define MLX5_NODNIC_RING_ADDR_L MLX5_BYTE_OFF(nodnic_ring_config, q_addr_l)
#define MLX5_NODNIC_RING_QUEUE_NUMBER \
	MLX5_BYTE_OFF(nodnic_ring_config, q_number)
#define MLX5_NODNIC_RING_DBR_ADDR_H \
	MLX5_BYTE_OFF(nodnic_ring_config, dbr_addr_h)
#define MLX5_NODNIC_RING_DBR_ADDR_L \
	MLX5_BYTE_OFF(nodnic_ring_config, dbr_addr_l)

/* mlx5_nodnic configurations are read and written from VSC
 * in a dword granularity
 */

struct mlx5_ifc_nodnic_iseg_cmdq_addr_l_bits {
	u8 cmdq_addr_l[0x14];
	u8 reserved_at_14[0x1];
	u8 nic_interface[0x3];
	u8 log_cmdq_size[0x4];
	u8 log_cmdq_stride[0x4];
};

struct mlx5_ifc_nodnic_iseg_initializing_word_bits {
	u8 initializing[0x1];
	u8 nic_interface_supported[0x7];
	u8 embedded_cpu[0x1];
	u8 driver_reset_ack[0x1];
	u8 recovery[0x1];
	u8 pre_boot_bios_hold[0x1];
	u8 initializing_state[0x4];
	u8 reset_state_machine[0x4];
	u8 reserved_at_14[0x1];
	u8 pre_boot_action[0x3];
	u8 reserved_at_17[0x8];
};

struct mlx5_ifc_nodnic_iseg_health_buffer_bits {
	u8 reserved_at_0[0x100];
	u8 assert_existptr[0x20];
	u8 assert_callra[0x20];
	u8 reserved_at_28[0x20];
	u8 time[0x20];
	u8 fw_version[0x20];
	u8 hw_id[0x20];
	u8 rfr[0x1];
	u8 crr[0x1];
	u8 reserved_at_e2[0x2];
	u8 valid[0x1];
	u8 severity[0x3];
	u8 reserved_at_e8[0x18];
	u8 irisc_index[0x8];
	u8 synd[0x8];
	u8 ext_synd[0x10];
};

struct mlx5_ifc_nodnic_clear_int_bits {
	u8 reserved_at_0[0x1f];
	u8 clear_int[0x1];
};

struct mlx5_ifc_nodnic_iseg_bits {
	u8 fw_rev[0x20];
	u8 cmdif_rev[0x20];
	u8 rsvd0[0x40];
	u8 cmdq_addr_h[0x20];
	struct mlx5_ifc_nodnic_iseg_cmdq_addr_l_bits cmdq_addr_l;
	u8 command_doorbell_vector[0x20];
	u8 rsvd1[0xee0];
	u8 traffic_state_rsvd[0x1e];
	u8 traffic_state[0x2];
	struct mlx5_ifc_nodnic_iseg_initializing_word_bits initializing_word;
	struct mlx5_ifc_nodnic_iseg_health_buffer_bits health_buffer;
	u8 no_dram_nic_offset[0x20];
	u8 rsvd2[0x6e40];
	struct mlx5_ifc_nodnic_clear_int_bits clear_int;
};

struct mlx5_ifc_nodnic_q_addr_l_bits {
	u8 q_addr_l[0x14];
	u8 reserved_at_14[0x6];
	u8 log_size[0x6];
};

struct mlx5_ifc_nodnic_ring_db_reg_bits {
	u8 reserved_at_0[0x8];
	u8 ring_pi[0x10];
	u8 reserved_at_18[0x8];
};

struct mlx5_ifc_nodnic_ring_q_number_bits {
	u8 reserved_at_0[0x8];
	u8 queue_number[0x18];
};

struct mlx5_ifc_nodnic_ring_dbr_addr_l_bits {
	u8 db_record_addr_l[0x1e];
	u8 reserved_at_1e[0x2];
};

struct mlx5_ifc_nodnic_ring_config_bits {
	u8 q_addr_h[0x20];
	struct mlx5_ifc_nodnic_q_addr_l_bits q_addr_l;
	struct mlx5_ifc_nodnic_ring_db_reg_bits	db_reg;
	struct mlx5_ifc_nodnic_ring_q_number_bits q_number;
	u8 q_key[0x20];
	u8 pkey[0x20];
	u8 dbr_addr_h[0x20];
	u8 dbr_addr_l[0x20];
};

struct mlx5_ifc_nodnic_port_event_bits {
	u8 driver_reset_needed[0x1];
	u8 port_management_change[0x1];
	u8 reserved_at_2[0x19];
	u8 link_type[0x1];
	u8 port_state[0x4];
};

struct mlx5_ifc_nodnic_port_network_bits {
	u8 network_en[0x1];
	u8 dma_en[0x1];
	u8 promisc_en[0x1];
	u8 promisc_multicast_en[0x1];
	u8 vlan_stripping_en[0x1];
	u8 protocol_filter_ip_ver[0x1];
	u8 data_msix_en[0x1];
	u8 event_msix_en[0x1];
	u8 reserved_at_8[0x8];
	u8 protocol_filter_en[0x8];
	u8 reserved_at_18[0x3];
	u8 receive_filter_en[0x5];
};

struct mlx5_ifc_nodnic_port_mac_h_bits {
	u8 reserved_at_0[0x10];
	u8 mac_h[0x10];
};

struct mlx5_ifc_nodnic_port_arm_cq_bits {
	u8 cq_ci[0x18];
	u8 reserved_at_18[0x8];
};

struct  mlx5_ifc_nodnic_cqn_bits {
	u8 reserved[0x8];
	u8 cq_n[0x18];
};

struct mlx5_ifc_nodnic_port_settings_bits {
	struct mlx5_ifc_nodnic_port_event_bits event;
	struct mlx5_ifc_nodnic_port_network_bits network;
	struct mlx5_ifc_nodnic_port_mac_h_bits mac_h;
	u8 mac_l[0x20];
	u8 mac_filters[0x200];
	u8 gid[0x80];
	u8 reserved_at_300[0x20];
	u8 sm_sl_lid[0x20];
	u8 cq_addr_h[0x20];
	struct mlx5_ifc_nodnic_q_addr_l_bits cq_addr_l;
	u8 working_buffer_addr_h[0x20];
	u8 working_buffer_addr_l[0x20];
	struct mlx5_ifc_nodnic_port_arm_cq_bits arm_cq;
	u8 pkey[0x20];
	struct mlx5_ifc_nodnic_ring_config_bits send_ring0;
	u8 rsvd_send_ring1[0x100];
	struct mlx5_ifc_nodnic_ring_config_bits receive_ring0;
	u8 rsvd_receive_ring1[0x100];
	u8 protocol_filter_tftp_port[0x20];
	u8 reserved_at_104[0x20];
	u8 send_ring0_uar_index[0x20];
	u8 send_ring1_uar_index[0x20];
	u8 cq_dbr_addr_h[0x20];
	u8 cq_dbr_addr_l[0x20];
	struct mlx5_ifc_nodnic_cqn_bits cqn;
	u8 padding[0x320];
};

struct mlx5_ifc_nodnic_gen_cfg_caps_bits  {
	u8 revision[0x8];
	u8 hardware_format[0x8];
	u8 support_receive_filter[0x1];
	u8 support_promisc_filter[0x1];
	u8 support_promisc_multicast[0x1];
	u8 support_protocol_filter[0x1];
	u8 reserved_at_13[0x1];
	u8 log_working_buffer_size[0x3];
	u8 log_pkey_table_size[0x4]; /* IB */
	u8 reserved_at_1a[0x3];
	u8 num_ports[0x1];
};

struct mlx5_ifc_nodnic_gen_cfg_log_max_ring_size_bits {
	u8 reserved_at_0[0x2];
	u8 log_max_ring_size[0x6];
	u8 reserved_at_8[0x18];
};

struct mlx5_ifc_nodnic_gen_cfg_cqe_format_bits {
	u8 cqe_format[0x4];
	u8 reserved_at_4[0x1c];
};

struct mlx5_ifc_nodnic_gen_cfg_feature_caps_bits {
	u8 support_db_record_rx[0x1];
	u8 reserved_at_1[0x1];
	u8 support_uar_tx_doorbell[0x1];
	u8 support_bar_dma_en[0x1];
	u8 support_bar_cq_ctrl[0x1];
	u8 vlan_stripping_supported[0x1];
	u8 data_msix_support[0x1];
	u8 event_msix_support[0x1];
	u8 reserved_at_8[0x18];
};

struct mlx5_ifc_nodnic_gen_cfg_log_uar_page_size_bits {
	u8 reserved_at_0[0x18];
	u8 log_uar_page_size[0x8];
};

struct mlx5_ifc_nodnic_gen_cfg_bits {
	struct mlx5_ifc_nodnic_gen_cfg_caps_bits caps;
	struct mlx5_ifc_nodnic_gen_cfg_log_max_ring_size_bits log_max_ring_size;
	u8 lkey[0x20];
	struct mlx5_ifc_nodnic_gen_cfg_cqe_format_bits cqe_format;
	u8 reserved_at_80[3][0x20];
	struct mlx5_ifc_nodnic_gen_cfg_feature_caps_bits feature_caps;
	struct mlx5_ifc_nodnic_gen_cfg_log_uar_page_size_bits log_uar_page_size;
};

struct mlx5_ifc_nodnic_config_seg_bits {
	struct mlx5_ifc_nodnic_gen_cfg_bits general;
	u8 reserved_at_24[55][0x20];
	struct mlx5_ifc_nodnic_port_settings_bits port;
};

#endif /* __MLX5_IFC_NODNIC_H__ */
