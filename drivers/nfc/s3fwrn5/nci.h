/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * NCI based driver for Samsung S3FWRN5 NFC chip
 *
 * Copyright (C) 2015 Samsung Electronics
 * Robert Baldyga <r.baldyga@samsung.com>
 */

#ifndef __LOCAL_S3FWRN5_NCI_H_
#define __LOCAL_S3FWRN5_NCI_H_

#include "s3fwrn5.h"

#define NCI_PROP_SET_RFREG	0x22

struct nci_prop_set_rfreg_cmd {
	__u8 index;
	__u8 data[252];
};

struct nci_prop_set_rfreg_rsp {
	__u8 status;
};

#define NCI_PROP_START_RFREG	0x26

struct nci_prop_start_rfreg_rsp {
	__u8 status;
};

#define NCI_PROP_STOP_RFREG	0x27

struct nci_prop_stop_rfreg_cmd {
	__u16 checksum;
};

struct nci_prop_stop_rfreg_rsp {
	__u8 status;
};

#define NCI_PROP_FW_CFG		0x28

/*
 * Single-byte FW_CFG payload (clock-speed selector) for the S3NRN4V reference
 * clock. Taken from the vendor configuration for this part (the encoding is
 * not documented).
 */
#define NCI_PROP_FW_CFG_CLK_SPEED	0x11

struct nci_prop_fw_cfg_cmd {
	__u8 clk_type;
	__u8 clk_speed;
	__u8 clk_req;
};

struct nci_prop_fw_cfg_rsp {
	__u8 status;
};

/*
 * The S3NRN4V updates its RF registers through a single "dual option" command
 * (a sub-OID selects the operation) instead of the START/SET/STOP_RFREG
 * opcodes above, and expects the HW and SW register blobs merged into one
 * stream.
 */
#define NCI_PROP_DUAL_OPTION		0x2a

#define NCI_PROP_DUAL_SUB_START_UPDATE	0x01
#define NCI_PROP_DUAL_SUB_SET_OPTION	0x02
#define NCI_PROP_DUAL_SUB_STOP_UPDATE	0x03

#define NCI_PROP_DUAL_SECTION_SIZE	252

struct nci_prop_dual_set_option_cmd {
	__u8 sub_oid;	/* NCI_PROP_DUAL_SUB_SET_OPTION */
	__u8 index;
	__u8 data[NCI_PROP_DUAL_SECTION_SIZE];
};

extern const struct nci_driver_ops s3fwrn5_nci_prop_ops[5];
int s3fwrn5_nci_rf_configure(struct s3fwrn5_info *info, const char *fw_name);
int s3fwrn5_nci_rf_configure_dual(struct s3fwrn5_info *info,
				  const char *hw_name, const char *sw_name);
int s3fwrn5_nci_clk_cfg(struct s3fwrn5_info *info);

#endif /* __LOCAL_S3FWRN5_NCI_H_ */
