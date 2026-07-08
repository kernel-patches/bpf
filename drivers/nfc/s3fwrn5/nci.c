// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * NCI based driver for Samsung S3FWRN5 NFC chip
 *
 * Copyright (C) 2015 Samsung Electronics
 * Robert Baldyga <r.baldyga@samsung.com>
 */

#include <linux/completion.h>
#include <linux/firmware.h>
#include <linux/minmax.h>
#include <linux/slab.h>
#include <linux/unaligned.h>

#include "s3fwrn5.h"
#include "nci.h"

static int s3fwrn5_nci_prop_rsp(struct nci_dev *ndev, struct sk_buff *skb)
{
	__u8 status = skb->data[0];

	nci_req_complete(ndev, status);
	return 0;
}

const struct nci_driver_ops s3fwrn5_nci_prop_ops[5] = {
	{
		.opcode = nci_opcode_pack(NCI_GID_PROPRIETARY,
				NCI_PROP_SET_RFREG),
		.rsp = s3fwrn5_nci_prop_rsp,
	},
	{
		.opcode = nci_opcode_pack(NCI_GID_PROPRIETARY,
				NCI_PROP_START_RFREG),
		.rsp = s3fwrn5_nci_prop_rsp,
	},
	{
		.opcode = nci_opcode_pack(NCI_GID_PROPRIETARY,
				NCI_PROP_STOP_RFREG),
		.rsp = s3fwrn5_nci_prop_rsp,
	},
	{
		.opcode = nci_opcode_pack(NCI_GID_PROPRIETARY,
				NCI_PROP_FW_CFG),
		.rsp = s3fwrn5_nci_prop_rsp,
	},
	{
		.opcode = nci_opcode_pack(NCI_GID_PROPRIETARY,
				NCI_PROP_DUAL_OPTION),
		.rsp = s3fwrn5_nci_prop_rsp,
	},
};

#define S3FWRN5_RFREG_SECTION_SIZE 252

int s3fwrn5_nci_rf_configure(struct s3fwrn5_info *info, const char *fw_name)
{
	struct device *dev = &info->ndev->nfc_dev->dev;
	const struct firmware *fw;
	struct nci_prop_fw_cfg_cmd fw_cfg;
	struct nci_prop_set_rfreg_cmd set_rfreg;
	struct nci_prop_stop_rfreg_cmd stop_rfreg;
	u32 checksum;
	int i, len;
	int ret;

	ret = request_firmware(&fw, fw_name, dev);
	if (ret < 0)
		return ret;

	/* Compute rfreg checksum */

	checksum = 0;
	for (i = 0; i < fw->size; i += 4)
		checksum += *((u32 *)(fw->data+i));

	/* Set default clock configuration for external crystal */

	fw_cfg.clk_type = 0x01;
	fw_cfg.clk_speed = 0xff;
	fw_cfg.clk_req = 0xff;
	ret = nci_prop_cmd(info->ndev, NCI_PROP_FW_CFG,
		sizeof(fw_cfg), (__u8 *)&fw_cfg);
	if (ret < 0)
		goto out;

	/* Start rfreg configuration */

	dev_info(dev, "rfreg configuration update: %s\n", fw_name);

	ret = nci_prop_cmd(info->ndev, NCI_PROP_START_RFREG, 0, NULL);
	if (ret < 0) {
		dev_err(dev, "Unable to start rfreg update\n");
		goto out;
	}

	/* Update rfreg */

	set_rfreg.index = 0;
	for (i = 0; i < fw->size; i += S3FWRN5_RFREG_SECTION_SIZE) {
		len = (fw->size - i < S3FWRN5_RFREG_SECTION_SIZE) ?
			(fw->size - i) : S3FWRN5_RFREG_SECTION_SIZE;
		memcpy(set_rfreg.data, fw->data+i, len);
		ret = nci_prop_cmd(info->ndev, NCI_PROP_SET_RFREG,
			len+1, (__u8 *)&set_rfreg);
		if (ret < 0) {
			dev_err(dev, "rfreg update error (code=%d)\n", ret);
			goto out;
		}
		set_rfreg.index++;
	}

	/* Finish rfreg configuration */

	stop_rfreg.checksum = checksum & 0xffff;
	ret = nci_prop_cmd(info->ndev, NCI_PROP_STOP_RFREG,
		sizeof(stop_rfreg), (__u8 *)&stop_rfreg);
	if (ret < 0) {
		dev_err(dev, "Unable to stop rfreg update\n");
		goto out;
	}

	dev_info(dev, "rfreg configuration update: success\n");
out:
	release_firmware(fw);
	return ret;
}

/*
 * Configure the reference clock. The S3NRN4V expects the single-byte FW_CFG
 * form (just the clock-speed selector). The downstream stack sends this in the
 * bootloader before CORE_RESET; the earliest the mainline NCI core lets us in
 * is the ->setup hook (after CORE_RESET, before CORE_INIT), which works.
 */
int s3fwrn5_nci_clk_cfg(struct s3fwrn5_info *info)
{
	u8 clk_speed = NCI_PROP_FW_CFG_CLK_SPEED;

	return nci_prop_cmd(info->ndev, NCI_PROP_FW_CFG, 1, &clk_speed);
}

/*
 * S3NRN4V RF register update. The HW and SW register blobs are merged into a
 * single stream (HW first) and pushed via the DUAL_OPTION command:
 * START_UPDATE, one SET_OPTION per 252-byte section, then STOP_UPDATE carrying
 * a 16-bit checksum (running sum of the merged stream as 32-bit words).
 */
int s3fwrn5_nci_rf_configure_dual(struct s3fwrn5_info *info,
				  const char *hw_name, const char *sw_name)
{
	const struct firmware *hw_fw = NULL, *sw_fw = NULL;
	struct nci_prop_dual_set_option_cmd set_option;
	struct device *dev = &info->ndev->nfc_dev->dev;
	size_t merged_size, i, len;
	u8 *merged = NULL;
	u8 stop_cmd[3];
	u32 checksum;
	u8 sub_oid;
	int ret;

	ret = request_firmware(&hw_fw, hw_name, dev);
	if (ret < 0)
		return ret;
	ret = request_firmware(&sw_fw, sw_name, dev);
	if (ret < 0)
		goto out_hw;

	merged_size = hw_fw->size + sw_fw->size;

	/*
	 * The stream is checksummed as 32-bit words and pushed in at most 256
	 * sections (the section index is a single byte); reject blobs that
	 * would silently break either.
	 */
	if (merged_size % 4 ||
	    merged_size > 256 * NCI_PROP_DUAL_SECTION_SIZE) {
		dev_err(dev, "invalid rfreg blob size (%zu)\n", merged_size);
		ret = -EINVAL;
		goto out;
	}

	merged = kmalloc(merged_size, GFP_KERNEL);
	if (!merged) {
		ret = -ENOMEM;
		goto out;
	}
	memcpy(merged, hw_fw->data, hw_fw->size);
	memcpy(merged + hw_fw->size, sw_fw->data, sw_fw->size);

	/* Running sum of the merged stream as little-endian 32-bit words. */
	checksum = 0;
	for (i = 0; i + 4 <= merged_size; i += 4)
		checksum += get_unaligned_le32(merged + i);

	dev_dbg(dev, "rfreg dual-option update: %s + %s\n", hw_name, sw_name);

	/* START_UPDATE */
	sub_oid = NCI_PROP_DUAL_SUB_START_UPDATE;
	ret = nci_prop_cmd(info->ndev, NCI_PROP_DUAL_OPTION, 1, &sub_oid);
	if (ret < 0) {
		dev_err(dev, "Unable to start rfreg update\n");
		goto out;
	}

	/* SET_OPTION per section */
	set_option.sub_oid = NCI_PROP_DUAL_SUB_SET_OPTION;
	set_option.index = 0;
	for (i = 0; i < merged_size; i += NCI_PROP_DUAL_SECTION_SIZE) {
		len = min_t(size_t, merged_size - i, NCI_PROP_DUAL_SECTION_SIZE);
		memcpy(set_option.data, merged + i, len);
		ret = nci_prop_cmd(info->ndev, NCI_PROP_DUAL_OPTION,
				   len + 2, (__u8 *)&set_option);
		if (ret < 0) {
			dev_err(dev, "rfreg update error (code=%d)\n", ret);
			goto out;
		}
		set_option.index++;
	}

	/* STOP_UPDATE with checksum */
	stop_cmd[0] = NCI_PROP_DUAL_SUB_STOP_UPDATE;
	put_unaligned_le16(checksum, &stop_cmd[1]);
	ret = nci_prop_cmd(info->ndev, NCI_PROP_DUAL_OPTION, 3, stop_cmd);
	if (ret < 0) {
		dev_err(dev, "Unable to stop rfreg update\n");
		goto out;
	}

	dev_dbg(dev, "rfreg dual-option update: success\n");
out:
	kfree(merged);
	release_firmware(sw_fw);
out_hw:
	release_firmware(hw_fw);
	return ret;
}
