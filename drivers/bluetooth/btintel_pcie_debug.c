// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel Bluetooth PCIe Debug Framework
 *
 * Copyright (C) 2026 Intel Corporation
 *
 * Runtime-configurable TLV-based debug collection framework for loading and
 * parsing the optional YoYo firmware configuration used to enable debug
 * regions, triggers, HCI commands, and configuration sets. Also provides
 * debug INI configuration and fatal-error injection testmode.
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>
#include "btintel_pcie.h"
#include "btintel_pcie_debug.h"

static char *btintel_pcie_read_debug_ini(struct btintel_pcie_data *data)
{
	const struct firmware *fw;
	char *buf;
	int err;

	err = request_firmware_direct(&fw, BTINTEL_PCIE_DBG_INI_FILE,
				      &data->pdev->dev);
	if (err)
		return ERR_PTR(err);

	buf = kmemdup_nul(fw->data, fw->size, GFP_KERNEL);
	release_firmware(fw);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	return buf;
}

static char *btintel_pcie_ini_next(char **cursor, char **key)
{
	char *line, *eq;

	while ((line = strsep(cursor, "\n"))) {
		line = strim(line);
		if (!line[0] || line[0] == '#' || line[0] == ';')
			continue;

		eq = strchr(line, '=');
		if (!eq)
			continue;

		*eq = '\0';
		*key = strim(line);
		return strim(eq + 1);
	}

	return NULL;
}

/* Loads optional "DBG_PATH=<value>", "ENABLE_INI=<value>" and
 * "LOG_MASK=<value>" overrides from BTINTEL_PCIE_DBG_INI_FILE and applies
 * them to data->dbg_path_cache, data->enable_ini and data->log_mask.
 *
 * DBG_PATH accepts BTINTEL_PCIE_WIFI_DBGC (0x06, default) and
 * BTINTEL_PCIE_DRAM (0x01, legacy); an invalid or missing entry leaves
 * the cached value set by the caller unchanged.
 *
 * ENABLE_INI accepts 1 (enabled) or 0 (disabled); an invalid or missing
 * entry leaves data->enable_ini unchanged.
 *
 * LOG_MASK accepts any u32 bitmask (see BTINTEL_PCIE_DUMP_TX and friends).
 * The default enables alive interrupt and Sx logging; an invalid or missing
 * entry leaves data->log_mask unchanged.
 */
void btintel_pcie_load_dbg_path_from_ini(struct btintel_pcie_data *data)
{
	const char *ini_file = BTINTEL_PCIE_DBG_INI_FILE;
	char *buf, *cursor, *key, *val;
	bool dbg_path_applied = false;
	bool log_mask_applied = false;

	buf = btintel_pcie_read_debug_ini(data);
	if (IS_ERR(buf)) {
		BT_DBG("%s unavailable (%ld), using dbg_path=0x%02x log_mask=0x%08x",
		       ini_file, PTR_ERR(buf), data->dbg_path_cache,
		       data->log_mask);
		if (data->dbg_path_cache != BTINTEL_PCIE_DRAM)
			data->enable_ini = false;
		return;
	}

	cursor = buf;
	while ((val = btintel_pcie_ini_next(&cursor, &key))) {
		unsigned int parsed;

		if (!strcasecmp(key, "DBG_PATH")) {
			BT_INFO("Read DBG_PATH from %s: '%s'", ini_file, val);
			if (!kstrtouint(val, 0, &parsed) &&
			    (parsed == BTINTEL_PCIE_DRAM ||
			     parsed == BTINTEL_PCIE_WIFI_DBGC)) {
				data->dbg_path_cache = parsed;
				dbg_path_applied = true;
				BT_INFO("WRT dbg_path accepted: 0x%02x",
					data->dbg_path_cache);
			} else {
				BT_WARN("Invalid DBG_PATH='%s' in %s, using dbg_path=0x%02x",
					val, ini_file, data->dbg_path_cache);
			}
		} else if (!strcasecmp(key, "LOG_MASK")) {
			BT_INFO("Read LOG_MASK from %s: '%s'", ini_file, val);
			if (!kstrtouint(val, 0, &parsed)) {
				data->log_mask = parsed;
				log_mask_applied = true;
				BT_INFO("WRT log_mask accepted: 0x%08x",
					data->log_mask);
			} else {
				BT_WARN("Invalid LOG_MASK='%s' in %s, using log_mask=0x%08x",
					val, ini_file, data->log_mask);
			}
		} else if (!strcasecmp(key, "ENABLE_INI")) {
			BT_INFO("Read ENABLE_INI from %s: '%s'", ini_file, val);
			if (!kstrtouint(val, 0, &parsed) && parsed <= 1) {
				data->enable_ini = !!parsed;
				BT_INFO("WRT enable_ini accepted: %u",
					data->enable_ini);
			} else {
				BT_WARN("Invalid ENABLE_INI='%s' in %s, using enable_ini=%u",
					val, ini_file, data->enable_ini);
			}
		}
	}

	if (data->dbg_path_cache != BTINTEL_PCIE_DRAM)
		data->enable_ini = false;

	if (dbg_path_applied)
		BT_DBG("Loaded dbg_path=0x%02x from %s", data->dbg_path_cache, ini_file);
	else
		BT_WARN("No valid DBG_PATH in %s, dbg_path=0x%02x", ini_file, data->dbg_path_cache);

	BT_DBG("ENABLE_INI effective state: %u", data->enable_ini);

	if (log_mask_applied)
		BT_DBG("Loaded log_mask=0x%08x from %s", data->log_mask, ini_file);
	else
		BT_DBG("No valid LOG_MASK in %s, log_mask=0x%08x", ini_file, data->log_mask);

	kfree(buf);
}
EXPORT_SYMBOL_GPL(btintel_pcie_load_dbg_path_from_ini);

void btintel_pcie_fatal_err_init(struct btintel_pcie_data *data)
{
	data->fatal_err.testmode_enabled = false;
	data->fatal_err.context = BTINTEL_PCIE_DEBUG_EXCEPTION_CONTEXT_THREAD;
	data->fatal_err.type = BTINTEL_PCIE_DEBUG_EXCEPTION_FAILURE_TYPE_DEFAULT;
}
EXPORT_SYMBOL_GPL(btintel_pcie_fatal_err_init);

void btintel_pcie_fatal_err_load(struct btintel_pcie_data *data)
{
	char *buf, *cursor, *key, *val;
	u32 parsed;

	WRITE_ONCE(data->fatal_err.testmode_enabled, false);
	clear_bit(BTINTEL_PCIE_FATAL_ERR_POST_SETUP_PENDING, &data->flags);
	buf = btintel_pcie_read_debug_ini(data);
	if (IS_ERR(buf)) {
		BT_DBG("%s unavailable (%ld); fatal-error testmode disabled",
		       BTINTEL_PCIE_DBG_INI_FILE, PTR_ERR(buf));
		return;
	}

	cursor = buf;
	while ((val = btintel_pcie_ini_next(&cursor, &key))) {
		if (strcasecmp(key, "FATAL_ERR_TESTMODE"))
			continue;

		if (kstrtou32(val, 0, &parsed) ||
		    BTINTEL_PCIE_FATAL_ERR_ENABLE(parsed) > 1 ||
		    BTINTEL_PCIE_FATAL_ERR_CONTEXT(parsed) >
				BTINTEL_PCIE_DEBUG_EXCEPTION_CONTEXT_RFKILL ||
		    parsed >> 24) {
			BT_ERR("Invalid FATAL_ERR_TESTMODE='%s' in %s; testmode disabled",
			       val, BTINTEL_PCIE_DBG_INI_FILE);
			break;
		}

		data->fatal_err.context = BTINTEL_PCIE_FATAL_ERR_CONTEXT(parsed);
		data->fatal_err.type = BTINTEL_PCIE_FATAL_ERR_TYPE(parsed);
		WRITE_ONCE(data->fatal_err.testmode_enabled,
			   BTINTEL_PCIE_FATAL_ERR_ENABLE(parsed));
		BT_INFO("FATAL_ERR_TESTMODE accepted: 0x%08x", parsed);
		break;
	}

	kfree(buf);
}
EXPORT_SYMBOL_GPL(btintel_pcie_fatal_err_load);

void btintel_pcie_fatal_err_check_api_lock(struct btintel_pcie_data *data,
					   bool api_lock)
{
	if (api_lock) {
		if (READ_ONCE(data->fatal_err.testmode_enabled))
			bt_dev_info(data->hdev,
				    "OPFW API lock enabled; disabling fatal-error testmode");
		WRITE_ONCE(data->fatal_err.testmode_enabled, false);
	} else if (READ_ONCE(data->fatal_err.testmode_enabled)) {
		bt_dev_info(data->hdev, "fatal-error testmode active: ctx=0x%02x type=0x%02x",
			    data->fatal_err.context, data->fatal_err.type);
	}
}
EXPORT_SYMBOL_GPL(btintel_pcie_fatal_err_check_api_lock);

static int btintel_pcie_inject_fatal_err(struct btintel_pcie_data *data,
					 u8 context)
{
	struct hci_dev *hdev = data->hdev;
	struct sk_buff *skb;
	u8 param[2];
	int err = 0;

	/* Setup and the rest of HCI initialization hold req_lock. Wait for
	 * them before testing HCI_UP; a delayed worker alone is not enough.
	 */
	hci_req_sync_lock(hdev);
	if (!test_bit(HCI_UP, &hdev->flags) ||
	    hci_dev_test_flag(hdev, HCI_UNREGISTER)) {
		err = -ENETDOWN;
		goto unlock;
	}

	if (!READ_ONCE(data->fatal_err.testmode_enabled))
		goto unlock;

	param[0] = data->fatal_err.type;
	param[1] = context;
	skb = __hci_cmd_sync(hdev, 0xfc4d, sizeof(param), param, HCI_CMD_TIMEOUT);
	if (IS_ERR(skb)) {
		err = PTR_ERR(skb);
		goto unlock;
	}

	kfree_skb(skb);
unlock:
	hci_req_sync_unlock(hdev);
	if (err && err != -ENETDOWN)
		bt_dev_err(hdev, "fatal-error inject failed (ctx=0x%02x err=%d)",
			   context, err);
	return err;
}

bool btintel_pcie_fatal_err_handle_rfkill(struct btintel_pcie_data *data,
					  bool rfkill_on)
{
	if (!READ_ONCE(data->fatal_err.testmode_enabled))
		return false;

	if (rfkill_on) {
		/* HCI down: nothing to inject, use the normal handling */
		if (btintel_pcie_inject_fatal_err(data, data->fatal_err.context) ==
		    -ENETDOWN)
			return false;
		return true;
	}

	/* Release of an assertion handled by the normal path: let it through */
	if (test_bit(BTINTEL_PCIE_HWRFKILL_ON, &data->flags))
		return false;

	bt_dev_dbg(data->hdev, "fatal-error testmode active: ignoring RF-KILL OFF");
	return true;
}
EXPORT_SYMBOL_GPL(btintel_pcie_fatal_err_handle_rfkill);

bool btintel_pcie_fatal_err_post_setup_pending(struct btintel_pcie_data *data)
{
	int err;

	if (!test_bit(BTINTEL_PCIE_FATAL_ERR_POST_SETUP_PENDING, &data->flags))
		return false;

	/* Intentional: RFKILL context tells the controller testmode is enabled */
	err = btintel_pcie_inject_fatal_err(data,
					    BTINTEL_PCIE_DEBUG_EXCEPTION_CONTEXT_RFKILL);
	/* HCI is down: keep the injection pending for a later pass and let
	 * the normal rfkill handling run.
	 */
	if (err == -ENETDOWN)
		return false;

	clear_bit(BTINTEL_PCIE_FATAL_ERR_POST_SETUP_PENDING, &data->flags);
	return true;
}
EXPORT_SYMBOL_GPL(btintel_pcie_fatal_err_post_setup_pending);

bool btintel_pcie_fatal_err_testmode_active(struct btintel_pcie_data *data)
{
	return READ_ONCE(data->fatal_err.testmode_enabled);
}
EXPORT_SYMBOL_GPL(btintel_pcie_fatal_err_testmode_active);

/* TLV-specific parser DEBUG_INFO TLV type */
static int btintel_pcie_yoyo_parse_dbg_info(struct btintel_pcie_yoyo_ctx *ctx,
					    const struct btintel_pcie_tlv_dbg_info *info,
					    u32 len)
{
	const u8 *data = (const u8 *)info;
	u32 domain, image_type, core_type, version;

	if (len != sizeof(*info) - sizeof(struct btintel_pcie_tlv_hdr)) {
		BT_WARN("YoYo: dbg info tlv is too short or Invalid");
		return -EBADMSG;
	}

	image_type = get_unaligned_le32(data +
				       offsetof(struct btintel_pcie_tlv_dbg_info,
						image_type));
	core_type = get_unaligned_le32(data +
				      offsetof(struct btintel_pcie_tlv_dbg_info,
					       core_type));
	domain = get_unaligned_le32(data +
				   offsetof(struct btintel_pcie_tlv_dbg_info,
					    dbg_hdr.domain));
	version = get_unaligned_le32(data +
				     offsetof(struct btintel_pcie_tlv_dbg_info,
					      dbg_hdr.tlv_data_version));

	if (domain != BTINTEL_PCIE_DOMAIN_BT ||
	    version != BTINTEL_PCIE_DBG_INFO_TLV_VERSION) {
		BT_WARN("YoYo: unsupported domain/version (%u/%u), disabling",
			domain, version);
		return -EINVAL;
	}

	if (image_type != BTINTEL_PCIE_IMAGE_TLV_TYPE_EXTERNAL) {
		BT_WARN("YoYo: unsupported image_type 0x%x, disabling", image_type);
		return -EINVAL;
	}

	if (core_type != BTINTEL_PCIE_CORE_TYPE_BT) {
		BT_WARN("YoYo: non BT core_type %u, disabling", core_type);
		return -EINVAL;
	}

	ctx->dbg_info_present = true;
	BT_DBG("YoYo: config='%.64s' image=%u core=%u",
	       info->config_name, image_type, core_type);
	return 0;
}

static int btintel_pcie_yoyo_parse_buf_alloc(struct btintel_pcie_yoyo_ctx *ctx,
					     const struct btintel_pcie_tlv_buf_alloc *tlv,
					     u32 len)
{
	u32 alloc_id, buf_location, domain, idx, max_num_frags, min_buf_size;
	u32 req_buf_size, version;

	if (len != sizeof(*tlv) - sizeof(struct btintel_pcie_tlv_hdr)) {
		BT_WARN("YoYo: buf alloc tlv is too short or Invalid");
		return -EBADMSG;
	}

	domain = get_unaligned_le32(&tlv->dbg_hdr.domain);
	version = get_unaligned_le32(&tlv->dbg_hdr.tlv_data_version);
	if (domain != BTINTEL_PCIE_DOMAIN_BT ||
	    version != BTINTEL_PCIE_BUF_ALLOC_TLV_VERSION) {
		BT_WARN("YoYo: unsupported buf allocation domain/version (%u/%u)",
			domain, version);
		return -EINVAL;
	}

	alloc_id = get_unaligned_le32(&tlv->alloc_id);
	if (alloc_id < BTINTEL_PCIE_ALLOC_ID_DBGC1 ||
	    alloc_id > BTINTEL_PCIE_ALLOC_ID_DBGC3) {
		BT_WARN("YoYo: invalid buf allocation id %u", alloc_id);
		return -EINVAL;
	}

	idx = alloc_id - BTINTEL_PCIE_ALLOC_ID_DBGC1;
	buf_location = get_unaligned_le32(&tlv->buf_location);
	max_num_frags = get_unaligned_le32(&tlv->max_num_frags);
	min_buf_size = get_unaligned_le32(&tlv->min_buf_size);
	req_buf_size = get_unaligned_le32(&tlv->req_buf_size);

	if (buf_location != BTINTEL_PCIE_BUF_LOC_DRAM) {
		BT_WARN("YoYo: buf allocation id=%u unsupported buffer location %u",
			alloc_id, buf_location);
		return -EINVAL;
	}

	if (!max_num_frags || max_num_frags > BTINTEL_PCIE_MAX_BUF_FRAGS ||
	    min_buf_size < BTINTEL_PCIE_MIN_BUF_SIZE ||
	    min_buf_size > BTINTEL_PCIE_MAX_BUF_SIZE ||
	    req_buf_size > BTINTEL_PCIE_MAX_BUF_SIZE ||
	    req_buf_size % max_num_frags ||
	    req_buf_size / max_num_frags < min_buf_size) {
		BT_WARN("YoYo: buf allocation id=%u req size=%u max frags=%u min size=%u",
			alloc_id, req_buf_size, max_num_frags, min_buf_size);
		return -EINVAL;
	}

	ctx->buf_alloc[idx].alloc_id = alloc_id;
	ctx->buf_alloc[idx].buf_location = buf_location;
	ctx->buf_alloc[idx].req_buf_size = req_buf_size;
	ctx->buf_alloc[idx].max_num_frags = max_num_frags;
	ctx->buf_alloc[idx].min_buf_size = min_buf_size;
	ctx->buf_alloc[idx].present = true;

	if (idx + 1 > ctx->num_buf_allocs)
		ctx->num_buf_allocs = idx + 1;

	BT_DBG("YoYo: buf allocation id=%u loc=%u req size=%u max frags=%u min size=%u",
	       alloc_id, ctx->buf_alloc[idx].buf_location,
	       ctx->buf_alloc[idx].req_buf_size,
	       ctx->buf_alloc[idx].max_num_frags,
	       ctx->buf_alloc[idx].min_buf_size);

	return 0;
}

static int btintel_pcie_yoyo_parse_config_set(struct btintel_pcie_yoyo_ctx *ctx,
					      const struct btintel_pcie_tlv_config_set *tlv,
					      u32 len)
{
	struct btintel_pcie_yoyo_config_set *cs;
	u32 fixed_size = sizeof(*tlv) - sizeof(struct btintel_pcie_tlv_hdr);
	u32 pairs_bytes, num_pairs, domain, version, time_point, config_set_type;

	if (len < fixed_size) {
		BT_WARN("YoYo: config set tlv too short or Invalid");
		return -EBADMSG;
	}

	domain = get_unaligned_le32(&tlv->dbg_hdr.domain);
	version = get_unaligned_le32(&tlv->dbg_hdr.tlv_data_version);
	if (domain != BTINTEL_PCIE_DOMAIN_BT ||
	    version != BTINTEL_PCIE_CONFIG_SET_TLV_VERSION) {
		BT_WARN("YoYo: unsupported domain/version (%u/%u)",
			domain, version);
		return 0;
	}

	time_point = get_unaligned_le32(&tlv->time_point);
	if (time_point != BTINTEL_PCIE_TP_EARLY) {
		BT_WARN("YoYo: config set unsupported time_point %u, skipping",
			time_point);
		return 0;
	}

	config_set_type = get_unaligned_le32(&tlv->config_set_type);
	if (config_set_type != BTINTEL_PCIE_CFGSET_CSR &&
	    config_set_type != BTINTEL_PCIE_CFGSET_PERIPH_MAC &&
	    config_set_type != BTINTEL_PCIE_CFGSET_DEVICE_MEM) {
		BT_WARN("YoYo: config set unsupported config_set_type %u, skipping",
			config_set_type);
		return 0;
	}

	/* Malformed pair data: skip this TLV, keep parsing the rest. */
	pairs_bytes = len - fixed_size;
	if (pairs_bytes % sizeof(struct btintel_pcie_addr_value)) {
		BT_WARN("YoYo: config set has an incomplete addr/value pair, skipping");
		return 0;
	}

	num_pairs = pairs_bytes / sizeof(struct btintel_pcie_addr_value);

	if (!num_pairs) {
		BT_WARN("YoYo: config set with no addr/value pairs, skipping");
		return 0;
	}

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs) {
		BT_WARN("YoYo: failed to allocate config set entry, disabling YoYo");
		/* -ENOMEM is fatal: load_and_parse() discards the whole configuration */
		return -ENOMEM;
	}

	cs->time_point = time_point;
	cs->config_set_type = config_set_type;
	cs->addr_offset = get_unaligned_le32(&tlv->addr_offset);
	cs->num_pairs = num_pairs;

	cs->pairs = kmemdup(tlv->addr_pair, pairs_bytes, GFP_KERNEL);
	if (!cs->pairs) {
		kfree(cs);
		BT_WARN("YoYo: failed to allocate config set pairs, disabling YoYo");
		return -ENOMEM;
	}

	BT_DBG("YoYo: config set tp=%u type=%u pairs=%u offset=0x%x",
	       cs->time_point, cs->config_set_type,
	       cs->num_pairs, cs->addr_offset);

	list_add_tail(&cs->list, &ctx->config_set_list);
	return 0;
}

static int btintel_pcie_yoyo_parse_region(struct btintel_pcie_yoyo_ctx *ctx,
					  const struct btintel_pcie_tlv_region *tlv,
					  u32 len)
{
	struct btintel_pcie_yoyo_region *old_region, *region, *tmp;
	u32 addr_count = 0, addr_offset = 0, domain, version;
	u32 addr_bytes, alloc_id, size;
	u16 region_id;

	if (len < sizeof(*tlv) - sizeof(struct btintel_pcie_tlv_hdr)) {
		BT_WARN("YoYo: region tlv is too short or Invalid");
		return -EBADMSG;
	}

	domain = get_unaligned_le32(&tlv->dbg_hdr.domain);
	version = get_unaligned_le32(&tlv->dbg_hdr.tlv_data_version);
	if (domain != BTINTEL_PCIE_DOMAIN_BT ||
	    version != BTINTEL_PCIE_REGION_TLV_VERSION) {
		BT_WARN("YoYo: unsupported region domain/version (%u/%u), skipping",
			domain, version);
		return 0;
	}

	region_id = get_unaligned_le16(&tlv->region_id);
	if (region_id > BTINTEL_PCIE_REGION_ID_MAX) {
		BT_WARN("YoYo: invalid region_id %u, skipping", region_id);
		return 0;
	}

	if (tlv->region_type <= BTINTEL_PCIE_REGION_INVALID ||
	    tlv->region_type >= BTINTEL_PCIE_REGION_TYPE_MAX) {
		BT_WARN("YoYo: invalid region type %u, skipping", tlv->region_type);
		return 0;
	}

	/* Any trailing bytes after the fixed region structure are an address
	 * list, regardless of region type, mirroring the reference parser.
	 */
	addr_offset = sizeof(*tlv) - sizeof(struct btintel_pcie_tlv_hdr);
	addr_bytes = len - addr_offset;
	if (addr_bytes % sizeof(__le32)) {
		BT_WARN("YoYo: invalid region addr_bytes length %u", addr_bytes);
		return 0;
	}

	addr_count = addr_bytes / sizeof(__le32);

	/* Size is checked only where the parser reads it; other types are
	 * validated by their dump code, as in the reference driver.
	 */
	size = sizeof(u32);
	switch (tlv->region_type) {
	case BTINTEL_PCIE_REGION_DEVICE_MEM:
		size = get_unaligned_le32(&tlv->conf_params.dev_addr.size_bytes);
		fallthrough;
	case BTINTEL_PCIE_REGION_PERIPH_MAC:
	case BTINTEL_PCIE_REGION_CSR:
		if (!addr_count) {
			BT_WARN("YoYo: region id=%u type=%u has no addresses, skipping",
				region_id, tlv->region_type);
			return 0;
		}
		break;
	case BTINTEL_PCIE_REGION_DRAM_BUF:
		alloc_id = get_unaligned_le32(&tlv->conf_params.dram_alloc_id);
		if (alloc_id < BTINTEL_PCIE_ALLOC_ID_DBGC1 ||
		    alloc_id > BTINTEL_PCIE_ALLOC_ID_DBGC3) {
			BT_WARN("YoYo: region id=%u invalid dram alloc id %u, skipping",
				region_id, alloc_id);
			return 0;
		}
		break;
	case BTINTEL_PCIE_REGION_INTERNAL_BUF:
		size = get_unaligned_le32(&tlv->conf_params.internal_buf.size_bytes);
		break;
	case BTINTEL_PCIE_REGION_SPECIAL_DEV_MEM:
		size = get_unaligned_le32(&tlv->conf_params.special_dev_addr.size_bytes);
		break;
	default:
		break;
	}

	/* Upper bound is applied by the dump path (BTINTEL_PCIE_REGION_MAX_SIZE) */
	if (!size || size % sizeof(u32)) {
		BT_WARN("YoYo: region id=%u type=%u invalid size %u, skipping",
			region_id, tlv->region_type, size);
		return 0;
	}

	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	region->region_id = region_id;
	region->dump_policy = get_unaligned_le16(&tlv->region_dump_policy);
	region->type = tlv->region_type;
	region->sub_type = tlv->region_sub_type;
	region->sub_type_ver = tlv->region_sub_type_ver;
	/* Fixed 32-byte name from the TLV, not NUL-terminated */
	memcpy(region->name, tlv->region_name, BTINTEL_PCIE_REGION_NAME_LEN);
	memcpy(&region->conf, &tlv->conf_params, sizeof(region->conf));

	if (addr_count) {
		u32 i;

		/* Root-supplied file; fail quietly instead of WARNing on huge lists */
		region->addrs = kmalloc_array(addr_count, sizeof(*region->addrs),
					      GFP_KERNEL | __GFP_NOWARN);
		if (!region->addrs) {
			kfree(region);
			return -ENOMEM;
		}

		for (i = 0; i < addr_count; i++)
			region->addrs[i] = get_unaligned_le32(&tlv->addrs[i]);
	}
	region->num_addrs = addr_count;

	/* Swap into list if duplicate region_id exists, otherwise append */
	list_for_each_entry_safe(old_region, tmp, &ctx->region_list, list) {
		if (old_region->region_id == region_id) {
			list_replace(&old_region->list, &region->list);
			kfree(old_region->addrs);
			kfree(old_region);
			goto out;
		}
	}

	list_add_tail(&region->list, &ctx->region_list);

out:
	BT_DBG("YoYo: region id=%u type=%u name='%.32s'",
	       region->region_id, region->type, region->name);
	return 0;
}

static int btintel_pcie_yoyo_parse_hcmd(struct btintel_pcie_yoyo_ctx *ctx,
					const struct btintel_pcie_tlv_hcmd *tlv,
					u32 len)
{
	u32 fixed_size = sizeof(*tlv) - sizeof(struct btintel_pcie_tlv_hdr);
	u32 cmd_len, time_point, period_msec, domain, version;
	struct btintel_pcie_yoyo_hcmd *hcmd;

	if (len < fixed_size) {
		BT_WARN("YoYo: hci cmd tlv is too short or Invalid");
		return -EBADMSG;
	}

	domain = get_unaligned_le32(&tlv->dbg_hdr.domain);
	version = get_unaligned_le32(&tlv->dbg_hdr.tlv_data_version);
	if (domain != BTINTEL_PCIE_DOMAIN_BT ||
	    version != BTINTEL_PCIE_HCMD_TLV_VERSION) {
		BT_WARN("YoYo: unsupported hcmd domain/version (%u/%u), skipping",
			domain, version);
		return 0;
	}

	time_point = get_unaligned_le32(&tlv->time_point);
	if (time_point != BTINTEL_PCIE_TP_AFTER_ALIVE) {
		BT_WARN("YoYo: skipping hcmd for timepoint %u", time_point);
		return 0;
	}

	cmd_len = len - fixed_size;
	if (cmd_len < 3 || (cmd_len - 3) > 255) {
		BT_WARN("YoYo: invalid HCMD payload length (%u)", cmd_len);
		return 0;
	}

	period_msec = get_unaligned_le32(&tlv->period_msec);
	if (period_msec) {
		BT_WARN("YoYo: periodic hcmd not supported (period=%u ms), skipping",
			period_msec);
		return 0;
	}

	hcmd = kzalloc_obj(*hcmd, GFP_KERNEL);
	if (!hcmd)
		return -ENOMEM;

	hcmd->time_point = time_point;
	hcmd->period_msec = period_msec;
	hcmd->cmd_len = cmd_len;

	hcmd->cmd_data = kmemdup(tlv->cmd_data, cmd_len, GFP_KERNEL);
	if (!hcmd->cmd_data) {
		kfree(hcmd);
		return -ENOMEM;
	}

	BT_DBG("YoYo: hcmd tp=%u period=%u cmd_len=%u",
	       hcmd->time_point, hcmd->period_msec, hcmd->cmd_len);

	list_add_tail(&hcmd->list, &ctx->hcmd_list);
	return 0;
}

/*
 * Parse the optional YoYo firmware TLV stream and validate each record.
 * This is the entry point for the runtime debug configuration payload.
 */
static int btintel_pcie_yoyo_parse_tlv_buffer(struct btintel_pcie_yoyo_ctx *ctx,
					      const u8 *buf, size_t buf_len)
{
	const struct btintel_pcie_tlv_hdr *tlv;
	const u8 *ptr = buf;
	size_t remaining = buf_len;
	u32 count = 0;
	int ret = 0;

	while (remaining >= sizeof(*tlv)) {
		size_t tlv_size;
		u32 type, len;

		tlv = (const struct btintel_pcie_tlv_hdr *)ptr;
		type = get_unaligned_le32(&tlv->type);
		len = get_unaligned_le32(&tlv->length);

		if (len > remaining - sizeof(*tlv)) {
			BT_ERR("YoYo: tlv %u truncated (len=%u rem=%zu)", count,
			       len, remaining);
			return -EBADMSG;
		}
		tlv_size = sizeof(*tlv) + len;

		switch (type) {
		case BTINTEL_PCIE_TLV_TYPE_DBG_INFO:
			ret = btintel_pcie_yoyo_parse_dbg_info(ctx,
							       (const void *)tlv, len);
			if (ret) {
				ctx->dbg_info_present = false;
			}
			break;
		case BTINTEL_PCIE_TLV_TYPE_DBG_BUF_ALLOC:
			ret = btintel_pcie_yoyo_parse_buf_alloc(ctx,
								(const void *)tlv, len);
			break;
		case BTINTEL_PCIE_TLV_TYPE_DBG_CONFIG_SET:
			ret = btintel_pcie_yoyo_parse_config_set(ctx, (const void *)tlv, len);
			break;
		case BTINTEL_PCIE_TLV_TYPE_DBG_REGION:
			ret = btintel_pcie_yoyo_parse_region(ctx, (const void *)tlv, len);
			break;
		case BTINTEL_PCIE_TLV_TYPE_DBG_HCMD:
			ret = btintel_pcie_yoyo_parse_hcmd(ctx, (const void *)tlv, len);
			break;
		case BTINTEL_PCIE_TLV_TYPE_DBG_TRIGGER:
		case BTINTEL_PCIE_TLV_TYPE_DBG_PRESET_OVERRIDE:
			BT_DBG("YoYo: valid tlv type 0x%x len=%u", type, len);
			break;
		default: /* Log and continue, do not fail*/
			BT_DBG("YoYo: unknown tlv type 0x%x len=%u", type, len);
			break;
		}

		ptr += tlv_size;
		remaining -= tlv_size;

		if (ret) {
			BT_ERR("YoYo: error parsing tlv type 0x%x (ret=%d)", type, ret);
			return ret;
		}

		count++;
	}

	/* If no TLVs were parsed, the YoYo binary is considered invalid */
	if (remaining || count == 0) {
		BT_ERR("YoYo: trailing %zu bytes after tlv stream", remaining);
		return -EBADMSG;
	}

	BT_DBG("YoYo: parsed %u tlv's", count);
	return 0;
}

/**
 * btintel_pcie_yoyo_init - Initialize the YoYo context
 * @ctx:   Pre-allocated context (typically embedded in driver data)
 */
int btintel_pcie_yoyo_init(struct btintel_pcie_yoyo_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	mutex_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->region_list);
	INIT_LIST_HEAD(&ctx->trigger_list);
	INIT_LIST_HEAD(&ctx->hcmd_list);
	INIT_LIST_HEAD(&ctx->config_set_list);

	/* set it to true after successful TLV parsing */
	ctx->enabled = false;

	return 0;
}
EXPORT_SYMBOL_GPL(btintel_pcie_yoyo_init);

/**
 * btintel_pcie_yoyo_cleanup - Clean up the YoYo context
 * @ctx:  YoYo context to clean up
 */
void btintel_pcie_yoyo_cleanup(struct btintel_pcie_yoyo_ctx *ctx)
{
	struct btintel_pcie_yoyo_config_set *config_set, *config_tmp;
	struct btintel_pcie_yoyo_region *region, *region_tmp;
	struct btintel_pcie_yoyo_hcmd *hcmd, *hcmd_tmp;

	if (!ctx)
		return;

	mutex_lock(&ctx->lock);
	ctx->enabled = false;
	ctx->dbg_info_present = false;
	ctx->num_buf_allocs = 0;
	memset(ctx->buf_alloc, 0, sizeof(ctx->buf_alloc));

	ctx->hdev = NULL;

	list_for_each_entry_safe(config_set, config_tmp, &ctx->config_set_list, list) {
		list_del(&config_set->list);
		kfree(config_set->pairs);
		kfree(config_set);
	}

	list_for_each_entry_safe(region, region_tmp, &ctx->region_list, list) {
		list_del(&region->list);
		kfree(region->addrs);
		kfree(region);
	}

	list_for_each_entry_safe(hcmd, hcmd_tmp, &ctx->hcmd_list, list) {
		list_del(&hcmd->list);
		kfree(hcmd->cmd_data);
		kfree(hcmd);
	}
	mutex_unlock(&ctx->lock);
}
EXPORT_SYMBOL_GPL(btintel_pcie_yoyo_cleanup);

/**
 * btintel_pcie_yoyo_load_and_parse - Load ibt_debug_yoyo.bin and parse TLVs
 * @ctx:  Initialized YoYo context
 * @dev:  Device for firmware loading (typically &pdev->dev)
 *
 * Uses request_firmware_direct, since the YoYo binary
 * is optional. On success, sets ctx->enabled.
 */
int btintel_pcie_yoyo_load_and_parse(struct btintel_pcie_yoyo_ctx *ctx,
				     struct device *dev)
{
	const struct firmware *fw;
	int ret;

	if (!ctx || !dev)
		return -EINVAL;

	ret = request_firmware_direct(&fw, BTINTEL_PCIE_YOYO_FW_NAME, dev);
	if (ret) {
		BT_WARN("YoYo: failed to load %s (%d)",
			BTINTEL_PCIE_YOYO_FW_NAME, ret);
		return ret;
	}

	/* Sanity check firmware size */
	if (fw->size < sizeof(struct btintel_pcie_tlv_hdr)) {
		release_firmware(fw);
		return -EBADMSG;
	}

	BT_DBG("YoYo: loaded %s (%zu bytes)", BTINTEL_PCIE_YOYO_FW_NAME,
	       fw->size);

	ret = btintel_pcie_yoyo_parse_tlv_buffer(ctx, fw->data, fw->size);
	release_firmware(fw);

	/* File Corruption / TLV validation failed */
	if (ret) {
		BT_WARN("YoYo: tlv parsing failed (%d)", ret);
		btintel_pcie_yoyo_cleanup(ctx);
		return ret;
	}

	/* DEBUG_INFO and buffer allocation TLVs are mandatory */
	if (!ctx->dbg_info_present || !ctx->num_buf_allocs) {
		BT_WARN("YoYo: mandatory tlv is missing, using legacy DBGC defaults");
		btintel_pcie_yoyo_cleanup(ctx);
		return -EBADMSG;
	}

	ctx->enabled = true;

	BT_INFO("YoYo (BDF - %s): feature enabled and configured", dev_name(dev));
	return 0;
}
EXPORT_SYMBOL_GPL(btintel_pcie_yoyo_load_and_parse);

/**
 * btintel_pcie_yoyo_get_buf_alloc - Query buffer allocation config for a DBGC
 * @ctx: YoYo context
 * @alloc_id: Allocation ID (1=DBGC1, 2=DBGC2, 3=DBGC3)
 *
 * Return the parsed configuration, or NULL if no matching TLV was present.
 */
const struct btintel_pcie_buf_alloc *
btintel_pcie_yoyo_get_buf_alloc(struct btintel_pcie_yoyo_ctx *ctx, u32 alloc_id)
{
	u32 idx;

	if (!ctx || !ctx->enabled ||
	    alloc_id < BTINTEL_PCIE_ALLOC_ID_DBGC1 ||
	    alloc_id > BTINTEL_PCIE_ALLOC_ID_DBGC3)
		return NULL;

	idx = alloc_id - BTINTEL_PCIE_ALLOC_ID_DBGC1;
	if (!ctx->buf_alloc[idx].present)
		return NULL;

	return &ctx->buf_alloc[idx];
}
EXPORT_SYMBOL_GPL(btintel_pcie_yoyo_get_buf_alloc);

MODULE_DESCRIPTION("Intel Bluetooth PCIe Debug Framework");
MODULE_LICENSE("GPL");
