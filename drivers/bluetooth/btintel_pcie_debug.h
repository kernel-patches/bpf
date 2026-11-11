/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Intel Bluetooth PCIe Debug Framework
 *
 * Copyright (C) 2026 Intel Corporation
 *
 */

#ifndef __BTINTEL_PCIE_DEBUG_H__
#define __BTINTEL_PCIE_DEBUG_H__

#include <linux/list.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/firmware.h>

struct btintel_pcie_data;

#define BTINTEL_PCIE_DBG_INI_FILE	"ibt_bt_dbg_cfg.ini"

/* FATAL_ERR_TESTMODE: B0 enable, B1 context, B2 type, B3 reserved. */
#define BTINTEL_PCIE_FATAL_ERR_ENABLE(v)	((u8)((v) & 0xff))
#define BTINTEL_PCIE_FATAL_ERR_CONTEXT(v)	((u8)(((v) >> 8) & 0xff))
#define BTINTEL_PCIE_FATAL_ERR_TYPE(v)	((u8)(((v) >> 16) & 0xff))

#define BTINTEL_PCIE_DEBUG_EXCEPTION_CONTEXT_THREAD	0x00
#define BTINTEL_PCIE_DEBUG_EXCEPTION_CONTEXT_IRQ		0x01
#define BTINTEL_PCIE_DEBUG_EXCEPTION_CONTEXT_RFKILL	0x02
#define BTINTEL_PCIE_DEBUG_EXCEPTION_FAILURE_TYPE_DEFAULT	0x00

struct btintel_pcie_fatal_err_cfg {
	bool	testmode_enabled;
	u8	context;
	u8	type;
};

void btintel_pcie_load_dbg_path_from_ini(struct btintel_pcie_data *data);
void btintel_pcie_fatal_err_init(struct btintel_pcie_data *data);
void btintel_pcie_fatal_err_load(struct btintel_pcie_data *data);
void btintel_pcie_fatal_err_check_api_lock(struct btintel_pcie_data *data,
					   bool api_lock);
bool btintel_pcie_fatal_err_handle_rfkill(struct btintel_pcie_data *data,
					  bool rfkill_on);
bool btintel_pcie_fatal_err_post_setup_pending(struct btintel_pcie_data *data);
bool btintel_pcie_fatal_err_testmode_active(struct btintel_pcie_data *data);

/* External YoYo binary file */
#define BTINTEL_PCIE_YOYO_FW_NAME	"intel/ibt_debug_yoyo.bin"

/* TLV type codes */
#define BTINTEL_PCIE_TLV_TYPE_DBG_INFO			0x1000005
#define BTINTEL_PCIE_TLV_TYPE_DBG_BUF_ALLOC		0x1000006
#define BTINTEL_PCIE_TLV_TYPE_DBG_HCMD			0x1000007
#define BTINTEL_PCIE_TLV_TYPE_DBG_REGION		0x1000008
#define BTINTEL_PCIE_TLV_TYPE_DBG_TRIGGER		0x1000009
#define BTINTEL_PCIE_TLV_TYPE_DBG_CONFIG_SET		0x100000A
#define BTINTEL_PCIE_TLV_TYPE_DBG_PRESET_OVERRIDE	0x100000B

/* Supported TLV type versions */
#define BTINTEL_PCIE_DBG_INFO_TLV_VERSION	2
#define BTINTEL_PCIE_BUF_ALLOC_TLV_VERSION	1
#define BTINTEL_PCIE_CONFIG_SET_TLV_VERSION	1
#define BTINTEL_PCIE_REGION_TLV_VERSION		3

/* Debug Info TLV */
#define BTINTEL_PCIE_CONFIG_NAME_LEN		64
#define BTINTEL_PCIE_DOMAIN_BT			0
#define BTINTEL_PCIE_CORE_TYPE_BT		1
/* Buffer allocation TLV */
#define BTINTEL_PCIE_MAX_BUF_ALLOC		3
#define BTINTEL_PCIE_MAX_BUF_FRAGS		16
#define BTINTEL_PCIE_MIN_BUF_SIZE		(32 * 1024)
#define BTINTEL_PCIE_MAX_BUF_SIZE		(4 * 1024 * 1024)
/* Region Tlv */
#define BTINTEL_PCIE_REGION_ID_MAX		63
#define BTINTEL_PCIE_REGION_NAME_LEN		32

enum btintel_pcie_image_tlv_type {
	BTINTEL_PCIE_IMAGE_TLV_TYPE_EXTERNAL	= 0x1,
	BTINTEL_PCIE_IMAGE_TLV_TYPE_INTERNAL	= 0x2,
	BTINTEL_PCIE_IMAGE_TLV_TYPE_UNKNOWN	= 0xff,
};

/* Allocation IDs */
enum btintel_dbg_alloc_id {
	BTINTEL_PCIE_ALLOC_ID_INVALID		= 0,
	BTINTEL_PCIE_ALLOC_ID_DBGC1		= 1,
	BTINTEL_PCIE_ALLOC_ID_DBGC2		= 2,
	BTINTEL_PCIE_ALLOC_ID_DBGC3		= 3,
	BTINTEL_PCIE_ALLOC_ID_MAX,
};

/* Buffer locations */
enum btintel_dbg_buf_location {
	BTINTEL_PCIE_BUF_LOC_INVALID		= 0,
	BTINTEL_PCIE_BUF_LOC_SRAM		= 1,
	BTINTEL_PCIE_BUF_LOC_DRAM		= 2,
	BTINTEL_PCIE_BUF_LOC_NPK		= 3,
	BTINTEL_PCIE_BUF_LOC_MAX,
};

/* Config set types */
enum btintel_pcie_dbg_config_set_type {
	BTINTEL_PCIE_CFGSET_INVALID		= 0,
	BTINTEL_PCIE_CFGSET_PERIPH_MAC		= 1,
	BTINTEL_PCIE_CFGSET_PERIPH_PHY		= 2,
	BTINTEL_PCIE_CFGSET_PERIPH_AUX		= 3,
	BTINTEL_PCIE_CFGSET_DEVICE_MEM		= 4,
	BTINTEL_PCIE_CFGSET_CSR			= 5,
	BTINTEL_PCIE_CFGSET_DBGC_DRAM_ADDR	= 6,
	BTINTEL_PCIE_CFGSET_PERIPH_SCRATCH	= 7,
	BTINTEL_PCIE_CFGSET_MAX,
};

/* Types of Timepoints */
enum btintel_pcie_dbg_timepoint {
	BTINTEL_PCIE_TP_INVALID			= 0,
	BTINTEL_PCIE_TP_EARLY			= 1,
	BTINTEL_PCIE_TP_AFTER_ALIVE		= 2,
	BTINTEL_PCIE_TP_POST_INIT		= 3,
	BTINTEL_PCIE_TP_FW_ASSERT		= 4,
	BTINTEL_PCIE_TP_FW_HW_ERROR		= 5,
	BTINTEL_PCIE_TP_FW_TFD_Q_HANG		= 6,
	BTINTEL_PCIE_TP_FW_DHC_NOTIF		= 7,
	BTINTEL_PCIE_TP_FW_RSP_OR_NOTIF		= 8,
	BTINTEL_PCIE_TP_USER_TRIGGER		= 9,
	BTINTEL_PCIE_TP_PERIODIC		= 10,
	BTINTEL_PCIE_TP_RESERVED		= 11,
	BTINTEL_PCIE_TP_HOST_ASSERT		= 12,
	BTINTEL_PCIE_TP_HOST_ALIVE_TIMEOUT	= 13,
	BTINTEL_PCIE_TP_HOST_DEVICE_DISABLE	= 15,
	BTINTEL_PCIE_TP_HOST_D3_START		= 16,
	BTINTEL_PCIE_TP_HOST_D3_END		= 17,
	BTINTEL_PCIE_TP_MAX_NUM,
};

/* Region types */
enum btintel_pcie_dbg_region_type {
	BTINTEL_PCIE_REGION_INVALID		= 0,
	BTINTEL_PCIE_REGION_TLV		= 1,
	BTINTEL_PCIE_REGION_INTERNAL_BUF	= 2,
	BTINTEL_PCIE_REGION_DRAM_BUF		= 3,
	BTINTEL_PCIE_REGION_DEVICE_TXFIFO	= 4,
	BTINTEL_PCIE_REGION_DEVICE_RXFIFO	= 5,
	BTINTEL_PCIE_REGION_LMAC_ERROR_TBL	= 6,
	BTINTEL_PCIE_REGION_UMAC_ERROR_TBL	= 7,
	BTINTEL_PCIE_REGION_FW_RSP_OR_NOTIF	= 8,
	BTINTEL_PCIE_REGION_DEVICE_MEM		= 9,
	BTINTEL_PCIE_REGION_PERIPH_MAC		= 10,
	BTINTEL_PCIE_REGION_PERIPH_PHY		= 11,
	BTINTEL_PCIE_REGION_PERIPH_AUX		= 12,
	BTINTEL_PCIE_REGION_VM			= 13,
	BTINTEL_PCIE_REGION_CSR			= 14,
	BTINTEL_PCIE_REGION_DRAM_IMR		= 15,
	BTINTEL_PCIE_REGION_PCI_IOSF_CFG	= 16,
	BTINTEL_PCIE_REGION_SPECIAL_DEV_MEM	= 17,
	BTINTEL_PCIE_REGION_DBGI_SRAM		= 18,
	BTINTEL_PCIE_REGION_TYPE_MAX
};

/*
 * Region dump policy flags for OS dump-size limits.
 * @BTINTEL_PCIE_REGION_POLICY_NO_LIMIT: OS has no dump-size limit
 * @BTINTEL_PCIE_REGION_POLICY_MAX_600KB: Wi-Fi LKD dump request
 * @BTINTEL_PCIE_REGION_POLICY_MAX_5MB: Microsoft BSOD/LKD dump request
 */
enum btintel_pcie_dbg_region_policy {
	BTINTEL_PCIE_REGION_POLICY_NO_LIMIT	= BIT(0),
	BTINTEL_PCIE_REGION_POLICY_MAX_600KB	= BIT(1),
	BTINTEL_PCIE_REGION_POLICY_MAX_5MB	= BIT(2),
};

/* TLV header */
struct btintel_pcie_tlv_hdr {
	__le32 type;
	__le32 length;
} __packed;

/* Debug header common to all debug TLVs */
struct btintel_pcie_dbg_hdr {
	__le32 tlv_data_version;
	__le32 domain;
} __packed;

/* Address/value pair */
struct btintel_pcie_addr_value {
	__le32 address;
	__le32 value;
} __packed;

/*
 * struct btintel_pcie_tlv_dbg_info - YoYo DEBUG_INFO TLV
 * @hdr: TLV type and payload length
 * @dbg_hdr: Debug TLV version and domain
 * @image_type: Firmware image type
 * @core_type: Firmware core type
 * @config_name: Fixed-size name of the firmware configuration
 *
 * Describes the firmware image targeted by the YoYo configuration. Fields
 * are stored in little-endian format in the packed firmware TLV.
 */
struct btintel_pcie_tlv_dbg_info {
	struct btintel_pcie_tlv_hdr hdr;
	struct btintel_pcie_dbg_hdr dbg_hdr;
	__le32 image_type;
	__le32 core_type;
	u8 config_name[BTINTEL_PCIE_CONFIG_NAME_LEN];
} __packed;

/*
 * struct btintel_pcie_tlv_buf_alloc - YoYo buffer allocation TLV
 * @hdr: Common TLV header
 * @dbg_hdr: Debug TLV version and domain
 * @alloc_id: DBGC allocation identifier (DBGC1..DBGC3)
 * @buf_location: Requested buffer location (SRAM / DRAM / NPK)
 * @req_buf_size: Total requested allocation size in bytes
 * @max_num_frags: Maximum number of buffer fragments (1..16)
 * @min_buf_size: Minimum buffer size in bytes
 *
 * Describes the buffer sizing override for one DBGC allocation.
 */
struct btintel_pcie_tlv_buf_alloc {
	struct btintel_pcie_tlv_hdr hdr;
	struct btintel_pcie_dbg_hdr dbg_hdr;
	__le32 alloc_id;
	__le32 buf_location;
	__le32 req_buf_size;
	__le32 max_num_frags;
	__le32 min_buf_size;
} __packed;

/*
 * struct btintel_pcie_tlv_config_set - YoYo configuration-set TLV
 * @hdr: Common TLV type and payload length
 * @dbg_hdr: Debug TLV version and domain
 * @time_point: Timepoint at which to apply this configuration
 * @config_set_type: Target register or memory space
 * @addr_offset: Offset added to each address/value pair address
 * @addr_pair: Variable-length array of address/value pairs
 *
 * Describes configuration values to apply at a specified timepoint. Fields
 * are stored in little-endian format in the packed firmware TLV.
 */
struct btintel_pcie_tlv_config_set {
	struct btintel_pcie_tlv_hdr hdr;
	struct btintel_pcie_dbg_hdr dbg_hdr;
	__le32 time_point;
	__le32 config_set_type;
	__le32 addr_offset;
	struct btintel_pcie_addr_value addr_pair[];
} __packed;

/* Device address for region conf params */
struct btintel_pcie_tlv_dev_addr {
	__le32 size_bytes;
	__le32 addr_offset;
} __packed;

/* Special device address */
struct btintel_pcie_tlv_special_dev_addr {
	__le16 special_addr_type;
	__le16 struct_version;
	__le32 base_addr;
	__le32 size_bytes;
	__le32 addr_offset;
} __packed;

/* FIFOs */
struct btintel_pcie_tlv_fifos {
	__le32 fifo_ids[2];
	__le32 skip_data;
	__le32 addr_offset;
} __packed;

/* Error table */
struct btintel_pcie_tlv_error_table {
	__le32 struct_version;
	__le32 base_addr;
	__le32 size_bytes;
	__le32 addr_offset;
} __packed;

/* Internal buffer */
struct btintel_pcie_tlv_internal_buf {
	__le32 alloc_id;
	__le32 base_addr;
	__le32 size_bytes;
} __packed;

/* Region conf params union */
union btintel_pcie_region_conf_params {
	struct btintel_pcie_tlv_dev_addr	dev_addr;
	struct btintel_pcie_tlv_special_dev_addr special_dev_addr;
	struct btintel_pcie_tlv_fifos	fifos;
	struct btintel_pcie_tlv_error_table	error_table;
	struct btintel_pcie_tlv_internal_buf internal_buf;
	__le32				dram_alloc_id;
	__le32				tlv_output_bitmask;
} __packed;

/*
 * struct btintel_pcie_tlv_region - YoYo debug region TLV
 * @hdr: Common TLV type and payload length
 * @dbg_hdr: Debug TLV version and domain
 * @region_id: Identifier used to select this region for a trigger
 * @region_dump_policy: Policy flags controlling dump size limits
 * @region_type: Region storage or access type
 * @region_sub_type: Region-specific subtype
 * @region_sub_type_ver: Version of the region subtype data
 * @reserved: Reserved for future use
 * @region_name: Fixed-size region name
 * @conf_params: Type-specific fixed configuration parameters
 * @addrs: Variable-length address list for address-based region types
 *
 * Describes a debug region in the packed firmware TLV. Address-based region
 * types may append a variable-length address array after @conf_params.
 * Multi-byte fields are stored in little-endian format.
 */
struct btintel_pcie_tlv_region {
	struct btintel_pcie_tlv_hdr hdr;
	struct btintel_pcie_dbg_hdr dbg_hdr;
	__le16 region_id;
	__le16 region_dump_policy;
	u8     region_type;
	u8     region_sub_type;
	u8     region_sub_type_ver;
	u8     reserved;
	u8     region_name[BTINTEL_PCIE_REGION_NAME_LEN];
	union  btintel_pcie_region_conf_params conf_params;
	__le32 addrs[];
} __packed;

/* Parsed buffer allocation entry in the YoYo context */
struct btintel_pcie_buf_alloc {
	u32	alloc_id;
	u32	buf_location;
	u32	req_buf_size;
	u32	max_num_frags;
	u32	min_buf_size;
	bool	present;
};

/* Parsed config set entry in yoyo ctx */
struct btintel_pcie_yoyo_config_set {
	struct list_head		list;
	u32				time_point;
	u32				config_set_type;
	u32				addr_offset;
	u32				num_pairs;
	struct btintel_pcie_addr_value	*pairs;
};

/* Parsed region entry */
struct btintel_pcie_yoyo_region {
	struct list_head	list;
	u16			region_id;
	u16			dump_policy;
	u8			type;
	u8			sub_type;
	u8			sub_type_ver;
	char		name[BTINTEL_PCIE_REGION_NAME_LEN];
	u32			num_addrs;
	u32			*addrs;
	union btintel_pcie_region_conf_params conf;
};

/*
 * struct btintel_pcie_yoyo_ctx - Runtime state for YoYo debug configuration
 * @enabled: Whether the loaded YoYo configuration passed validation
 * @dbg_info_present: Whether the mandatory DEBUG_INFO TLV was validated
 * @region_list: Parsed debug-region entries
 * @trigger_list: Parsed debug-trigger entries
 * @hcmd_list: Parsed HCI command entries
 * @config_set_list: Parsed configuration-set entries
 * @buf_alloc: Parsed buffer allocation entries
 * @num_buf_allocs: Number of parsed buffer allocation entries
 * @hdev: Associated HCI device; NULL until successful HCI registration
 *
 * Stores the validation state and parsed TLV data for the optional YoYo
 * firmware configuration.
 */
struct btintel_pcie_yoyo_ctx {
	bool			 enabled;
	bool			 dbg_info_present;
	struct list_head	 region_list;
	struct list_head	 trigger_list;
	struct list_head	 hcmd_list;
	struct list_head	 config_set_list;
	struct btintel_pcie_buf_alloc buf_alloc[BTINTEL_PCIE_MAX_BUF_ALLOC];
	int			 num_buf_allocs;
	struct hci_dev		 *hdev;
};

int  btintel_pcie_yoyo_init(struct btintel_pcie_yoyo_ctx *ctx);
void btintel_pcie_yoyo_cleanup(struct btintel_pcie_yoyo_ctx *ctx);

/* Load and parse the external .bin file */
int  btintel_pcie_yoyo_load_and_parse(struct btintel_pcie_yoyo_ctx *ctx,
				      struct device *dev);

const struct btintel_pcie_buf_alloc *
btintel_pcie_yoyo_get_buf_alloc(struct btintel_pcie_yoyo_ctx *ctx, u32 alloc_id);

#endif /* __BTINTEL_PCIE_DEBUG_H__ */
