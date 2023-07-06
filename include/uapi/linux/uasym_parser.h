/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the user space interface for user asymmetric keys and signatures.
 */

#ifndef _UAPI_LINUX_UASYM_PARSER_H
#define _UAPI_LINUX_UASYM_PARSER_H

#include <linux/types.h>
#include <linux/pub_key_info.h>

/*
 * User asymmmetric key and signature format:
 *
 * +----------------+-----------------+-----------------+
 * | data type (u8) | num fields (u16)| total len (u64) |
 * +--------------+-+----------+------+-----------+-----+
 * | field1 (u16) | len1 (u32) | value1 (u8 len1) |
 * +--------------+------------+------------------+
 * |     ...      |    ...     |        ...       |
 * +--------------+------------+------------------+
 * | fieldN (u16) | lenN (u32) | valueN (u8 lenN) |
 * +--------------+------------+------------------+
 */

/**
 * struct uasym_hdr - Header of user asymmetric keys and signatures
 * @data_type: Type of data to parse
 * @_reserved0: Reserved for future use
 * @num_fields: Number of fields provided
 * @_reserved1: Reserved for future use
 * @total_len: Total length of the data blob, excluding the header
 *
 * This structure represents the header of the user asymmetric keys and
 * signatures format.
 */
struct uasym_hdr {
	__u8 data_type;
	__u8 _reserved0;
	__u16 num_fields;
	__u32 _reserved1;
	__u64 total_len;
} __packed;

/**
 * struct uasym_entry - Data entry of user asymmetric keys and signatures
 * @field: Data field identifier
 * @length: Data length
 * @data: Data
 *
 * This structure represents a TLV entry of the data part of the user
 * asymmetric keys and signatures format.
 */
struct uasym_entry {
	__u16 field;
	__u32 length;
	__u8 data[];
} __packed;

#define FOR_EACH_DATA_TYPE(DATA_TYPE) \
	DATA_TYPE(TYPE_KEY) \
	DATA_TYPE(TYPE__LAST)

#define FOR_EACH_FIELD(FIELD) \
	FIELD(KEY_PUB) \
	FIELD(KEY_ALGO) \
	FIELD(KEY_KID0) \
	FIELD(KEY_KID1) \
	FIELD(KEY_KID2) \
	FIELD(KEY_DESC) \
	FIELD(FIELD__LAST)

#define GENERATE_ENUM(ENUM) ENUM,
#define GENERATE_STRING(STRING) #STRING,

/**
 * enum data_types - Type of data to parse
 *
 * Enumerates the type of data to parse.
 */
enum data_types {
	FOR_EACH_DATA_TYPE(GENERATE_ENUM)
};

/**
 * enum fields - Data fields
 *
 * Enumerates the data fields. Some belongs to keys, some to signatures.
 */
enum fields {
	FOR_EACH_FIELD(GENERATE_ENUM)
};

#endif /* _UAPI_LINUX_UASYM_PARSER_H */
