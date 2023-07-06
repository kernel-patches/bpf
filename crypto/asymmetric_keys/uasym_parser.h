/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header file of user asymmetric keys and signatures.
 */

#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>

#include <uapi/linux/uasym_parser.h>

#define kenter(FMT, ...) \
	pr_debug("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_debug("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

typedef int (*parse_callback)(void *, enum fields, const u8 *, u32);

extern const char *data_types_str[];
extern const char *fields_str[];

int uasym_parse_hdr(const u8 **data, size_t *data_len, u8 *data_type,
		    u16 *num_fields, u64 *total_len);
int uasym_parse_data(parse_callback callback, void *callback_data,
		     u16 num_fields, const u8 *data, size_t data_len);
int uasym_parse(enum data_types expected_data_type, parse_callback callback,
		void *callback_data, const u8 *data, size_t data_len);

int parse_key_algo(const char **pkey_algo, enum fields field,
		   const u8 *field_data, u32 field_data_len);
int parse_key_kid(struct asymmetric_key_id **id, enum fields field,
		  const u8 *data, u32 data_len);
