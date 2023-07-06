// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the user asymmetric keys and signature parser.
 */

#define pr_fmt(fmt) "UASYM PARSER: "fmt

#include "uasym_parser.h"

const char *data_types_str[] = {
	FOR_EACH_DATA_TYPE(GENERATE_STRING)
};

const char *fields_str[] = {
	FOR_EACH_FIELD(GENERATE_STRING)
};

/**
 * uasym_parse_hdr - Parse a user asymmetric key or signature header
 * @data: Data to parse (updated)
 * @data_len: Length of @data (updated)
 * @data_type: Data type (updated)
 * @num_fields: Data fields (updated)
 * @total_len: Length of key or signature, excluding the header (updated)
 *
 * Parse the header of a user asymmetric key or signature, update the data
 * pointer and length, and provide the data type, number of fields and the
 * length of that element.
 *
 * Return: Zero on success, a negative value on error.
 */
int uasym_parse_hdr(const u8 **data, size_t *data_len, u8 *data_type,
		    u16 *num_fields, u64 *total_len)
{
	struct uasym_hdr *hdr;

	if (*data_len < sizeof(*hdr)) {
		pr_debug("Data blob too short, %lu bytes, expected %lu\n",
			 *data_len, sizeof(*hdr));
		return -EBADMSG;
	}

	hdr = (struct uasym_hdr *)*data;

	*data += sizeof(*hdr);
	*data_len -= sizeof(*hdr);

	*data_type = hdr->data_type;
	if (*data_type >= TYPE__LAST) {
		pr_debug("Invalid data type %u\n", *data_type);
		return -EBADMSG;
	}

	if (hdr->_reserved0 != 0) {
		pr_debug("_reserved0 must be zero\n");
		return -EBADMSG;
	}

	*num_fields = be16_to_cpu(hdr->num_fields);
	if (*num_fields >= FIELD__LAST) {
		pr_debug("Too many fields %u, max: %u\n", *num_fields,
			 FIELD__LAST);
		return -EBADMSG;
	}

	if (hdr->_reserved1 != 0) {
		pr_debug("_reserved1 must be zero\n");
		return -EBADMSG;
	}

	*total_len = be64_to_cpu(hdr->total_len);
	if (*total_len > *data_len) {
		pr_debug("Invalid total length %llu, expected: %lu\n",
			 *total_len, *data_len);
		return -EBADMSG;
	}

	pr_debug("Header: type: %s, num fields: %d, total len: %lld\n",
		 data_types_str[hdr->data_type], *num_fields, *total_len);

	return 0;
}

/**
 * uasym_parse_data - Parse a user asymmetric key or signature data
 * @callback: Callback function to call to parse the fields
 * @callback_data: Opaque data to supply to the callback function
 * @num_fields: Data fields
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * Parse the data part of a user asymmetric key or signature and call the
 * supplied callback function for each data field, passing also the opaque
 * data pointer.
 *
 * Return: Zero on success, a negative value on error.
 */
int uasym_parse_data(parse_callback callback, void *callback_data,
		     u16 num_fields, const u8 *data, size_t data_len)
{
	const u8 *data_ptr = data;
	struct uasym_entry *entry;
	u16 field;
	u32 len;
	int ret, i;

	for (i = 0; i < num_fields; i++) {
		if (data_len < sizeof(*entry))
			return -EBADMSG;

		entry = (struct uasym_entry *)data_ptr;
		data_ptr += sizeof(*entry);
		data_len -= sizeof(*entry);

		field = be16_to_cpu(entry->field);
		len = be32_to_cpu(entry->length);

		if (data_len < len)
			return -EBADMSG;

		pr_debug("Data: field: %s, len: %d\n", fields_str[field], len);

		if (!len)
			continue;

		ret = callback(callback_data, field, data_ptr, len);
		if (ret < 0) {
			pr_debug("Parsing of field %s failed, ret: %d\n",
				 fields_str[field], ret);
			return -EBADMSG;
		}

		data_ptr += len;
		data_len -= len;
	}

	if (data_len) {
		pr_debug("Excess data: %ld bytes\n", data_len);
		return -EBADMSG;
	}

	return 0;
}

/**
 * uasym_parse - Parse a user asymmetric key or signature
 * @expected_data_type: Desired data type
 * @callback: Callback function to call to parse the fields
 * @callback_data: Opaque data to supply to the callback function
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * Parse a user asymmetric key or signature and call the supplied callback
 * function for each data field, passing also the opaque data pointer.
 *
 * Return: Zero on success, a negative value on error.
 */
int uasym_parse(enum data_types expected_data_type, parse_callback callback,
		void *callback_data, const u8 *data, size_t data_len)
{
	u8 data_type;
	u16 num_fields;
	u64 total_len;
	int ret = 0;

	pr_debug("Start parsing data blob, size: %ld, expected data type: %s\n",
		 data_len, data_types_str[expected_data_type]);

	while (data_len) {
		ret = uasym_parse_hdr(&data, &data_len, &data_type, &num_fields,
				      &total_len);
		if (ret < 0)
			goto out;

		if (data_type == expected_data_type)
			break;

		/*
		 * uasym_parse_hdr() already checked that total_len <= data_len.
		 */
		data += total_len;
		data_len -= total_len;
	}

	if (!data_len) {
		pr_debug("Data type %s not found\n",
			 data_types_str[expected_data_type]);
		ret = -ENOENT;
		goto out;
	}

	ret = uasym_parse_data(callback, callback_data, num_fields, data,
			       total_len);
out:
	pr_debug("End of parsing data blob, ret: %d\n", ret);
	return ret;
}
