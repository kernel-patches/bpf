// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 *   David Howells <dhowells@redhat.com>
 *   Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Load user asymmetric keys from a keyring blob.
 */

#include <linux/module.h>
#include <linux/key.h>
#include <linux/err.h>

#include "uasym_parser.h"

/**
 * create_uasym_key - Create a user asymmetric key
 * @data_start: Where the user asymmetric key starts in the blob
 * @data_end: Where the user asymmetric key ends in the blob
 * @keyring: The keyring to add the new key to
 *
 * Create a user asymmetric key from the supplied buffer.
 */
static void __init create_uasym_key(const u8 *data_start, const u8 *data_end,
				    struct key *keyring)
{
	key_ref_t key;

	key = key_create_or_update(make_key_ref(keyring, 1), "asymmetric", NULL,
				   data_start, data_end - data_start,
				   ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
				    KEY_USR_VIEW | KEY_USR_READ),
				   KEY_ALLOC_NOT_IN_QUOTA |
				   KEY_ALLOC_BUILT_IN |
				   KEY_ALLOC_BYPASS_RESTRICTION);
	if (IS_ERR(key)) {
		pr_notice("Ignoring user asymmetric key, error: %ld\n",
			  PTR_ERR(key));
		return;
	}

	pr_notice("Loaded user asymmetric key '%s'\n",
		  key_ref_to_ptr(key)->description);

	key_ref_put(key);
}

/**
 * preload_uasym_keys - Load user asymmetric keys from a keyring blob
 * @data: The keyring blob containing the user asymmetric keys
 * @data_len: The size of the @data blob
 * @keyring: The keyring to add the new keys to
 *
 * Preload a pack of user_asymmetric keys from a keyring blob.
 *
 * The callers should override the current creds if they want the keys to be
 * owned by someone other than the current process's owner. Keys will not be
 * accounted towards the owner's quota.
 *
 * This function may only be called whilst the kernel is booting.
 *
 * Return: Zero on success, a negative value otherwise.
 */
int __init preload_uasym_keys(const u8 *data, size_t data_len,
			      struct key *keyring)
{
	const u8 *data_ptr = data, *data_end = data + data_len;
	u8 data_type;
	u16 num_fields;
	u64 total_len;
	int ret;

	kenter("");

	while (data_ptr < data_end) {
		ret = uasym_parse_hdr(&data_ptr, &data_len, &data_type,
				      &num_fields, &total_len);
		if (ret < 0) {
			pr_notice("Unable to parse keyring blob, ret: %d\n",
				  ret);
			return ret;
		}

		if (data_type != TYPE_KEY) {
			data_ptr += total_len;
			continue;
		}

		create_uasym_key(data_ptr - sizeof(struct uasym_hdr),
				 data_ptr + total_len, keyring);

		data_ptr += total_len;
	}

	return 0;
}
