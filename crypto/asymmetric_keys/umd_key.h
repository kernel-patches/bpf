/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header file of the UMD asymmetric key parser.
 */

#include <linux/usermode_driver_mgmt.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>

#include "umd_key_sig_umh.h"

extern struct umd_mgmt key_ops;
extern const char *pub_key_algos[PUBKEY_ALGO__LAST];

int umd_get_kids(struct umd_asymmetric_key_ids *umd_kids,
		 struct asymmetric_key_id *id[3]);

struct umd_sig_message {
	struct public_key_signature *sig;
	size_t data_len;
	const void *data;
	size_t sig_data_len;
	const void *sig_data;
};
