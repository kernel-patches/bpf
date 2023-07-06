// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Public key info: Public key algorithms information
 */

#include <linux/export.h>
#include <crypto/pub_key_info.h>

const char *const pub_key_algo_name[PKEY_ALGO__LAST] = {
	[PKEY_ALGO_RSA]		= "rsa",
	[PKEY_ALGO_ECDSA]	= "ecdsa",
	[PKEY_ALGO_ECDSA_P192]	= "ecdsa-nist-p192",
	[PKEY_ALGO_ECDSA_P256]	= "ecdsa-nist-p256",
	[PKEY_ALGO_ECDSA_P384]	= "ecdsa-nist-p384",
	[PKEY_ALGO_ECRDSA]	= "ecrdsa",
	[PKEY_ALGO_SM2]		= "sm2",
};
EXPORT_SYMBOL_GPL(pub_key_algo_name);
