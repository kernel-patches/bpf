// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Sig enc info: Signature encoding information
 */

#include <linux/export.h>
#include <crypto/sig_enc_info.h>

const char *const sig_enc_name[SIG_ENC__LAST] = {
	[SIG_ENC_PKCS1] = "pkcs1",
	[SIG_ENC_X962] = "x962",
	[SIG_ENC_RAW] = "raw",
};
EXPORT_SYMBOL_GPL(sig_enc_name);
