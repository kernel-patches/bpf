/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Sig enc info: Signature encoding information
 */

#ifndef _UAPI_LINUX_SIG_ENC_INFO_H
#define _UAPI_LINUX_SIG_ENC_INFO_H

enum sig_enc_info {
	SIG_ENC_PKCS1,
	SIG_ENC_X962,
	SIG_ENC_RAW,
	SIG_ENC__LAST,
};

#endif /* _UAPI_LINUX_SIG_ENC_INFO_H */
