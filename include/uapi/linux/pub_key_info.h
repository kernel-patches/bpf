/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Public key info: Public key algorithms information
 */

#ifndef _UAPI_LINUX_PUB_KEY_INFO_H
#define _UAPI_LINUX_PUB_KEY_INFO_H

enum pub_key_algo {
	PKEY_ALGO_RSA,
	PKEY_ALGO_ECDSA,
	PKEY_ALGO_ECDSA_P192,
	PKEY_ALGO_ECDSA_P256,
	PKEY_ALGO_ECDSA_P384,
	PKEY_ALGO_ECRDSA,
	PKEY_ALGO_SM2,
	PKEY_ALGO__LAST,
};

#endif /* _UAPI_LINUX_PUB_KEY_INFO_H */
