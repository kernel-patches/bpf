/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header of the UMD asymmetric key signature parser.
 */

#ifndef _CRYPTO_UMD_SIG_H
#define _CRYPTO_UMD_SIG_H

#include <linux/verification.h>
#include <linux/hash_info.h>
#include <crypto/public_key.h>

struct key;
struct umd_sig_message;

#ifdef CONFIG_UMD_SIG_PARSER
extern struct umd_sig_message *umd_sig_parse_message(const u8 *sig_data,
						     size_t sig_len);
extern int umd_sig_supply_detached_data(struct umd_sig_message *umd_sig,
					const void *data, size_t data_len);
extern int umd_sig_get_content_data(struct umd_sig_message *umd_sig,
				    const void **_data, size_t *_data_len,
				    size_t *_headerlen);
extern int umd_sig_get_digest(struct umd_sig_message *umd_sig, const u8 **buf,
			      u32 *len, enum hash_algo *hash_algo);
extern int umd_sig_verify_message(struct umd_sig_message *umd_sig,
				  struct key *keyring);
extern void umd_sig_free_message(struct umd_sig_message *umd_sig);
#else
static inline struct umd_sig_message *umd_sig_parse_message(const u8 *sig_data,
							    size_t sig_len)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int umd_sig_supply_detached_data(struct umd_sig_message *umd_sig,
					       const void *data, size_t data_len)
{
	return -EOPNOTSUPP;
}

static inline int umd_sig_get_content_data(struct umd_sig_message *umd_sig,
					   const void **_data,
					   size_t *_data_len,
					   size_t *_headerlen)
{
	return -EOPNOTSUPP;
}

static inline int umd_sig_get_digest(struct umd_sig_message *umd_sig, const u8 **buf,
				     u32 *len, enum hash_algo *hash_algo)
{
	return -EOPNOTSUPP;
}

static inline int umd_sig_verify_message(struct umd_sig_message *umd_sig,
					 struct key *keyring)
{
	return -EOPNOTSUPP;
}

static inline void umd_sig_free_message(struct umd_sig_message *umd_sig)
{
}

#endif /* CONFIG_UMD_SIG_PARSER */
#endif /* _CRYPTO_UMD_SIG_H */
