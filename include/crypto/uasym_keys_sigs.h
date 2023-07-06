/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header of the user asymmetric keys and signatures parser.
 */

#ifndef _CRYPTO_UASYM_KEYS_SIGS_H
#define _CRYPTO_UASYM_KEYS_SIGS_H

#include <linux/hash_info.h>
#include <crypto/public_key.h>

struct key;
struct uasym_sig_message;

#ifdef CONFIG_UASYM_KEYS_SIGS
extern struct uasym_sig_message *uasym_sig_parse_message(const u8 *sig_data,
							 size_t sig_len);
extern int uasym_sig_supply_detached_data(struct uasym_sig_message *uasym_sig,
					  const void *data, size_t data_len);
extern int uasym_sig_get_content_data(struct uasym_sig_message *uasym_sig,
				      const void **_data, size_t *_data_len,
				      size_t *_headerlen);
extern int uasym_sig_get_digest(struct uasym_sig_message *uasym_sig,
				const u8 **buf, u32 *len,
				enum hash_algo *hash_algo);
extern int uasym_sig_verify_message(struct uasym_sig_message *uasym_sig,
				    struct key *keyring);
extern void uasym_sig_free_message(struct uasym_sig_message *uasym_sig);

int __init preload_uasym_keys(const u8 *data, size_t data_len,
			      struct key *keyring);
#else
static inline struct uasym_sig_message *
uasym_sig_parse_message(const u8 *sig_data, size_t sig_len)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int
uasym_sig_supply_detached_data(struct uasym_sig_message *uasym_sig,
			       const void *data, size_t data_len)
{
	return -EOPNOTSUPP;
}

static inline int
uasym_sig_get_content_data(struct uasym_sig_message *uasym_sig,
			   const void **_data, size_t *_data_len,
			   size_t *_headerlen)
{
	return -EOPNOTSUPP;
}

static inline int uasym_sig_get_digest(struct uasym_sig_message *uasym_sig,
				       const u8 **buf, u32 *len,
				       enum hash_algo *hash_algo)
{
	return -EOPNOTSUPP;
}

static inline int uasym_sig_verify_message(struct uasym_sig_message *uasym_sig,
					   struct key *keyring)
{
	return -EOPNOTSUPP;
}

static inline void uasym_sig_free_message(struct uasym_sig_message *uasym_sig)
{
}

static inline int __init preload_uasym_keys(const u8 *data, size_t data_len,
					    struct key *keyring)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_UASYM_KEYS_SIGS */
#endif /* _CRYPTO_UASYM_KEYS_SIGS_H */
