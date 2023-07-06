// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 *   David Howells <dhowells@redhat.com>
 *   Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the user asymmetric key signature parser.
 */

#define pr_fmt(fmt) "UASYM SIG: "fmt
#include <linux/module.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>
#include <crypto/public_key.h>
#include <crypto/uasym_keys_sigs.h>
#include <crypto/pub_key_info.h>
#include <crypto/sig_enc_info.h>
#include <crypto/hash_info.h>
#include <crypto/hash.h>

#include "uasym_parser.h"

static int parse_sig_s(struct public_key_signature *sig, enum fields field,
		       const u8 *field_data, u32 field_data_len)
{
	int ret = 0;

	kenter(",%u,%u", field, field_data_len);

	sig->s = kmemdup(field_data, field_data_len, GFP_KERNEL);
	if (!sig->s) {
		ret = -ENOMEM;
		goto out;
	}

	sig->s_size = field_data_len;
	pr_debug("Signature length: %d\n", sig->s_size);
out:
	kleave(" = %d", ret);
	return ret;
}

static int parse_sig_hash_algo_size(struct public_key_signature *sig,
				    enum fields field, const u8 *field_data,
				    u32 field_data_len)
{
	u8 algo;
	int ret = 0;

	kenter(",%u,%u", field, field_data_len);

	if (field_data_len != sizeof(u8)) {
		pr_debug("Unexpected data length %u, expected %lu\n",
			 field_data_len, sizeof(u8));
		ret = -EBADMSG;
		goto out;
	}

	algo = *field_data;

	if (algo >= HASH_ALGO__LAST) {
		pr_debug("Unexpected hash algo %u\n", algo);
		ret = -EBADMSG;
		goto out;
	}

	sig->hash_algo = hash_algo_name[algo];
	sig->digest_size = hash_digest_size[algo];
	pr_debug("Hash algo: %s, digest length: %d\n", sig->hash_algo,
		 sig->digest_size);
out:
	kleave(" = %d", ret);
	return ret;
}

static int parse_sig_enc(struct public_key_signature *sig, enum fields field,
			 const u8 *field_data, u32 field_data_len)
{
	u8 enc;
	int ret = 0;

	kenter(",%u,%u", field, field_data_len);

	if (field_data_len != sizeof(u8)) {
		pr_debug("Unexpected data length %u, expected %lu\n",
			 field_data_len, sizeof(u8));
		ret = -EBADMSG;
		goto out;
	}

	enc = *field_data;

	if (enc >= SIG_ENC__LAST) {
		pr_debug("Unexpected encoding %u\n", enc);
		ret = -EBADMSG;
		goto out;
	}

	sig->encoding = sig_enc_name[enc];
	pr_debug("Signature encoding: %s\n", sig->encoding);
out:
	kleave(" = %d", ret);
	return ret;
}

static int parse_sig_data_end(struct uasym_sig_message *uasym_sig,
			      enum fields field, const u8 *field_data,
			      u32 field_data_len)
{
	int ret = 0;

	uasym_sig->sig_data = kmemdup(field_data, field_data_len, GFP_KERNEL);
	if (!uasym_sig->sig_data) {
		ret = -ENOMEM;
		goto out;
	}

	uasym_sig->sig_data_len = field_data_len;
	pr_debug("Signature data length appended at the end: %ld\n",
		 uasym_sig->sig_data_len);
out:
	kleave(" = %d", ret);
	return ret;
}

static int sig_callback(void *callback_data, enum fields field,
			const u8 *field_data, u32 field_data_len)
{
	struct uasym_sig_message *uasym_sig;
	struct public_key_signature *sig;
	struct asymmetric_key_id **id;
	int ret;

	uasym_sig = (struct uasym_sig_message *)callback_data;
	sig = uasym_sig->sig;

	switch (field) {
	case SIG_S:
		ret = parse_sig_s(sig, field, field_data, field_data_len);
		break;
	case SIG_KEY_ALGO:
		ret = parse_key_algo(&sig->pkey_algo, field, field_data,
				     field_data_len);
		break;
	case SIG_HASH_ALGO:
		ret = parse_sig_hash_algo_size(sig, field, field_data,
					       field_data_len);
		break;
	case SIG_ENC:
		ret = parse_sig_enc(sig, field, field_data, field_data_len);
		break;
	case SIG_KID0:
		id = (struct asymmetric_key_id **)&sig->auth_ids[0];
		ret = parse_key_kid(id, field, field_data, field_data_len);
		break;
	case SIG_KID1:
		id = (struct asymmetric_key_id **)&sig->auth_ids[1];
		ret = parse_key_kid(id, field, field_data, field_data_len);
		break;
	case SIG_KID2:
		id = (struct asymmetric_key_id **)&sig->auth_ids[2];
		ret = parse_key_kid(id, field, field_data, field_data_len);
		break;
	case SIG_DATA_END:
		ret = parse_sig_data_end(uasym_sig, field, field_data,
					 field_data_len);
		break;
	default:
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

/**
 * uasym_sig_parse_message - Parse a user asymmetric key signature
 * @sig_data: Signature blob
 * @sig_len: Length of signature blob
 *
 * Parse a user asymmetric key signature and initialize the signature context.
 *
 * Return: A uasym_sig_message structure on success, an error pointer on error.
 */
struct uasym_sig_message *uasym_sig_parse_message(const u8 *sig_data,
						  size_t sig_len)
{
	struct uasym_sig_message *uasym_sig = NULL;
	struct public_key_signature *sig;
	int ret = -EBADMSG;

	kenter("");

	uasym_sig = kzalloc(sizeof(*uasym_sig), GFP_KERNEL);
	if (!uasym_sig) {
		ret = -ENOMEM;
		goto out;
	}

	sig = kzalloc(sizeof(*sig), GFP_KERNEL);
	if (!sig) {
		ret = -ENOMEM;
		goto out;
	}

	uasym_sig->sig = sig;

	ret = uasym_parse(TYPE_SIG, sig_callback, uasym_sig, sig_data, sig_len);
	if (ret < 0)
		goto out;

	if (!sig->s || !sig->pkey_algo || !sig->hash_algo || !sig->encoding ||
	    (!sig->auth_ids[0] && !sig->auth_ids[1] && !sig->auth_ids[2])) {
		pr_debug("Incomplete data\n");
		ret = -ENOENT;
		goto out;
	}
out:
	if (ret < 0) {
		if (uasym_sig) {
			public_key_signature_free(sig);
			kfree(uasym_sig->sig_data);
			kfree(uasym_sig);
		}

		uasym_sig = ERR_PTR(ret);
		kleave(" = ERR_PTR(%d)", ret);
	}

	kleave(" = PTR(uasym_sig)");
	return uasym_sig;
}
EXPORT_SYMBOL_GPL(uasym_sig_parse_message);

/**
 * uasym_sig_supply_detached_data - Supply data to verify a user asym key sig
 * @uasym_sig: The signature context
 * @data: The data to be verified
 * @data_len: The amount of data
 *
 * Supply the detached data needed to verify a user asymmetric key signature.
 * Note that no attempt to retain/pin the data is made. That is left to the
 * caller. The data will not be modified by uasym_sig_verify_message() and will
 * not be freed when the signature context is freed.
 *
 * Return: Zero on success, -EINVAL if data are already supplied.
 */
int uasym_sig_supply_detached_data(struct uasym_sig_message *uasym_sig,
				   const void *data, size_t data_len)
{
	if (uasym_sig->data) {
		pr_debug("Data already supplied\n");
		return -EINVAL;
	}

	uasym_sig->data = data;
	uasym_sig->data_len = data_len;
	return 0;
}
EXPORT_SYMBOL_GPL(uasym_sig_supply_detached_data);

/**
 * uasym_sig_get_content_data - Get access to content data and additional data
 * @uasym_sig: The signature context
 * @_data: Place to return a pointer to the data (updated)
 * @_data_len: Place to return the data length (updated)
 * @_headerlen: Size of the additional data (updated)
 *
 * Get access to the data associated to the user asymmetric key signature.
 * This includes the content data eventually supplied by the caller of the user
 * asymmetric key signatures API, and the additional data resulting from the
 * signature parsing, appended at the end (more orderings can be supported
 * in the future).
 *
 * Data is allocated, to concatenate together the two data sources, and must be
 * freed by the caller. It is presented in a way that is suitable for
 * calculating the digest for verifying the signature.
 *
 * Return: Zero if the data and additional data can be provided,
 *         a negative value on error.
 */
int uasym_sig_get_content_data(struct uasym_sig_message *uasym_sig,
			       const void **_data, size_t *_data_len,
			       size_t *_headerlen)
{
	void *data;

	if (!uasym_sig->data)
		return -ENODATA;

	if (!_data)
		goto skip_data;

	data = kmalloc(uasym_sig->data_len + uasym_sig->sig_data_len,
		       GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	memcpy(data, uasym_sig->data, uasym_sig->data_len);
	memcpy(data + uasym_sig->data_len, uasym_sig->sig_data,
	       uasym_sig->sig_data_len);
	*_data = data;
skip_data:
	if (_data_len)
		*_data_len = uasym_sig->data_len + uasym_sig->sig_data_len;
	if (_headerlen)
		*_headerlen = uasym_sig->data_len;
	return 0;
}
EXPORT_SYMBOL_GPL(uasym_sig_get_content_data);

static int uasym_sig_digest(struct uasym_sig_message *uasym_sig)
{
	struct public_key_signature *sig = uasym_sig->sig;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t desc_size;
	int ret;

	/* The digest was calculated already. */
	if (sig->digest)
		return 0;

	tfm = crypto_alloc_shash(sig->hash_algo, 0, 0);
	if (IS_ERR(tfm))
		return (PTR_ERR(tfm) == -ENOENT) ? -ENOPKG : PTR_ERR(tfm);

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);

	ret = -ENOMEM;
	sig->digest = kmalloc(sig->digest_size, GFP_KERNEL);
	if (!sig->digest)
		goto error_no_desc;

	desc = kzalloc(desc_size, GFP_KERNEL);
	if (!desc)
		goto error_no_desc;

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	ret = crypto_shash_update(desc, uasym_sig->data, uasym_sig->data_len);
	if (ret < 0)
		goto error;

	if (uasym_sig->sig_data_len) {
		ret = crypto_shash_update(desc, uasym_sig->sig_data,
					  uasym_sig->sig_data_len);
		if (ret < 0)
			goto error;
	}

	ret = crypto_shash_final(desc, sig->digest);
error:
	kfree(desc);
error_no_desc:
	crypto_free_shash(tfm);
	return ret;
}

/**
 * uasym_sig_get_digest - Obtain the digest and algorithm of the data to verify
 * @uasym_sig: The signature context
 * @digest: The buffer the digest is written to
 * @digest_len: The length of @digest
 * @hash_algo: The algorithm the digest is calculated with
 *
 * Calculate the digest of data to verify with the user asymmetric key
 * signature, if not calculated already. Pass the pointer of the digest from
 * the public_key_signature structure, the length and the algorithm to the
 * caller.
 *
 * Return: Zero on success, a negative value otherwise.
 */
int uasym_sig_get_digest(struct uasym_sig_message *uasym_sig, const u8 **digest,
			 u32 *digest_len, enum hash_algo *hash_algo)
{
	struct public_key_signature *sig = uasym_sig->sig;
	int i, ret;

	ret = uasym_sig_digest(uasym_sig);
	if (ret)
		return ret;

	*digest = sig->digest;
	*digest_len = sig->digest_size;

	i = match_string(hash_algo_name, HASH_ALGO__LAST, sig->hash_algo);
	if (i >= 0)
		*hash_algo = i;

	return 0;
}
EXPORT_SYMBOL_GPL(uasym_sig_get_digest);

static struct key *get_key(struct uasym_sig_message *uasym_sig,
			   struct key *keyring)
{
	struct public_key_signature *sig = uasym_sig->sig;
	struct key *key;

	key = find_asymmetric_key(keyring, sig->auth_ids[0], sig->auth_ids[1],
				  sig->auth_ids[2], false);
	if (IS_ERR(key)) {
		pr_debug("Public key not found (%*phN, %*phN, %*phN)\n",
			 sig->auth_ids[0] ? sig->auth_ids[0]->len : 0,
			 sig->auth_ids[0] ? sig->auth_ids[0]->data : NULL,
			 sig->auth_ids[1] ? sig->auth_ids[1]->len : 0,
			 sig->auth_ids[1] ? sig->auth_ids[1]->data : NULL,
			 sig->auth_ids[2] ? sig->auth_ids[2]->len : 0,
			 sig->auth_ids[2] ? sig->auth_ids[2]->data : NULL);

		switch (PTR_ERR(key)) {
			/* Hide some search errors */
		case -EACCES:
		case -ENOTDIR:
		case -EAGAIN:
			return ERR_PTR(-ENOKEY);
		default:
			return ERR_CAST(key);
		}
	}

	return key;
}

/**
 * uasym_sig_verify_message - Verify the user asymmetric key signature
 * @uasym_sig: The signature context
 * @keyring: Keyring containing the key for signature verification
 *
 * Calculate the digest, search the key for signature verification, and verify
 * the signature.
 *
 * Return: Zero if the signature is valid, a negative value otherwise.
 */
int uasym_sig_verify_message(struct uasym_sig_message *uasym_sig,
			     struct key *keyring)
{
	const struct public_key *pub;
	struct key *key;
	int ret;

	ret = uasym_sig_digest(uasym_sig);
	if (ret < 0)
		return ret;

	key = get_key(uasym_sig, keyring);
	if (IS_ERR(key))
		return PTR_ERR(key);

	pub = key->payload.data[asym_crypto];

	if (strcmp(pub->pkey_algo, uasym_sig->sig->pkey_algo) != 0 &&
	    (strncmp(pub->pkey_algo, "ecdsa-", 6) != 0 ||
	     strcmp(uasym_sig->sig->pkey_algo, "ecdsa") != 0)) {
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = verify_signature(key, uasym_sig->sig);
out:
	key_put(key);
	return ret;
}
EXPORT_SYMBOL_GPL(uasym_sig_verify_message);

/**
 * uasym_sig_free_message - Free the memory allocated
 * @uasym_sig: The signature context
 *
 * Free the memory allocated for the verification of the user asymmetric key
 * signature.
 */
void uasym_sig_free_message(struct uasym_sig_message *uasym_sig)
{
	if (!uasym_sig)
		return;

	kfree(uasym_sig->sig_data);
	public_key_signature_free(uasym_sig->sig);
	kfree(uasym_sig);
}
EXPORT_SYMBOL_GPL(uasym_sig_free_message);
