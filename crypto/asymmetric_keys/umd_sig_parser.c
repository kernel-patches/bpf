// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the UMD asymmetric key signature parser.
 */

#include <linux/module.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>
#include <crypto/public_key.h>
#include <crypto/umd_sig.h>
#include <crypto/hash_info.h>
#include <crypto/hash.h>

#include "umd_key.h"

const char *sig_encodings[SIG_ENC__LAST] = {
	[SIG_ENC_PKCS1] = "pkcs1",
	[SIG_ENC_X962] = "x962",
	[SIG_ENC_RAW] = "raw",
};

static struct public_key_signature *get_sig(struct msg_out *out)
{
	struct public_key_signature *sig = NULL;
	int ret;

	if (!out->sig.sig_len) {
		pr_err("Unexpected zero-length for signature\n");
		return ERR_PTR(-EBADMSG);
	}

	if (out->sig.sig_len > sizeof(out->sig.sig)) {
		pr_err("Signature length %ld greater than expected %ld\n",
		       out->sig.sig_len, sizeof(out->sig.sig));
		return ERR_PTR(-EBADMSG);
	}

	if (out->sig.pkey_algo >= PUBKEY_ALGO__LAST) {
		pr_err("Unexpected key algo %d\n", out->sig.pkey_algo);
		return ERR_PTR(-EBADMSG);
	}

	if (out->sig.hash_algo >= HASH_ALGO__LAST) {
		pr_err("Unexpected hash algo %d\n", out->sig.hash_algo);
		return ERR_PTR(-EBADMSG);
	}

	if (out->sig.enc >= SIG_ENC__LAST) {
		pr_err("Unexpected signature encoding %d\n", out->sig.enc);
		return ERR_PTR(-EBADMSG);
	}

	sig = kzalloc(sizeof(*sig), GFP_KERNEL);
	if (!sig)
		return ERR_PTR(-ENOMEM);

	sig->s = kmemdup(out->sig.sig, out->sig.sig_len, GFP_KERNEL);
	if (!sig->s) {
		ret = -ENOMEM;
		goto out;
	}

	sig->s_size = out->sig.sig_len;

	ret = umd_get_kids(&out->sig.auth_ids, sig->auth_ids);
	if (ret)
		goto out;

	sig->pkey_algo = pub_key_algos[out->sig.pkey_algo];
	sig->hash_algo = hash_algo_name[out->sig.hash_algo];
	sig->digest_size = hash_digest_size[out->sig.hash_algo];
	sig->encoding = sig_encodings[out->sig.enc];
out:
	if (ret) {
		public_key_signature_free(sig);
		sig = ERR_PTR(ret);
	}

	return sig;
}

static int get_sig_data(struct msg_out *out, struct umd_sig_message *umd_sig)
{
	if (!out->sig.sig_data_len)
		return 0;

	if (out->sig.sig_data_len > sizeof(out->sig.sig_data)) {
		pr_err("Additional data length %ld greater than expected %ld\n",
		       out->sig.sig_data_len, sizeof(out->sig.sig_data));
		return -EBADMSG;
	}

	umd_sig->sig_data = kmemdup(out->sig.sig_data, out->sig.sig_data_len,
				    GFP_KERNEL);
	if (!umd_sig->sig_data)
		return -ENOMEM;

	umd_sig->sig_data_len = out->sig.sig_data_len;
	return 0;
}

/**
 * umd_sig_parse_message - Parse a signature with a UMD handler
 * @sig_data: Signature blob
 * @sig_len: Length of signature blob
 *
 * Pass the signature blob to a UMD handler and fill a public_key_signature
 * structure from the UMD handler response.
 *
 * Return: A umd_sig_message structure on success, an error pointer on error.
 */
struct umd_sig_message *umd_sig_parse_message(const u8 *sig_data,
					      size_t sig_len)
{
	struct msg_in *in = NULL;
	struct msg_out *out = NULL;
	struct umd_sig_message *umd_sig = NULL;
	int ret = -ENOMEM;

	if (sig_len > sizeof(in->data))
		return ERR_PTR(-EINVAL);

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		goto out;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		goto out;

	in->cmd = CMD_SIG;
	in->data_len = sig_len;
	memcpy(in->data, sig_data, sig_len);

	out->ret = -EINVAL;

	ret = umd_mgmt_send_recv(&key_ops, in, sizeof(*in), out, sizeof(*out));
	if (ret)
		goto out;

	if (out->ret) {
		ret = out->ret;
		goto out;
	}

	umd_sig = kzalloc(sizeof(*umd_sig), GFP_KERNEL);
	if (!umd_sig) {
		ret = -ENOMEM;
		goto out;
	}

	umd_sig->sig = get_sig(out);
	if (IS_ERR(umd_sig->sig)) {
		ret = PTR_ERR(umd_sig->sig);
		umd_sig->sig = NULL;
		goto out;
	}

	ret = get_sig_data(out, umd_sig);
out:
	if (ret) {
		if (umd_sig) {
			public_key_signature_free(umd_sig->sig);
			kfree(umd_sig);
		}

		umd_sig = ERR_PTR(ret);
	}

	kfree(in);
	kfree(out);
	return umd_sig;
}
EXPORT_SYMBOL_GPL(umd_sig_parse_message);

/**
 * umd_sig_supply_detached_data - Supply the data to verify a UMD-parsed sig
 * @umd_sig: The UMD-parsed signature
 * @data: The data to be verified
 * @data_len: The amount of data
 *
 * Supply the detached data needed to verify a UMD-parsed signature. Note that
 * no attempt to retain/pin the data is made. That is left to the caller. The
 * data will not be modified by umd_sig_verify_message() and will not be freed
 * when the UMD-parsed signature is freed.
 *
 * Return: Zero on success, -EINVAL if data are already supplied.
 */
int umd_sig_supply_detached_data(struct umd_sig_message *umd_sig,
				 const void *data, size_t data_len)
{
	if (umd_sig->data) {
		pr_debug("Data already supplied\n");
		return -EINVAL;
	}
	umd_sig->data = data;
	umd_sig->data_len = data_len;
	return 0;
}
EXPORT_SYMBOL_GPL(umd_sig_supply_detached_data);

/**
 * umd_sig_get_content_data - Get access to content data and additional data
 * @umd_sig: The UMD-parsed signature
 * @_data: Place to return a pointer to the data
 * @_data_len: Place to return the data length
 * @_headerlen: Size of the additional data
 *
 * Get access to the data associated to the UMD-parsed signature. This includes
 * the content data eventually supplied by the caller of the UMD signatures API,
 * and the additional data resulting from the signature parsing, appended at the
 * end (the ordering can be configurable in the future).
 *
 * Data is allocated, to concatenate together the two data sources, and must be
 * freed by the caller. It is presented in a way that is suitable for
 * calculating the digest for verifying the signature.
 *
 * Return: Zero if the data and additional data can be provided,
 *         a negative value on error.
 */
int umd_sig_get_content_data(struct umd_sig_message *umd_sig,
			     const void **_data, size_t *_data_len,
			     size_t *_headerlen)
{
	void *data;

	if (!umd_sig->data)
		return -ENODATA;

	if (!_data)
		goto skip_data;

	data = kmalloc(umd_sig->data_len + umd_sig->sig->data_size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	memcpy(data, umd_sig->data, umd_sig->data_len);
	memcpy(data + umd_sig->data_len, umd_sig->sig->data,
	       umd_sig->sig->data_size);
	*_data = data;
skip_data:
	if (_data_len)
		*_data_len = umd_sig->data_len + umd_sig->sig->data_size;
	if (_headerlen)
		*_headerlen = umd_sig->sig->data_size;
	return 0;
}
EXPORT_SYMBOL_GPL(umd_sig_get_content_data);

static int umd_sig_digest(struct umd_sig_message *umd_sig)
{
	struct public_key_signature *sig = umd_sig->sig;
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

	ret = crypto_shash_update(desc, umd_sig->data, umd_sig->data_len);
	if (ret < 0)
		goto error;

	ret = crypto_shash_finup(desc, umd_sig->sig_data, umd_sig->sig_data_len,
				 sig->digest);
error:
	kfree(desc);
error_no_desc:
	crypto_free_shash(tfm);
	return ret;
}

/**
 * umd_sig_get_digest - Obtain the digest and algorithm of the data to verify
 * @umd_sig: The UMD-parsed signature
 * @digest: The buffer the digest is written to
 * @digest_len: The length of @digest
 * @hash_algo: The algorithm the digest is calculated with
 *
 * Calculate the digest of data to verify with the UMD-parsed signature, if
 * not calculated already. Pass the pointer of the digest from the
 * public_key_signature structure, the length and the algorithm to the caller.
 *
 * Return: Zero on success, a negative value otherwise.
 */
int umd_sig_get_digest(struct umd_sig_message *umd_sig, const u8 **digest,
		       u32 *digest_len, enum hash_algo *hash_algo)
{
	struct public_key_signature *sig = umd_sig->sig;
	int i, ret;

	ret = umd_sig_digest(umd_sig);
	if (ret)
		return ret;

	*digest = sig->digest;
	*digest_len = sig->digest_size;

	i = match_string(hash_algo_name, HASH_ALGO__LAST, sig->hash_algo);
	if (i >= 0)
		*hash_algo = i;

	return 0;
}
EXPORT_SYMBOL_GPL(umd_sig_get_digest);

static struct key *get_key(struct umd_sig_message *umd_sig, struct key *keyring)
{
	struct public_key_signature *sig = umd_sig->sig;
	struct key *key;

	key = find_asymmetric_key(keyring, sig->auth_ids[0], sig->auth_ids[1],
				  sig->auth_ids[2], true);
	if (IS_ERR(key)) {
		pr_debug("Public key not found (#%*phN, #%*phN, #%*phN)\n",
			 sig->auth_ids[0]->len, sig->auth_ids[0]->data,
			 sig->auth_ids[1]->len, sig->auth_ids[1]->data,
			 sig->auth_ids[2]->len, sig->auth_ids[2]->data);

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
 * umd_sig_verify_message - Verify the UMD-parsed signature
 * @umd_sig: The UMD-parsed signature
 * @keyring: Keyring containing the key for signature verification
 *
 * Calculate the digest, search the key for signature verification, and verify
 * the signature.
 *
 * Return: Zero if the signature is valid, a negative value otherwise.
 */
int umd_sig_verify_message(struct umd_sig_message *umd_sig, struct key *keyring)
{
	const struct public_key *pub;
	struct key *key;
	int ret;

	ret = umd_sig_digest(umd_sig);
	if (ret < 0)
		return ret;

	key = get_key(umd_sig, keyring);
	if (IS_ERR(key))
		return PTR_ERR(key);

	pub = key->payload.data[asym_crypto];

	if (strcmp(pub->pkey_algo, umd_sig->sig->pkey_algo) != 0 &&
	    (strncmp(pub->pkey_algo, "ecdsa-", 6) != 0 ||
	     strcmp(umd_sig->sig->pkey_algo, "ecdsa") != 0)) {
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = verify_signature(key, umd_sig->sig);
out:
	key_put(key);
	return ret;
}
EXPORT_SYMBOL_GPL(umd_sig_verify_message);

/**
 * umd_sig_free_message - Free the memory allocated
 * @umd_sig: The UMD-parsed signature
 *
 * Free the memory allocated for the verification of the UMD-parsed signature.
 */
void umd_sig_free_message(struct umd_sig_message *umd_sig)
{
	if (!umd_sig)
		return;

	kfree(umd_sig->sig_data);
	public_key_signature_free(umd_sig->sig);
	kfree(umd_sig);
}
EXPORT_SYMBOL_GPL(umd_sig_free_message);
