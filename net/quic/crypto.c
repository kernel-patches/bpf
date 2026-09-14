// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <crypto/skcipher.h>
#include <linux/skbuff.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <linux/quic.h>
#include <net/tls.h>

#include "common.h"
#include "crypto.h"

/* HKDF-Extract. */
static int quic_crypto_hkdf_extract(struct crypto_shash *tfm,
				    struct quic_data *srt,
				    struct quic_data *hash,
				    struct quic_data *key)
{
	int err;

	err = crypto_shash_setkey(tfm, srt->data, srt->len);
	if (err)
		return err;

	return crypto_shash_tfm_digest(tfm, hash->data, hash->len, key->data);
}

#define QUIC_MAX_INFO_LEN	256

/* HKDF-Expand-Label. */
static int quic_crypto_hkdf_expand(struct crypto_shash *tfm,
				   struct quic_data *srt,
				   struct quic_data *label,
				   struct quic_data *key)
{
	u8 info[QUIC_MAX_INFO_LEN], *p = info, tmp[QUIC_SECRET_LEN];
	unsigned int i, infolen, hashlen = srt->len;
	SHASH_DESC_ON_STACK(desc, tfm);
	u8 LABEL[] = "tls13 ", cnt = 1;
	const u8 *prev = NULL;
	int err;

	/* rfc8446#section-7.1:
	 *
	 *  HKDF-Expand-Label(Secret, Label, Context, Length) =
	 *       HKDF-Expand(Secret, HkdfLabel, Length)
	 *
	 *  Where HkdfLabel is specified as:
	 *
	 *  struct {
	 *      uint16 length = Length;
	 *      opaque label<7..255> = "tls13 " + Label;
	 *      opaque context<0..255> = Context;
	 *  } HkdfLabel;
	 */
	put_unaligned_be16(key->len, p);
	p += 2;
	*p++ = (u8)(sizeof(LABEL) - 1 + label->len);
	p = quic_put_data(p, LABEL, sizeof(LABEL) - 1);
	p = quic_put_data(p, label->data, label->len);
	*p++ = 0;
	infolen = (unsigned int)(p - info);

	err = crypto_shash_setkey(tfm, srt->data, srt->len);
	if (err)
		return err;
	desc->tfm = tfm;

	for (i = 0; i < key->len; i += hashlen) {
		err = crypto_shash_init(desc);
		if (err)
			goto out;

		if (prev) {
			err = crypto_shash_update(desc, prev, hashlen);
			if (err)
				goto out;
		}

		err = crypto_shash_update(desc, info, infolen);
		if (err)
			goto out;

		BUILD_BUG_ON(sizeof(cnt) != 1);
		if (key->len - i < hashlen) {
			err = crypto_shash_finup(desc, &cnt, 1, tmp);
			if (err)
				goto out;
			memcpy(&key->data[i], tmp, key->len - i);
			memzero_explicit(tmp, sizeof(tmp));
		} else {
			err = crypto_shash_finup(desc, &cnt, 1, &key->data[i]);
			if (err)
				goto out;
		}
		cnt++;
		prev = &key->data[i];
	}
out:
	shash_desc_zero(desc);
	memzero_explicit(tmp, sizeof(tmp));
	return err;
}

#define KEY_LABEL_V1		"quic key"
#define IV_LABEL_V1		"quic iv"
#define HP_KEY_LABEL_V1		"quic hp"

#define KU_LABEL_V1		"quic ku"

/* rfc9369#section-3.3.2:
 *
 * The labels used in rfc9001 to derive packet protection keys, header
 * protection keys, Retry Integrity Tag keys, and key updates change from "quic
 * key" to "quicv2 key", from "quic iv" to "quicv2 iv", from "quic hp" to
 * "quicv2 hp", and from "quic ku" to "quicv2 ku".
 */
#define KEY_LABEL_V2		"quicv2 key"
#define IV_LABEL_V2		"quicv2 iv"
#define HP_KEY_LABEL_V2		"quicv2 hp"

#define KU_LABEL_V2		"quicv2 ku"

/* Packet Protection Keys. */
static int quic_crypto_keys_derive(struct crypto_shash *tfm,
				   struct quic_data *s, struct quic_data *k,
				   struct quic_data *i, struct quic_data *hp_k,
				   u32 version)
{
	struct quic_data hp_k_l = {HP_KEY_LABEL_V1, strlen(HP_KEY_LABEL_V1)};
	struct quic_data k_l = {KEY_LABEL_V1, strlen(KEY_LABEL_V1)};
	struct quic_data i_l = {IV_LABEL_V1, strlen(IV_LABEL_V1)};
	int err;

	/* rfc9001#section-5.1:
	 *
	 * The current encryption level secret and the label "quic key" are
	 * input to the KDF to produce the AEAD key; the label "quic iv" is
	 * used to derive the Initialization Vector (IV). The header protection
	 * key uses the "quic hp" label.  Using these labels provides key
	 * separation between QUIC and TLS.
	 */
	if (version == QUIC_VERSION_V2) {
		quic_data(&hp_k_l, HP_KEY_LABEL_V2, strlen(HP_KEY_LABEL_V2));
		quic_data(&k_l, KEY_LABEL_V2, strlen(KEY_LABEL_V2));
		quic_data(&i_l, IV_LABEL_V2, strlen(IV_LABEL_V2));
	}

	err = quic_crypto_hkdf_expand(tfm, s, &k_l, k);
	if (err)
		return err;
	err = quic_crypto_hkdf_expand(tfm, s, &i_l, i);
	if (err)
		return err;
	/* Don't change hp key for key update. */
	if (!hp_k)
		return 0;

	return quic_crypto_hkdf_expand(tfm, s, &hp_k_l, hp_k);
}

/* Derive and install reception (RX) or transmission (TX) packet protection
 * keys for the current key phase.  This installs AEAD protection key, IV, and
 * optionally header protection key.
 */
static int quic_crypto_keys_derive_and_install(struct quic_crypto *crypto,
					       bool rx, u8 phase)
{
	struct quic_data srt = {}, k, iv, hp_k = {}, *hp = NULL;
	u8 key[QUIC_KEY_LEN], hp_key[QUIC_KEY_LEN] = {};
	u32 keylen, ivlen = QUIC_IV_LEN;
	struct crypto_skcipher *hp_tfm;
	struct crypto_aead *tfm;
	int err;

	keylen = crypto->cipher->keylen;
	quic_data(&k, key, keylen);

	if (rx) {
		quic_data(&srt, crypto->rx_secret[phase],
			  crypto->cipher->secretlen);
		quic_data(&iv, crypto->rx_iv[phase], ivlen);
		tfm = crypto->rx_tfm[phase];
		hp_tfm = crypto->rx_hp_tfm;
	} else {
		quic_data(&srt, crypto->tx_secret[phase],
			  crypto->cipher->secretlen);
		quic_data(&iv, crypto->tx_iv[phase], ivlen);
		tfm = crypto->tx_tfm[phase];
		hp_tfm = crypto->tx_hp_tfm;
	}

	/* Only derive header protection key when not in key update. */
	if (crypto->key_phase == phase)
		hp = quic_data(&hp_k, hp_key, keylen);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &srt, &k, &iv, hp,
				      crypto->version);
	if (err)
		goto out;
	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		goto out;
	err = crypto_aead_setkey(tfm, key, keylen);
	if (err)
		goto out;
	if (hp) {
		err = crypto_skcipher_setkey(hp_tfm, hp_key, keylen);
		if (err)
			goto out;
	}
out:
	memzero_explicit(key, sizeof(key));
	memzero_explicit(hp_key, sizeof(hp_key));
	return err;
}

#define QUIC_CIPHER_MIN TLS_CIPHER_AES_GCM_128
#define QUIC_CIPHER_MAX TLS_CIPHER_CHACHA20_POLY1305

#define TLS_CIPHER_AES_GCM_128_SECRET_SIZE		32
#define TLS_CIPHER_AES_GCM_256_SECRET_SIZE		48
#define TLS_CIPHER_AES_CCM_128_SECRET_SIZE		32
#define TLS_CIPHER_CHACHA20_POLY1305_SECRET_SIZE	32

#define CIPHER_DESC(type, aead_n, skc_n, sha_n)[type - QUIC_CIPHER_MIN] = { \
	.secretlen = type ## _SECRET_SIZE, \
	.keylen = type ## _KEY_SIZE, \
	.aead = aead_n, \
	.skc = skc_n, \
	.shash = sha_n, \
}

static const struct quic_cipher
ciphers[QUIC_CIPHER_MAX + 1 - QUIC_CIPHER_MIN] = {
	CIPHER_DESC(TLS_CIPHER_AES_GCM_128,
		    "gcm(aes)", "ecb(aes)", "hmac(sha256)"),
	CIPHER_DESC(TLS_CIPHER_AES_GCM_256,
		    "gcm(aes)", "ecb(aes)", "hmac(sha384)"),
	CIPHER_DESC(TLS_CIPHER_AES_CCM_128,
		    "ccm(aes)", "ecb(aes)", "hmac(sha256)"),
	CIPHER_DESC(TLS_CIPHER_CHACHA20_POLY1305,
		    "rfc7539(chacha20,poly1305)", "chacha20", "hmac(sha256)"),
};

int quic_crypto_set_cipher(struct quic_crypto *crypto, u32 type)
{
	const struct quic_cipher *cipher;
	void *tfm;
	int err;

	if (type < QUIC_CIPHER_MIN || type > QUIC_CIPHER_MAX)
		return -EINVAL;

	cipher = &ciphers[type - QUIC_CIPHER_MIN];
	tfm = crypto_alloc_shash(cipher->shash, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	crypto->secret_tfm = tfm;

	/* Allocate AEAD and HP transform for each RX key phase. */
	tfm = crypto_alloc_aead(cipher->aead, 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto err;
	}
	crypto->rx_tfm[0] = tfm;
	tfm = crypto_alloc_aead(cipher->aead, 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto err;
	}
	crypto->rx_tfm[1] = tfm;
	tfm = crypto_alloc_sync_skcipher(cipher->skc, 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto err;
	}
	crypto->rx_hp_tfm = tfm;

	/* Allocate AEAD and HP transform for each TX key phase. */
	tfm = crypto_alloc_aead(cipher->aead, 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto err;
	}
	crypto->tx_tfm[0] = tfm;
	tfm = crypto_alloc_aead(cipher->aead, 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto err;
	}
	crypto->tx_tfm[1] = tfm;
	tfm = crypto_alloc_sync_skcipher(cipher->skc, 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto err;
	}
	crypto->tx_hp_tfm = tfm;

	crypto->cipher = cipher;
	crypto->cipher_type = type;
	return 0;
err:
	quic_crypto_free(crypto);
	return err;
}

int quic_crypto_set_secret(struct quic_crypto *crypto,
			   struct quic_crypto_secret *srt, u32 version)
{
	const struct quic_cipher *cipher;
	u8 phase = crypto->key_phase;
	int err;

	/* If no cipher has been initialized yet, set it up. */
	if (!crypto->cipher) {
		err = quic_crypto_set_cipher(crypto, srt->type);
		if (err)
			return err;
	}
	cipher = crypto->cipher;

	/* Handle RX path setup. */
	if (!srt->send) {
		crypto->version = version;
		memcpy(crypto->rx_secret[phase], srt->secret,
		       cipher->secretlen);
		err = quic_crypto_keys_derive_and_install(crypto, true, phase);
		if (err)
			return err;
		crypto->recv_ready = 1;
		return 0;
	}

	/* Handle TX path setup. */
	crypto->version = version;
	memcpy(crypto->tx_secret[phase], srt->secret, cipher->secretlen);
	err = quic_crypto_keys_derive_and_install(crypto, false, phase);
	if (err)
		return err;
	crypto->send_ready = 1;
	return 0;
}

/* Save token secret in Initial TX secret (phase 1) for token generation. */
int quic_crypto_set_token_secret(struct quic_crypto *crypto)
{
	/* Reuse TX AEAD (phase 1) in Initial crypto. */
	u8 key[TLS_CIPHER_AES_GCM_128_KEY_SIZE], *srt = crypto->tx_secret[1];
	struct crypto_aead *tfm = crypto->tx_tfm[1];
	struct quic_data s = {}, k, i;
	int err;

	if (!memchr_inv(srt, 0, TLS_CIPHER_AES_GCM_128_SECRET_SIZE))
		get_random_bytes(srt, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);

	quic_data(&s, srt, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	quic_data(&k, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	quic_data(&i, crypto->tx_iv[1], QUIC_IV_LEN);
	err = quic_crypto_keys_derive(crypto->secret_tfm, &s, &k, &i, NULL,
				      QUIC_VERSION_V1);
	if (err)
		goto out;
	err = crypto_aead_setauthsize(tfm, QUIC_TAG_LEN);
	if (err)
		goto out;
	err = crypto_aead_setkey(tfm, key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
out:
	memzero_explicit(key, sizeof(key));
	return err;
}

/* Initiating a Key Update. */
int quic_crypto_key_update(struct quic_crypto *crypto)
{
	struct quic_data l = {KU_LABEL_V1, strlen(KU_LABEL_V1)};
	u8 phase = crypto->key_phase;
	struct quic_data k, srt;
	u32 secret_len;
	int err;

	if (crypto->key_pending || !crypto->recv_ready)
		return -EINVAL;
	if (crypto->key_derived)
		return 0;

	/* rfc9001#section-6.1:
	 *
	 * Endpoints maintain separate read and write secrets for packet
	 * protection. An endpoint initiates a key update by updating its
	 * packet protection write secret and using that to protect new
	 * packets. The endpoint creates a new write secret from the existing
	 * write secret. This uses the KDF function provided by TLS with a
	 * label of "quic ku". The corresponding key and IV are created from
	 * that secret. The header protection key is not updated.
	 *
	 * For example, to update write keys with TLS 1.3, HKDF-Expand-Label is
	 * used as:
	 *   secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku",
	 *                                    "", Hash.length)
	 */
	secret_len = crypto->cipher->secretlen;
	if (crypto->version == QUIC_VERSION_V2)
		quic_data(&l, KU_LABEL_V2, strlen(KU_LABEL_V2));

	quic_data(&srt, crypto->tx_secret[phase], secret_len);
	quic_data(&k, crypto->tx_secret[!phase], secret_len);
	err = quic_crypto_hkdf_expand(crypto->secret_tfm, &srt, &l, &k);
	if (err)
		return err;
	err = quic_crypto_keys_derive_and_install(crypto, false, !phase);
	if (err)
		return err;

	quic_data(&srt, crypto->rx_secret[phase], secret_len);
	quic_data(&k, crypto->rx_secret[!phase], secret_len);
	err = quic_crypto_hkdf_expand(crypto->secret_tfm, &srt, &l, &k);
	if (err)
		return err;
	err = quic_crypto_keys_derive_and_install(crypto, true, !phase);
	if (err)
		return err;

	crypto->key_derived = 1;
	return 0;
}

void quic_crypto_free(struct quic_crypto *crypto)
{
	if (crypto->rx_tfm[0])
		crypto_free_aead(crypto->rx_tfm[0]);
	if (crypto->rx_tfm[1])
		crypto_free_aead(crypto->rx_tfm[1]);
	if (crypto->tx_tfm[0])
		crypto_free_aead(crypto->tx_tfm[0]);
	if (crypto->tx_tfm[1])
		crypto_free_aead(crypto->tx_tfm[1]);
	if (crypto->secret_tfm)
		crypto_free_shash(crypto->secret_tfm);
	if (crypto->rx_hp_tfm)
		crypto_free_skcipher(crypto->rx_hp_tfm);
	if (crypto->tx_hp_tfm)
		crypto_free_skcipher(crypto->tx_hp_tfm);

	memzero_explicit(crypto, offsetof(struct quic_crypto, send_offset));
}

#define QUIC_INITIAL_SALT_V1 \
	"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17" \
	"\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a"

#define QUIC_INITIAL_SALT_V2 \
	"\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93" \
	"\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9"

#define QUIC_INITIAL_SALT_LEN	20

/* Initial Secrets. */
int quic_crypto_initial_keys_install(struct quic_crypto *crypto,
				     struct quic_conn_id *conn_id,
				     u32 version, bool is_serv)
{
	u8 secret[TLS_CIPHER_AES_GCM_128_SECRET_SIZE];
	struct quic_data salt, s, k, l, dcid;
	struct quic_crypto_secret srt = {};
	char *tl, *rl, *sal;
	int err;

	/* rfc9001#section-5.2:
	 *
	 * The secret used by clients to construct Initial packets uses the PRK
	 * and the label "client in" as input to the HKDF-Expand-Label function
	 * from TLS [TLS13] to produce a 32-byte secret. Packets constructed by
	 * the server use the same process with the label "server in". The hash
	 * function for HKDF when deriving initial secrets and keys is SHA-256
	 * [SHA].
	 *
	 * This process in pseudocode is:
	 *
	 *   initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
	 *   initial_secret = HKDF-Extract(initial_salt,
	 *                                 client_dst_connection_id)
	 *
	 *   client_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                             "client in", "",
	 *                                             Hash.length)
	 *   server_initial_secret = HKDF-Expand-Label(initial_secret,
	 *                                             "server in", "",
	 *                                             Hash.length)
	 */
	if (is_serv) {
		rl = "client in";
		tl = "server in";
	} else {
		tl = "client in";
		rl = "server in";
	}
	sal = QUIC_INITIAL_SALT_V1;
	if (version == QUIC_VERSION_V2)
		sal = QUIC_INITIAL_SALT_V2;
	quic_data(&salt, sal, QUIC_INITIAL_SALT_LEN);
	quic_data(&dcid, conn_id->data, conn_id->len);
	quic_data(&s, secret, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	err = quic_crypto_hkdf_extract(crypto->secret_tfm, &salt, &dcid, &s);
	if (err)
		goto out;

	quic_data(&l, tl, strlen(tl));
	quic_data(&k, srt.secret, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 1;
	err = quic_crypto_hkdf_expand(crypto->secret_tfm, &s, &l, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt, version);
	if (err)
		goto out;

	quic_data(&l, rl, strlen(rl));
	quic_data(&k, srt.secret, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	srt.type = TLS_CIPHER_AES_GCM_128;
	srt.send = 0;
	err = quic_crypto_hkdf_expand(crypto->secret_tfm, &s, &l, &k);
	if (err)
		goto out;
	err = quic_crypto_set_secret(crypto, &srt, version);
out:
	memzero_explicit(secret, sizeof(secret));
	memzero_explicit(&srt, sizeof(srt));
	return err;
}

/* Derive a secret using HKDF-Extract and HKDF-Expand with the given label.
 * Used to generate a stateless reset token or session resumption master key.
 */
int quic_crypto_derive_secret(struct quic_crypto *crypto, void *data, u32 len,
			      char *label, u8 *srt, u32 srt_len)
{
	struct crypto_shash *tfm = crypto->secret_tfm;
	u8 secret[TLS_CIPHER_AES_GCM_128_SECRET_SIZE];
	struct quic_data salt, s, l, k;
	int err;

	quic_data(&salt, data, len);
	quic_data(&k, crypto->tx_secret[1], TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	quic_data(&s, secret, TLS_CIPHER_AES_GCM_128_SECRET_SIZE);
	err = quic_crypto_hkdf_extract(tfm, &salt, &k, &s);
	if (err)
		goto out;

	quic_data(&l, label, strlen(label));
	quic_data(&k, srt, srt_len);
	err = quic_crypto_hkdf_expand(tfm, &s, &l, &k);
out:
	memzero_explicit(secret, sizeof(secret));
	return err;
}
