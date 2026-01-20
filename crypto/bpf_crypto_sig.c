// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <linux/types.h>
#include <linux/module.h>
#include <linux/bpf_crypto.h>
#include <linux/crypto.h>
#include <crypto/sig.h>

static void *bpf_crypto_sig_alloc_tfm(const char *algo)
{
	return crypto_alloc_sig(algo, 0, 0);
}

static void bpf_crypto_sig_free_tfm(void *tfm)
{
	crypto_free_sig(tfm);
}

static int bpf_crypto_sig_has_algo(const char *algo)
{
	return crypto_has_alg(algo, CRYPTO_ALG_TYPE_SIG, CRYPTO_ALG_TYPE_MASK);
}

static u32 bpf_crypto_sig_get_flags(void *tfm)
{
	return crypto_tfm_get_flags(crypto_sig_tfm(tfm));
}

static int bpf_crypto_sig_setkey(void *tfm, const u8 *key, unsigned int keylen)
{
	return crypto_sig_set_pubkey(tfm, key, keylen);
}

static int bpf_crypto_sig_verify(void *tfm, const u8 *sig, unsigned int sig_len,
				 const u8 *msg, unsigned int msg_len)
{
	return crypto_sig_verify(tfm, sig, sig_len, msg, msg_len);
}

static unsigned int bpf_crypto_sig_keysize(void *tfm)
{
	return crypto_sig_keysize(tfm);
}

static unsigned int bpf_crypto_sig_digestsize(void *tfm)
{
	struct sig_alg *alg = crypto_sig_alg(tfm);

	return alg->digest_size ? alg->digest_size(tfm) : 0;
}

static unsigned int bpf_crypto_sig_maxsize(void *tfm)
{
	struct sig_alg *alg = crypto_sig_alg(tfm);

	return alg->max_size ? alg->max_size(tfm) : 0;
}

static const struct bpf_crypto_type bpf_crypto_sig_type = {
	.alloc_tfm	= bpf_crypto_sig_alloc_tfm,
	.free_tfm	= bpf_crypto_sig_free_tfm,
	.has_algo	= bpf_crypto_sig_has_algo,
	.get_flags	= bpf_crypto_sig_get_flags,
	.setkey		= bpf_crypto_sig_setkey,
	.verify		= bpf_crypto_sig_verify,
	.keysize	= bpf_crypto_sig_keysize,
	.digestsize	= bpf_crypto_sig_digestsize,
	.maxsize	= bpf_crypto_sig_maxsize,
	.owner		= THIS_MODULE,
	.type_id	= BPF_CRYPTO_TYPE_SIG,
	.name		= "sig",
};

static int __init bpf_crypto_sig_init(void)
{
	return bpf_crypto_register_type(&bpf_crypto_sig_type);
}

static void __exit bpf_crypto_sig_exit(void)
{
	int err = bpf_crypto_unregister_type(&bpf_crypto_sig_type);

	WARN_ON_ONCE(err);
}

module_init(bpf_crypto_sig_init);
module_exit(bpf_crypto_sig_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Signature algorithm support for BPF");
