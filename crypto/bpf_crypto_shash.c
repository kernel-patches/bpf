// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <linux/types.h>
#include <linux/module.h>
#include <linux/bpf_crypto.h>
#include <crypto/hash.h>

struct bpf_shash_ctx {
	struct crypto_shash *tfm;
	struct shash_desc desc;
};

static void *bpf_crypto_shash_alloc_tfm(const char *algo)
{
	struct bpf_shash_ctx *ctx;
	struct crypto_shash *tfm;

	tfm = crypto_alloc_shash(algo, 0, 0);
	if (IS_ERR(tfm))
		return tfm;

	ctx = kzalloc(sizeof(*ctx) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!ctx) {
		crypto_free_shash(tfm);
		return ERR_PTR(-ENOMEM);
	}

	ctx->tfm = tfm;
	ctx->desc.tfm = tfm;

	return ctx;
}

static void bpf_crypto_shash_free_tfm(void *tfm)
{
	struct bpf_shash_ctx *ctx = tfm;

	crypto_free_shash(ctx->tfm);
	kfree(ctx);
}

static int bpf_crypto_shash_has_algo(const char *algo)
{
	return crypto_has_shash(algo, 0, 0);
}

static int bpf_crypto_shash_hash(void *tfm, const u8 *data, u8 *out,
				 unsigned int len)
{
	struct bpf_shash_ctx *ctx = tfm;

	return crypto_shash_digest(&ctx->desc, data, len, out);
}

static unsigned int bpf_crypto_shash_digestsize(void *tfm)
{
	struct bpf_shash_ctx *ctx = tfm;

	return crypto_shash_digestsize(ctx->tfm);
}

static u32 bpf_crypto_shash_get_flags(void *tfm)
{
	struct bpf_shash_ctx *ctx = tfm;

	return crypto_shash_get_flags(ctx->tfm);
}

static const struct bpf_crypto_type bpf_crypto_shash_type = {
	.alloc_tfm	= bpf_crypto_shash_alloc_tfm,
	.free_tfm	= bpf_crypto_shash_free_tfm,
	.has_algo	= bpf_crypto_shash_has_algo,
	.hash		= bpf_crypto_shash_hash,
	.digestsize	= bpf_crypto_shash_digestsize,
	.get_flags	= bpf_crypto_shash_get_flags,
	.owner		= THIS_MODULE,
	.type_id	= BPF_CRYPTO_TYPE_HASH,
	.name		= "hash",
};

static int __init bpf_crypto_shash_init(void)
{
	return bpf_crypto_register_type(&bpf_crypto_shash_type);
}

static void __exit bpf_crypto_shash_exit(void)
{
	int err = bpf_crypto_unregister_type(&bpf_crypto_shash_type);

	WARN_ON_ONCE(err);
}

module_init(bpf_crypto_shash_init);
module_exit(bpf_crypto_shash_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hash algorithm support for BPF");
