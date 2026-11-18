// SPDX-License-Identifier: GPL-2.0-only
/* Glue code for AES encryption optimized for sparc64 crypto opcodes.
 *
 * This is based largely upon arch/x86/crypto/aesni-intel_glue.c
 *
 * Copyright (C) 2008, Intel Corp.
 *    Author: Huang Ying <ying.huang@intel.com>
 *
 * Added RFC4106 AES-GCM support for 128-bit keys under the AEAD
 * interface for 64-bit kernels.
 *    Authors: Adrian Hoban <adrian.hoban@intel.com>
 *             Gabriele Paoloni <gabriele.paoloni@intel.com>
 *             Tadeusz Struk (tadeusz.struk@intel.com)
 *             Aidan O'Mahony (aidan.o.mahony@intel.com)
 *    Copyright (c) 2010, Intel Corporation.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <crypto/algapi.h>
#include <crypto/aes.h>
#include <crypto/internal/skcipher.h>

#include <asm/fpumacro.h>
#include <asm/opcodes.h>
#include <asm/pstate.h>
#include <asm/elf.h>

struct aes_ops {
	void (*load_encrypt_keys)(const u64 *key);
	void (*load_decrypt_keys)(const u64 *key);
	void (*cbc_encrypt)(const u64 *key, const u64 *input, u64 *output,
			    unsigned int len, u64 *iv);
	void (*cbc_decrypt)(const u64 *key, const u64 *input, u64 *output,
			    unsigned int len, u64 *iv);
};

struct crypto_sparc64_aes_ctx {
	struct aes_ops *ops;
	u64 key[AES_MAX_KEYLENGTH / sizeof(u64)];
	u32 key_length;
	u32 expanded_key_length;
};

static struct aes_ops aes128_ops = {
	.load_encrypt_keys	= aes_sparc64_load_encrypt_keys_128,
	.load_decrypt_keys	= aes_sparc64_load_decrypt_keys_128,
	.cbc_encrypt		= aes_sparc64_cbc_encrypt_128,
	.cbc_decrypt		= aes_sparc64_cbc_decrypt_128,
};

static struct aes_ops aes192_ops = {
	.load_encrypt_keys	= aes_sparc64_load_encrypt_keys_192,
	.load_decrypt_keys	= aes_sparc64_load_decrypt_keys_192,
	.cbc_encrypt		= aes_sparc64_cbc_encrypt_192,
	.cbc_decrypt		= aes_sparc64_cbc_decrypt_192,
};

static struct aes_ops aes256_ops = {
	.load_encrypt_keys	= aes_sparc64_load_encrypt_keys_256,
	.load_decrypt_keys	= aes_sparc64_load_decrypt_keys_256,
	.cbc_encrypt		= aes_sparc64_cbc_encrypt_256,
	.cbc_decrypt		= aes_sparc64_cbc_decrypt_256,
};

static int aes_set_key_skcipher(struct crypto_skcipher *tfm, const u8 *in_key,
				unsigned int key_len)
{
	struct crypto_sparc64_aes_ctx *ctx = crypto_skcipher_ctx(tfm);

	switch (key_len) {
	case AES_KEYSIZE_128:
		ctx->expanded_key_length = 0xb0;
		ctx->ops = &aes128_ops;
		break;

	case AES_KEYSIZE_192:
		ctx->expanded_key_length = 0xd0;
		ctx->ops = &aes192_ops;
		break;

	case AES_KEYSIZE_256:
		ctx->expanded_key_length = 0xf0;
		ctx->ops = &aes256_ops;
		break;

	default:
		return -EINVAL;
	}

	aes_sparc64_key_expand((const u32 *)in_key, &ctx->key[0], key_len);
	ctx->key_length = key_len;

	return 0;
}

static int cbc_encrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct crypto_sparc64_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, true);
	if (err)
		return err;

	ctx->ops->load_encrypt_keys(&ctx->key[0]);
	while ((nbytes = walk.nbytes) != 0) {
		ctx->ops->cbc_encrypt(&ctx->key[0], walk.src.virt.addr,
				      walk.dst.virt.addr,
				      round_down(nbytes, AES_BLOCK_SIZE),
				      walk.iv);
		err = skcipher_walk_done(&walk, nbytes % AES_BLOCK_SIZE);
	}
	fprs_write(0);
	return err;
}

static int cbc_decrypt(struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct crypto_sparc64_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
	const u64 *key_end;
	struct skcipher_walk walk;
	unsigned int nbytes;
	int err;

	err = skcipher_walk_virt(&walk, req, true);
	if (err)
		return err;

	ctx->ops->load_decrypt_keys(&ctx->key[0]);
	key_end = &ctx->key[ctx->expanded_key_length / sizeof(u64)];
	while ((nbytes = walk.nbytes) != 0) {
		ctx->ops->cbc_decrypt(key_end, walk.src.virt.addr,
				      walk.dst.virt.addr,
				      round_down(nbytes, AES_BLOCK_SIZE),
				      walk.iv);
		err = skcipher_walk_done(&walk, nbytes % AES_BLOCK_SIZE);
	}
	fprs_write(0);

	return err;
}

static struct skcipher_alg skcipher_algs[] = {
	{
		.base.cra_name		= "cbc(aes)",
		.base.cra_driver_name	= "cbc-aes-sparc64",
		.base.cra_priority	= SPARC_CR_OPCODE_PRIORITY,
		.base.cra_blocksize	= AES_BLOCK_SIZE,
		.base.cra_ctxsize	= sizeof(struct crypto_sparc64_aes_ctx),
		.base.cra_alignmask	= 7,
		.base.cra_module	= THIS_MODULE,
		.min_keysize		= AES_MIN_KEY_SIZE,
		.max_keysize		= AES_MAX_KEY_SIZE,
		.ivsize			= AES_BLOCK_SIZE,
		.setkey			= aes_set_key_skcipher,
		.encrypt		= cbc_encrypt,
		.decrypt		= cbc_decrypt,
	}
};

static bool __init sparc64_has_aes_opcode(void)
{
	unsigned long cfr;

	if (!(sparc64_elf_hwcap & HWCAP_SPARC_CRYPTO))
		return false;

	__asm__ __volatile__("rd %%asr26, %0" : "=r" (cfr));
	if (!(cfr & CFR_AES))
		return false;

	return true;
}

static int __init aes_sparc64_mod_init(void)
{
	if (!sparc64_has_aes_opcode()) {
		pr_info("sparc64 aes opcodes not available.\n");
		return -ENODEV;
	}
	pr_info("Using sparc64 aes opcodes optimized AES implementation\n");
	return crypto_register_skciphers(skcipher_algs,
					 ARRAY_SIZE(skcipher_algs));
}

static void __exit aes_sparc64_mod_fini(void)
{
	crypto_unregister_skciphers(skcipher_algs, ARRAY_SIZE(skcipher_algs));
}

module_init(aes_sparc64_mod_init);
module_exit(aes_sparc64_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Rijndael (AES) Cipher Algorithm, sparc64 aes opcode accelerated");

MODULE_ALIAS_CRYPTO("aes");

#include "crop_devid.c"
