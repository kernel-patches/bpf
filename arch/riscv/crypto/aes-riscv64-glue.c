// SPDX-License-Identifier: GPL-2.0-only
/*
 * AES modes using the RISC-V vector crypto extensions
 *
 * Copyright (C) 2023 VRULL GmbH
 * Author: Heiko Stuebner <heiko.stuebner@vrull.eu>
 *
 * Copyright (C) 2023 SiFive, Inc.
 * Author: Jerry Shih <jerry.shih@sifive.com>
 *
 * Copyright 2024 Google LLC
 */

#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/aes.h>
#include <crypto/internal/simd.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <crypto/xts.h>
#include <linux/linkage.h>
#include <linux/minmax.h>
#include <linux/module.h>

asmlinkage void aes_xts_encrypt_zvkned_zvbb_zvkg(
			const struct crypto_aes_ctx *key,
			const u8 *in, u8 *out, size_t len,
			u8 tweak[AES_BLOCK_SIZE]);

asmlinkage void aes_xts_decrypt_zvkned_zvbb_zvkg(
			const struct crypto_aes_ctx *key,
			const u8 *in, u8 *out, size_t len,
			u8 tweak[AES_BLOCK_SIZE]);

static int riscv64_aes_setkey(struct crypto_aes_ctx *ctx,
			      const u8 *key, unsigned int keylen)
{
	/*
	 * For now we just use the generic key expansion, for these reasons:
	 *
	 * - zvkned's key expansion instructions don't support AES-192.
	 *   So, non-zvkned fallback code would be needed anyway.
	 *
	 * - Users of AES in Linux usually don't change keys frequently.
	 *   So, key expansion isn't performance-critical.
	 *
	 * - For single-block AES exposed as a "cipher" algorithm, it's
	 *   necessary to use struct crypto_aes_ctx and initialize its 'key_dec'
	 *   field with the round keys for the Equivalent Inverse Cipher.  This
	 *   is because with "cipher", decryption can be requested from a
	 *   context where the vector unit isn't usable, necessitating a
	 *   fallback to aes_decrypt().  But, zvkned can only generate and use
	 *   the normal round keys.  Of course, it's preferable to not have
	 *   special code just for "cipher", as e.g. XTS also uses a
	 *   single-block AES encryption.  It's simplest to just use
	 *   struct crypto_aes_ctx and aes_expandkey() everywhere.
	 */
	return aes_expandkey(ctx, key, keylen);
}

/* AES-XTS */

struct riscv64_aes_xts_ctx {
	struct crypto_aes_ctx ctx1;
	struct aes_enckey tweak_key;
};

static int riscv64_aes_xts_setkey(struct crypto_skcipher *tfm, const u8 *key,
				  unsigned int keylen)
{
	struct riscv64_aes_xts_ctx *ctx = crypto_skcipher_ctx(tfm);

	return xts_verify_key(tfm, key, keylen) ?:
	       riscv64_aes_setkey(&ctx->ctx1, key, keylen / 2) ?:
	       aes_prepareenckey(&ctx->tweak_key, key + keylen / 2, keylen / 2);
}

static int riscv64_aes_xts_crypt(struct skcipher_request *req, bool enc)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct riscv64_aes_xts_ctx *ctx = crypto_skcipher_ctx(tfm);
	int tail = req->cryptlen % AES_BLOCK_SIZE;
	struct scatterlist sg_src[2], sg_dst[2];
	struct skcipher_request subreq;
	struct scatterlist *src, *dst;
	struct skcipher_walk walk;
	int err;

	if (req->cryptlen < AES_BLOCK_SIZE)
		return -EINVAL;

	/* Encrypt the IV with the tweak key to get the first tweak. */
	aes_encrypt(&ctx->tweak_key, req->iv, req->iv);

	err = skcipher_walk_virt(&walk, req, false);

	/*
	 * If the message length isn't divisible by the AES block size and the
	 * full message isn't available in one step of the scatterlist walk,
	 * then separate off the last full block and the partial block.  This
	 * ensures that they are processed in the same call to the assembly
	 * function, which is required for ciphertext stealing.
	 */
	if (unlikely(tail > 0 && walk.nbytes < walk.total)) {
		skcipher_walk_abort(&walk);

		skcipher_request_set_tfm(&subreq, tfm);
		skcipher_request_set_callback(&subreq,
					      skcipher_request_flags(req),
					      NULL, NULL);
		skcipher_request_set_crypt(&subreq, req->src, req->dst,
					   req->cryptlen - tail - AES_BLOCK_SIZE,
					   req->iv);
		req = &subreq;
		err = skcipher_walk_virt(&walk, req, false);
	} else {
		tail = 0;
	}

	while (walk.nbytes) {
		unsigned int nbytes = walk.nbytes;

		if (nbytes < walk.total)
			nbytes = round_down(nbytes, AES_BLOCK_SIZE);

		kernel_vector_begin();
		if (enc)
			aes_xts_encrypt_zvkned_zvbb_zvkg(
				&ctx->ctx1, walk.src.virt.addr,
				walk.dst.virt.addr, nbytes, req->iv);
		else
			aes_xts_decrypt_zvkned_zvbb_zvkg(
				&ctx->ctx1, walk.src.virt.addr,
				walk.dst.virt.addr, nbytes, req->iv);
		kernel_vector_end();
		err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
	}

	if (err || likely(!tail))
		return err;

	/* Do ciphertext stealing with the last full block and partial block. */

	dst = src = scatterwalk_ffwd(sg_src, req->src, req->cryptlen);
	if (req->dst != req->src)
		dst = scatterwalk_ffwd(sg_dst, req->dst, req->cryptlen);

	skcipher_request_set_crypt(req, src, dst, AES_BLOCK_SIZE + tail,
				   req->iv);

	err = skcipher_walk_virt(&walk, req, false);
	if (err)
		return err;

	kernel_vector_begin();
	if (enc)
		aes_xts_encrypt_zvkned_zvbb_zvkg(
			&ctx->ctx1, walk.src.virt.addr,
			walk.dst.virt.addr, walk.nbytes, req->iv);
	else
		aes_xts_decrypt_zvkned_zvbb_zvkg(
			&ctx->ctx1, walk.src.virt.addr,
			walk.dst.virt.addr, walk.nbytes, req->iv);
	kernel_vector_end();

	return skcipher_walk_done(&walk, 0);
}

static int riscv64_aes_xts_encrypt(struct skcipher_request *req)
{
	return riscv64_aes_xts_crypt(req, true);
}

static int riscv64_aes_xts_decrypt(struct skcipher_request *req)
{
	return riscv64_aes_xts_crypt(req, false);
}

/* Algorithm definitions */

static struct skcipher_alg riscv64_zvkned_zvbb_zvkg_aes_skcipher_alg = {
	.setkey = riscv64_aes_xts_setkey,
	.encrypt = riscv64_aes_xts_encrypt,
	.decrypt = riscv64_aes_xts_decrypt,
	.min_keysize = 2 * AES_MIN_KEY_SIZE,
	.max_keysize = 2 * AES_MAX_KEY_SIZE,
	.ivsize = AES_BLOCK_SIZE,
	.chunksize = AES_BLOCK_SIZE,
	.walksize = 4 * AES_BLOCK_SIZE, /* matches LMUL=4 */
	.base = {
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct riscv64_aes_xts_ctx),
		.cra_priority = 300,
		.cra_name = "xts(aes)",
		.cra_driver_name = "xts-aes-riscv64-zvkned-zvbb-zvkg",
		.cra_module = THIS_MODULE,
	},
};

static inline bool riscv64_aes_xts_supported(void)
{
	return riscv_isa_extension_available(NULL, ZVBB) &&
	       riscv_isa_extension_available(NULL, ZVKG) &&
	       riscv_vector_vlen() < 2048 /* Implementation limitation */;
}

static int __init riscv64_aes_mod_init(void)
{
	int err = -ENODEV;

	if (riscv_isa_extension_available(NULL, ZVKNED) &&
	    riscv_vector_vlen() >= 128) {
		if (riscv64_aes_xts_supported()) {
			err = crypto_register_skcipher(
				&riscv64_zvkned_zvbb_zvkg_aes_skcipher_alg);
			if (err)
				return err;
		}
	}

	return err;
}

static void __exit riscv64_aes_mod_exit(void)
{
	crypto_unregister_skcipher(&riscv64_zvkned_zvbb_zvkg_aes_skcipher_alg);
}

module_init(riscv64_aes_mod_init);
module_exit(riscv64_aes_mod_exit);

MODULE_DESCRIPTION("AES-XTS (RISC-V accelerated)");
MODULE_AUTHOR("Jerry Shih <jerry.shih@sifive.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("aes");
MODULE_ALIAS_CRYPTO("xts(aes)");
