// SPDX-License-Identifier: GPL-2.0

#include <linux/dmapool.h>
#include <crypto/sha1.h>
#include <crypto/sm4.h>
#include <crypto/sha2.h>
#include <crypto/sha3.h>
#include <crypto/md5.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/hash.h>
#include <crypto/engine.h>
#include <linux/delay.h>
#include <linux/atomic.h>

#include "spacc_device.h"
#include "spacc_core.h"

#define PPP_BUF_SIZE 128

static struct mode_tab possible_hashes[] = {
	{ MODE_TAB_HASH("cmac(sm4)",	MAC_SM4_CMAC, 16, 16) },
	{ .keylen[0] = 32 | MODE_TAB_HASH_XCBC, MODE_TAB_HASH("xcbc(sm4)",
	MAC_SM4_XCBC, 16, 16) },

	{ MODE_TAB_HASH("hmac(md5)",	HMAC_MD5, MD5_DIGEST_SIZE,
	MD5_HMAC_BLOCK_SIZE) },
	{ MODE_TAB_HASH("md5",		HASH_MD5, MD5_DIGEST_SIZE,
	MD5_HMAC_BLOCK_SIZE) },

	{ MODE_TAB_HASH("hmac(sha1)",	HMAC_SHA1, SHA1_DIGEST_SIZE,
	SHA1_BLOCK_SIZE) },
	{ MODE_TAB_HASH("sha1",		HASH_SHA1, SHA1_DIGEST_SIZE,
	SHA1_BLOCK_SIZE) },

	{ MODE_TAB_HASH("sha224",	HASH_SHA224, SHA224_DIGEST_SIZE,
	SHA224_BLOCK_SIZE) },
	{ MODE_TAB_HASH("sha256",	HASH_SHA256, SHA256_DIGEST_SIZE,
	SHA256_BLOCK_SIZE) },
	{ MODE_TAB_HASH("sha384",	HASH_SHA384, SHA384_DIGEST_SIZE,
	SHA384_BLOCK_SIZE) },
	{ MODE_TAB_HASH("sha512",	HASH_SHA512, SHA512_DIGEST_SIZE,
	SHA512_BLOCK_SIZE) },

	{ MODE_TAB_HASH("hmac(sha512)",	HMAC_SHA512, SHA512_DIGEST_SIZE,
	SHA512_BLOCK_SIZE) },
	{ MODE_TAB_HASH("hmac(sha224)",	HMAC_SHA224, SHA224_DIGEST_SIZE,
	SHA224_BLOCK_SIZE) },
	{ MODE_TAB_HASH("hmac(sha256)",	HMAC_SHA256, SHA256_DIGEST_SIZE,
	SHA256_BLOCK_SIZE) },
	{ MODE_TAB_HASH("hmac(sha384)",	HMAC_SHA384, SHA384_DIGEST_SIZE,
	SHA384_BLOCK_SIZE) },

	{ MODE_TAB_HASH("sha3-224",	HASH_SHA3_224, SHA3_224_DIGEST_SIZE,
	SHA3_224_BLOCK_SIZE) },
	{ MODE_TAB_HASH("sha3-256",	HASH_SHA3_256, SHA3_256_DIGEST_SIZE,
	SHA3_256_BLOCK_SIZE) },
	{ MODE_TAB_HASH("sha3-384",	HASH_SHA3_384, SHA3_384_DIGEST_SIZE,
	SHA3_384_BLOCK_SIZE) },
	{ MODE_TAB_HASH("sha3-512",	HASH_SHA3_512, SHA3_512_DIGEST_SIZE,
	SHA3_512_BLOCK_SIZE) },
};

static void spacc_hash_cleanup_dma_dst(struct ahash_request *req)
{
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);

	pdu_ddt_free(&ctx->dst);
}

static void spacc_hash_cleanup_dma_src(struct spacc_crypto_ctx *tctx,
				       struct ahash_request *req)
{
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);

	if (tctx->tmp_sgl && tctx->tmp_sgl[0].length != 0) {
		dma_unmap_sg(tctx->dev, tctx->tmp_sgl, ctx->src_nents,
			     DMA_TO_DEVICE);
		tctx->tmp_sgl[0].length = 0;
	} else {
		dma_unmap_sg(tctx->dev, req->src, ctx->src_nents,
			     DMA_TO_DEVICE);
	}

	pdu_ddt_free(&ctx->src);
}

static int spacc_init_calg(struct crypto_alg *calg,
			   const struct mode_tab *mode)
{
	if (strscpy(calg->cra_name, mode->name) < 0)
		return -ENAMETOOLONG;

	if (snprintf(calg->cra_driver_name, CRYPTO_MAX_ALG_NAME,
			"spacc-%s", mode->name) >= CRYPTO_MAX_ALG_NAME)
		return -ENAMETOOLONG;

	calg->cra_blocksize = mode->blocklen;

	return 0;
}

static int spacc_hash_init_dma(struct device *dev, struct ahash_request *req)
{
	int rc = -1;
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct spacc_crypto_ctx *tctx = crypto_ahash_ctx(tfm);
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);
	struct spacc_priv *priv = tctx->priv;
	gfp_t mflags = GFP_KERNEL;

	ctx->digest_buf = dma_pool_alloc(priv->hash_pool, mflags,
					 &ctx->digest_dma);
	if (!ctx->digest_buf)
		return -ENOMEM;

	rc = pdu_ddt_init(dev, &ctx->dst, 1 | 0x80000000);
	if (rc < 0) {
		dev_err(dev, "ERR: PDU DDT init error\n");
		rc = -EIO;
		goto err_free_digest;
	}

	pdu_ddt_add(dev, &ctx->dst, ctx->digest_dma, SPACC_MAX_DIGEST_SIZE);

	if (ctx->total_nents > 0 && ctx->single_shot) {
		if (req->nbytes) {
			rc = spacc_sg_to_ddt(dev, req->src, req->nbytes,
				&ctx->src, DMA_TO_DEVICE);
		} else {
			memset(tctx->tmp_buffer, '\0', PPP_BUF_SIZE);
			sg_set_buf(&tctx->tmp_sgl[0], tctx->tmp_buffer,
				PPP_BUF_SIZE);
			rc = spacc_sg_to_ddt(dev, &tctx->tmp_sgl[0],
				tctx->tmp_sgl[0].length,
				&ctx->src, DMA_TO_DEVICE);
		}
	} else if (ctx->total_nents == 0 && req->nbytes == 0) {
		/* zero length case */
		memset(tctx->tmp_buffer, '\0', PPP_BUF_SIZE);
		sg_set_buf(&tctx->tmp_sgl[0], tctx->tmp_buffer, PPP_BUF_SIZE);
		rc = spacc_sg_to_ddt(dev, &tctx->tmp_sgl[0],
				tctx->tmp_sgl[0].length,
				&ctx->src, DMA_TO_DEVICE);
	} else {
		dev_err(dev, "ERR: empty src sg with nbytes=%u\n", req->nbytes);
		rc = -EINVAL;
		goto err_free_dst;
	}

	if (rc < 0)
		goto err_free_dst;

	ctx->src_nents = rc;
	return rc;

err_free_dst:
	pdu_ddt_free(&ctx->dst);

err_free_digest:
	dma_pool_free(priv->hash_pool, ctx->digest_buf, ctx->digest_dma);

	return rc;
}

static void spacc_free_mems(struct spacc_crypto_reqctx *ctx,
			    struct spacc_crypto_ctx *tctx,
			    struct ahash_request *req)
{
	spacc_hash_cleanup_dma_dst(req);
	spacc_hash_cleanup_dma_src(tctx, req);

	if (ctx->single_shot) {
		kfree(tctx->tmp_sgl);
		tctx->tmp_sgl = NULL;

		ctx->single_shot = 0;
		if (ctx->total_nents)
			ctx->total_nents = 0;
	}
}

static void spacc_digest_cb(void *spacc, void *tfm)
{
	int err;
	int dig_sz;
	struct ahash_cb_data *cb = tfm;
	struct spacc_device *device = spacc;
	struct spacc_priv *priv = container_of(device, struct spacc_priv,
					       spacc);

	dig_sz = crypto_ahash_digestsize(crypto_ahash_reqtfm(cb->req));

	err = cb->spacc->job[cb->new_handle].job_err;

	if (!err)
		memcpy(cb->req->result, cb->ctx->digest_buf, dig_sz);

	dma_pool_free(priv->hash_pool, cb->ctx->digest_buf,
			cb->ctx->digest_dma);

	spacc_free_mems(cb->ctx, cb->tctx, cb->req);
	spacc_close(cb->spacc, cb->new_handle);

	local_bh_disable();
	crypto_finalize_hash_request(priv->engine, cb->req, err);
	local_bh_enable();

	/*
	 * This decrement must run exactly once for every enqueued job (it
	 * balances the atomic_inc in spacc_hash_do_one_request and releases
	 * the drain in spacc_crypto_remove).
	 */
	if (atomic_dec_and_test(&priv->dma_ref_cnt))
		wake_up(&priv->drain_wq);
}

static int spacc_ctx_open_handle(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct spacc_crypto_ctx *tctx = crypto_ahash_ctx(tfm);
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);
	const struct spacc_alg *salg = spacc_tfm_ahash(&tfm->base);
	struct spacc_priv *priv = tctx->priv;
	u8 keybuf[sizeof(tctx->ipad)];
	unsigned int klen;
	int h, rc;

	if (!priv)
		return -ENODEV;

	h = spacc_open(&priv->spacc, CRYPTO_MODE_NULL, salg->mode->id,
		       -1, 0, spacc_digest_cb, &ctx->acb);
	if (h < 0)
		return h;

	rc = spacc_set_operation(&priv->spacc, h, OP_ENCRYPT, ICV_HASH,
				 IP_ICV_OFFSET, 0, 0, 0);
	if (rc < 0)
		goto err_close;

	spin_lock_bh(&tctx->key_lock);
	klen = tctx->keylen;
	memcpy(keybuf, tctx->ipad, klen);
	spin_unlock_bh(&tctx->key_lock);

	if (klen) {
		if (salg->mode->id == CRYPTO_MODE_MAC_SM4_XCBC) {
			rc = spacc_compute_xcbc_key(&priv->spacc, salg->mode->id,
					    h, keybuf, klen, keybuf);
			if (rc < 0)
				goto err_zero;
			rc = spacc_write_context(&priv->spacc, h,
					 SPACC_HASH_OPERATION,
					 keybuf, 32 + klen, NULL, 0);
		} else {
			rc = spacc_write_context(&priv->spacc, h,
					 SPACC_HASH_OPERATION,
					 keybuf, klen, NULL, 0);
		}
		if (rc < 0)
			goto err_zero;
	}
	memzero_explicit(keybuf, sizeof(keybuf));

	ctx->acb.new_handle = h;
	ctx->acb.tctx  = tctx;
	ctx->acb.ctx   = ctx;
	ctx->acb.req   = req;
	ctx->acb.spacc = &priv->spacc;
	return 0;

err_zero:
	memzero_explicit(keybuf, sizeof(keybuf));
err_close:
	spacc_close(&priv->spacc, h);
	return rc;
}

static int spacc_hash_commit_key(struct crypto_ahash *tfm,
				 const u8 *key, unsigned int keylen,
				 const u8 *keybuf, unsigned int klen)
{
	struct spacc_crypto_ctx *tctx = crypto_ahash_ctx(tfm);
	struct crypto_ahash *fb = crypto_ahash_fb(tfm);
	int ret;

	if (fb) {
		ret = crypto_ahash_setkey(fb, key, keylen);
		if (ret)
			return ret;
	}

	spin_lock_bh(&tctx->key_lock);
	memcpy(tctx->ipad, keybuf, klen);
	tctx->keylen = klen;
	spin_unlock_bh(&tctx->key_lock);

	return 0;
}

static int spacc_hash_setkey(struct crypto_ahash *tfm, const u8 *key,
			     unsigned int keylen)
{
	unsigned int block_size;
	unsigned int digest_size;
	const struct spacc_alg *salg = spacc_tfm_ahash(&tfm->base);
	struct spacc_crypto_ctx *tctx = crypto_ahash_ctx(tfm);
	struct spacc_priv *priv = tctx->priv;
	u8 keybuf[sizeof(tctx->ipad)];
	unsigned int klen;
	int ret = 0;

	if (!priv)
		return -ENODEV;

	block_size = crypto_tfm_alg_blocksize(&tfm->base);
	digest_size = crypto_ahash_digestsize(tfm);

	/*
	 * We are using hardware for HMAC operations. The software fallback is
	 * only for key pre-processing in case of HMACs.
	 * This was meant for hashes but it also works for cmac/xcbc.
	 */
	if (keylen > block_size) {
		dev_dbg(salg->dev, "Exceeds keylen: %u\n", keylen);
		dev_dbg(salg->dev, "Req. keylen hashing %s\n",
				salg->calg->cra_name);

		switch (salg->mode->id) {
		case CRYPTO_MODE_HMAC_SHA224:
			sha224(key, keylen, keybuf);
			break;

		case CRYPTO_MODE_HMAC_SHA256:
			sha256(key, keylen, keybuf);
			break;

		case CRYPTO_MODE_HMAC_SHA384:
			sha384(key, keylen, keybuf);
			break;

		case CRYPTO_MODE_HMAC_SHA512:
			sha512(key, keylen, keybuf);
			break;

		case CRYPTO_MODE_HMAC_MD5:
			md5(key, keylen, keybuf);
			break;

		case CRYPTO_MODE_HMAC_SHA1:
			sha1(key, keylen, keybuf);
			break;
		default:
			ret = -EINVAL;
			goto out;
		}

		klen = digest_size;
		dev_dbg(salg->dev, "updated keylen: %u\n", keylen);
	} else {
		/*
		 * CMAC/XCBC skip the hashing path above, and via AF_ALG the
		 * key length is fully user-controlled.  tctx->ipad is a fixed
		 * 128-byte buffer, so reject anything that would not fit
		 * before copying to prevent a heap buffer overflow.
		 */
		if (keylen > sizeof(keybuf)) {
			ret = -EINVAL;
			goto out;
		}

		/*
		 * Enforcing valid block-cipher key sizes supported by SPAcc:
		 *  - AES-CMAC accepts 16/24/32,
		 *  - SM4-CMAC/XCBC/SM4-XCBC only 16.
		 */
		memcpy(keybuf, key, keylen);
		klen = keylen;

		/*
		 * An empty HMAC key is the same as an all-zero key, because
		 * HMAC pads the key with zeros. Program one zero byte so a
		 * key is always written to the hardware context.
		 */
		if (!klen) {
			keybuf[0] = 0;
			klen = 1;
		}
	}

	if (!spacc_is_mode_keysize_supported(&priv->spacc, salg->mode->id,
				klen, 1)) {
		dev_dbg(salg->dev, "keylen %u not supported for mode %d\n",
				klen, salg->mode->id);
		ret = -EINVAL;
		goto out;
	}

	ret = spacc_hash_commit_key(tfm, key, keylen, keybuf, klen);

out:
	memzero_explicit(keybuf, sizeof(keybuf));
	return ret;
}

static int spacc_hash_try_hw(struct spacc_crypto_ctx *tctx,
			     struct spacc_priv *priv,
			     const struct spacc_alg *salg,
			     struct crypto_ahash *reqtfm,
			     struct ahash_request *req)
{
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);
	int rc = spacc_ctx_open_handle(req);

	if (rc < 0)
		return rc;

	rc = spacc_hash_init_dma(tctx->dev, req);
	if (rc < 0) {
		spacc_close(&priv->spacc, ctx->acb.new_handle);
		ctx->acb.new_handle = -1;
		return rc;
	}

	return 0;
}

/* Crypto engine hash operation */
static int spacc_hash_do_one_request(struct crypto_engine *engine, void *areq)
{
	int rc = 0;
	struct ahash_request *req = ahash_request_cast(areq);
	struct crypto_ahash *reqtfm = crypto_ahash_reqtfm(req);
	struct spacc_crypto_ctx *tctx = crypto_ahash_ctx(reqtfm);
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);
	const struct spacc_alg *salg = spacc_tfm_ahash(&reqtfm->base);

	struct spacc_priv *priv = tctx->priv;

	ctx->single_shot = 1;
	ctx->total_nents = sg_nents(req->src);
	if (req->nbytes > priv->max_msg_len)
		goto fallback;

	tctx->tmp_sgl = kmalloc_array(2, sizeof(*tctx->tmp_sgl), GFP_KERNEL);
	if (!tctx->tmp_sgl)
		goto fallback;

	sg_init_table(tctx->tmp_sgl, 2);
	tctx->tmp_sgl[0].length = 0;

	if (spacc_hash_try_hw(tctx, priv, salg, reqtfm, req) < 0)
		goto fallback;

	atomic_inc(&priv->dma_ref_cnt);

	rc = spacc_packet_enqueue_ddt(&priv->spacc, ctx->acb.new_handle,
			&ctx->src, &ctx->dst, req->nbytes,
			0, req->nbytes, 0, 0, 0, false);
	if (rc < 0) {

		spacc_free_mems(ctx, tctx, req);
		dma_pool_free(priv->hash_pool, ctx->digest_buf,
				ctx->digest_dma);
		pdu_ddt_free(&ctx->dst);

		if (ctx->acb.new_handle >= 0) {
			spacc_close(&priv->spacc, ctx->acb.new_handle);
			ctx->acb.new_handle = -1;
		}

		if (rc == -EBUSY)
			dev_dbg(salg->dev, "HW full, failing request\n");

		local_bh_disable();
		crypto_finalize_hash_request(priv->engine, req, rc);
		local_bh_enable();

		if (atomic_dec_and_test(&priv->dma_ref_cnt))
			wake_up(&priv->drain_wq);

		return 0;
	}

	return 0;

fallback:
	kfree(tctx->tmp_sgl);
	tctx->tmp_sgl = NULL;

	HASH_FBREQ_ON_STACK(fbreq, req);
	rc = crypto_ahash_digest(fbreq);
	HASH_REQUEST_ZERO(fbreq);

	local_bh_disable();
	crypto_finalize_hash_request(engine, req, rc);
	local_bh_enable();

	return 0;
}

static int spacc_hash_init_tfm(struct crypto_ahash *tfm)
{
	const struct spacc_alg *salg = container_of(crypto_ahash_alg(tfm),
						    struct spacc_alg,
						    alg.hash.base);
	struct spacc_crypto_ctx *tctx = crypto_ahash_ctx(tfm);
	struct spacc_priv *priv = salg->priv;

	tctx->dev       = get_device(salg->dev);
	tctx->priv      = priv;
	kref_get(&priv->ref);
	spin_lock_init(&tctx->key_lock);

	crypto_ahash_set_statesize(tfm,
				   crypto_ahash_statesize(crypto_ahash_fb(tfm)));

	return 0;
}

static void spacc_hash_exit_tfm(struct crypto_ahash *tfm)
{
	struct spacc_crypto_ctx *tctx = crypto_ahash_ctx(tfm);
	struct spacc_priv *priv = tctx->priv;

	put_device(tctx->dev);
	kref_put(&priv->ref, spacc_priv_release);
}

static int spacc_hash_init(struct ahash_request *req)
{
	int rc;
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);

	memset(ctx->state_buffer, 0, sizeof(ctx->state_buffer));

	HASH_FBREQ_ON_STACK(fbreq, req);
	rc = crypto_ahash_init(fbreq);
	if (!rc)
		rc = crypto_ahash_export(fbreq, ctx->state_buffer);
	HASH_REQUEST_ZERO(fbreq);

	return rc;
}

static int spacc_hash_update(struct ahash_request *req)
{
	int rc;
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);

	if (!req->nbytes)
		return 0;

	HASH_FBREQ_ON_STACK(fbreq, req);

	rc = crypto_ahash_import(fbreq, ctx->state_buffer);
	if (!rc)
		rc = crypto_ahash_update(fbreq);
	if (!rc)
		rc = crypto_ahash_export(fbreq, ctx->state_buffer);

	HASH_REQUEST_ZERO(fbreq);

	return rc;
}

static int spacc_hash_final(struct ahash_request *req)
{
	int rc;
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);

	HASH_FBREQ_ON_STACK(fbreq, req);
	rc = crypto_ahash_import(fbreq, ctx->state_buffer);
	if (!rc)
		rc = crypto_ahash_final(fbreq);
	HASH_REQUEST_ZERO(fbreq);

	return rc;
}

static int spacc_hash_digest(struct ahash_request *req)
{
	struct crypto_ahash *reqtfm = crypto_ahash_reqtfm(req);
	struct spacc_crypto_ctx *tctx = crypto_ahash_ctx(reqtfm);
	struct spacc_priv *priv = tctx->priv;
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&priv->spacc.lock, flags);
	if (priv->removing)
		ret = -ENODEV;
	else
		ret = crypto_transfer_hash_request_to_engine(priv->engine, req);
	spin_unlock_irqrestore(&priv->spacc.lock, flags);

	return ret;
}

static int spacc_hash_finup(struct ahash_request *req)
{
	int rc;
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);

	HASH_FBREQ_ON_STACK(fbreq, req);
	rc = crypto_ahash_import(fbreq, ctx->state_buffer);
	if (!rc)
		rc = crypto_ahash_finup(fbreq);
	HASH_REQUEST_ZERO(fbreq);

	return rc;
}

static int spacc_hash_export(struct ahash_request *req, void *out)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);

	memcpy(out, ctx->state_buffer, crypto_ahash_statesize(tfm));
	return 0;
}

static int spacc_hash_import(struct ahash_request *req, const void *in)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);
	struct spacc_crypto_reqctx *ctx = ahash_request_ctx(req);

	memcpy(ctx->state_buffer, in, crypto_ahash_statesize(tfm));
	return 0;
}

static void spacc_hash_alg_destroy(struct crypto_alg *alg)
{
	struct spacc_alg *salg = container_of(alg, struct spacc_alg,
					      alg.hash.base.halg.base);
	struct spacc_priv *priv = salg->priv;

	if (!salg->registered)
		return;

	kfree(salg);
	kref_put(&priv->ref, spacc_priv_release);
}

static const struct ahash_engine_alg spacc_hash_template = {
	.base = {
		.init		= spacc_hash_init,
		.update		= spacc_hash_update,
		.final		= spacc_hash_final,
		.finup		= spacc_hash_finup,
		.digest		= spacc_hash_digest,
		.setkey		= spacc_hash_setkey,
		.export		= spacc_hash_export,
		.import		= spacc_hash_import,
		.init_tfm	= spacc_hash_init_tfm,
		.exit_tfm	= spacc_hash_exit_tfm,

		.halg.base = {
			.cra_priority	= 300,
			.cra_module	= THIS_MODULE,
			.cra_ctxsize	= sizeof(struct spacc_crypto_ctx),
			.cra_reqsize	= sizeof(struct spacc_crypto_reqctx),
			.cra_destroy	= spacc_hash_alg_destroy,
			.cra_flags	= CRYPTO_ALG_TYPE_AHASH		|
					  CRYPTO_ALG_ASYNC
		},
	},
	.op = {
		.do_one_request = spacc_hash_do_one_request,
	},
};

/* Keyed algorithms need a setkey(); plain digests must not have one. */
static bool spacc_mode_is_keyed(int id)
{
	switch (id) {
	case CRYPTO_MODE_HMAC_MD5:
	case CRYPTO_MODE_HMAC_SHA1:
	case CRYPTO_MODE_HMAC_SHA224:
	case CRYPTO_MODE_HMAC_SHA256:
	case CRYPTO_MODE_HMAC_SHA384:
	case CRYPTO_MODE_HMAC_SHA512:
	case CRYPTO_MODE_MAC_SM4_CMAC:
	case CRYPTO_MODE_MAC_SM4_XCBC:
		return true;
	default:
		return false;
	}
}

static int spacc_register_hash(struct spacc_alg *salg)
{
	int rc = 0;
	struct spacc_priv *priv = salg->priv;

	salg->calg = &salg->alg.hash.base.halg.base;
	salg->alg.hash = spacc_hash_template;

	/* Unkeyed digests must not advertise a setkey. */
	if (!spacc_mode_is_keyed(salg->mode->id))
		salg->alg.hash.base.setkey = NULL;

	rc = spacc_init_calg(salg->calg, salg->mode);
	if (rc)
		return rc;

	salg->alg.hash.base.halg.digestsize = salg->mode->hashlen;
	{
		struct crypto_ahash *fb;

		/* statesize must equal the software fallback's exported state. */
		fb = crypto_alloc_ahash(salg->calg->cra_name, 0,
					CRYPTO_ALG_ASYNC);
		if (IS_ERR(fb))
			return PTR_ERR(fb);
		salg->alg.hash.base.halg.statesize = crypto_ahash_statesize(fb);
		crypto_free_ahash(fb);
	}

	rc = crypto_engine_register_ahash(&salg->alg.hash);
	if (rc < 0)
		return rc;

	kref_get(&priv->ref);
	salg->registered = true;

	guard(mutex)(&priv->hash_alg_mutex);
	list_add(&salg->list, &priv->hash_alg_list);

	return 0;
}

int spacc_probe_hashes(struct platform_device *spacc_pdev)
{
	int rc = 0;
	unsigned int index;
	int registered = 0;
	struct spacc_alg *salg;
	struct spacc_priv *priv = dev_get_drvdata(&spacc_pdev->dev);
	const char *name = NULL;

	INIT_LIST_HEAD(&priv->hash_alg_list);
	mutex_init(&priv->hash_alg_mutex);

	/* Create per-device DMA pool */
	priv->hash_pool = dma_pool_create("spacc-digest", &spacc_pdev->dev,
			SPACC_MAX_DIGEST_SIZE,
			SPACC_DMA_ALIGN, SPACC_DMA_BOUNDARY);

	if (!priv->hash_pool)
		return -ENOMEM;

	for (index = 0; index < ARRAY_SIZE(possible_hashes); index++) {
		name = possible_hashes[index].name;

		if (!crypto_has_ahash(name, 0, 0))
			continue;

		if (spacc_is_mode_keysize_supported(&priv->spacc,
					possible_hashes[index].id & 0xFF,
					possible_hashes[index].hashlen, 1)) {
			salg = kzalloc_obj(*salg, GFP_KERNEL);
			if (!salg) {
				rc = -ENOMEM;
				goto err_unregister;
			}

			salg->mode = &possible_hashes[index];
			salg->dev = &spacc_pdev->dev;
			salg->priv = priv;

			rc = spacc_register_hash(salg);
			if (rc < 0) {
				kfree(salg);
				continue;
			}
			registered++;
		}
	}

	return registered;

err_unregister:
	spacc_unregister_hash_algs(priv);
	return rc;
}

int spacc_unregister_hash_algs(struct spacc_priv *priv)
{
	struct spacc_alg *salg, *tmp;

	if (!priv)
		return 0;

	guard(mutex)(&priv->hash_alg_mutex);

	list_for_each_entry_safe(salg, tmp, &priv->hash_alg_list, list) {
		list_del(&salg->list);
		crypto_engine_unregister_ahash(&salg->alg.hash);
	}

	return 0;
}
