/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SPACC_DEVICE_H_
#define SPACC_DEVICE_H_

#include <crypto/hash.h>
#include <crypto/ctr.h>
#include <crypto/skcipher.h>
#include <crypto/internal/aead.h>
#include <crypto/engine.h>
#include <linux/of.h>
#include "spacc_core.h"

#define MODE_TAB_AEAD(_name, _ciph, _hash, _hashlen, _ivlen, _blocklen) \
	.name = _name, .aead = { .ciph = _ciph, .hash = _hash }, \
	.hashlen = _hashlen, .ivlen = _ivlen, .blocklen = _blocklen

/* helper macros for initializing the hash/cipher tables */
#define MODE_TAB_COMMON(_name, _id_name, _blocklen) \
	.name = _name, .id = CRYPTO_MODE_##_id_name, .blocklen = _blocklen

#define MODE_TAB_HASH(_name, _id_name, _hashlen, _blocklen) \
	MODE_TAB_COMMON(_name, _id_name, _blocklen), \
	.hashlen = _hashlen, .testlen = _hashlen

#define MODE_TAB_CIPH(_name, _id_name, _ivlen, _blocklen) \
	MODE_TAB_COMMON(_name, _id_name, _blocklen), \
	.ivlen = _ivlen

#define MODE_TAB_HASH_XCBC	0x8000

#define SPACC_MAX_DIGEST_SIZE	64
#define SPACC_MAX_KEY_SIZE	32
#define SPACC_MAX_IV_SIZE	16

#define SPACC_DMA_ALIGN			4
#define SPACC_DMA_BOUNDARY		0x10000
#define SPACC_TEST_DMA_BUFF_SIZE	256

/* flag means the IV is computed from setkey and crypt */
#define SPACC_MANGLE_IV_FLAG	0x8000

/* we're doing a CTR mangle (for RFC3686/IPsec) */
#define SPACC_MANGLE_IV_RFC3686	0x0100

/* we're doing GCM */
#define SPACC_MANGLE_IV_RFC4106	0x0200

/* we're doing GMAC */
#define SPACC_MANGLE_IV_RFC4543	0x0300

/* we're doing CCM */
#define SPACC_MANGLE_IV_RFC4309	0x0400

/* we're doing SM4 GCM/CCM */
#define SPACC_MANGLE_IV_RFC8998	0x0500

#define CRYPTO_MODE_AES_CTR_RFC3686 (CRYPTO_MODE_AES_CTR \
		| SPACC_MANGLE_IV_FLAG \
		| SPACC_MANGLE_IV_RFC3686)
#define CRYPTO_MODE_AES_GCM_RFC4106 (CRYPTO_MODE_AES_GCM \
		| SPACC_MANGLE_IV_FLAG \
		| SPACC_MANGLE_IV_RFC4106)
#define CRYPTO_MODE_AES_GCM_RFC4543 (CRYPTO_MODE_AES_GCM \
		| SPACC_MANGLE_IV_FLAG \
		| SPACC_MANGLE_IV_RFC4543)
#define CRYPTO_MODE_AES_CCM_RFC4309 (CRYPTO_MODE_AES_CCM \
		| SPACC_MANGLE_IV_FLAG \
		| SPACC_MANGLE_IV_RFC4309)
#define CRYPTO_MODE_SM4_GCM_RFC8998 (CRYPTO_MODE_SM4_GCM)
#define CRYPTO_MODE_SM4_CCM_RFC8998 (CRYPTO_MODE_SM4_CCM)

struct spacc_crypto_ctx {
	struct device *dev;
	struct spacc_priv *priv;
	spinlock_t key_lock;

	/* HW hash/MAC key material (staged into the SPAcc context) */
	u8 ipad[128]           __aligned(sizeof(u32));
	u8 digest_ctx_buf[128] __aligned(sizeof(u32));

	/*
	 * tmp_buffer is mapped directly for DMA on zero-length requests.
	 * Must be cacheline-aligned to prevent cache maintenance operations
	 * from corrupting adjacent fields on non-coherent architectures.
	 */
	u8 tmp_buffer[128] ____cacheline_aligned;

	/* save keylen from setkey */
	unsigned int keylen;
	struct scatterlist *tmp_sgl;
};

struct spacc_crypto_reqctx {
	struct pdu_ddt src, dst;
	void *digest_buf;
	dma_addr_t digest_dma;
	int src_nents, total_nents;
	int single_shot;
	u8 state_buffer[HASH_MAX_STATESIZE + 16] __aligned(8);

	struct ahash_cb_data {
		int new_handle;
		struct spacc_crypto_ctx    *tctx;
		struct spacc_crypto_reqctx *ctx;
		struct ahash_request       *req;
		struct spacc_device        *spacc;
	} acb;
};

struct mode_tab {
	char name[128];
	int valid;

	/* mode ID used in hash/cipher mode but not aead */
	int id;

	/* ciph/hash mode used in aead */
	struct {
		int ciph, hash;
	} aead;

	unsigned int hashlen, ivlen, blocklen, keylen[3];
	unsigned int keylen_mask, testlen;
	unsigned int chunksize, walksize, min_keysize, max_keysize;

	union {
		unsigned char hash_test[SPACC_MAX_DIGEST_SIZE];
		unsigned char ciph_test[3][2 * SPACC_MAX_IV_SIZE];
	};
};

struct spacc_alg {
	struct mode_tab *mode;
	unsigned int keylen_mask;

	struct device *dev;
	struct spacc_priv *priv;
	bool registered;

	struct list_head list;
	struct crypto_alg *calg;
	struct crypto_tfm *tfm;

	/*
	 * Kept as a union so salg->alg.hash resolves unchanged; the aead and
	 * skcipher arms belong to the later cipher/AEAD series and are not
	 * part of this hash-only driver.
	 */
	union {
		struct ahash_engine_alg hash;
	} alg;
};

struct spacc_completion {
	unsigned int wait_done;
	struct completion spacc_wait_complete;
	struct list_head list;
};

static inline const struct spacc_alg *spacc_tfm_ahash(struct crypto_tfm *tfm)
{
	const struct crypto_alg *calg = tfm->__crt_alg;

	if ((calg->cra_flags & CRYPTO_ALG_TYPE_MASK) == CRYPTO_ALG_TYPE_AHASH) {
		return container_of(calg, struct spacc_alg,
				    alg.hash.base.halg.base);
	}

	return NULL;
}

int spacc_probe_hashes(struct platform_device *spacc_pdev);
void spacc_priv_release(struct kref *ref);
int spacc_unregister_hash_algs(struct spacc_priv *priv);

irqreturn_t spacc_irq_handler(int irq, void *dev);
#endif
