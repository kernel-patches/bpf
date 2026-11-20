// SPDX-License-Identifier: GPL-2.0

#include <linux/minmax.h>
#include <crypto/skcipher.h>
#include <linux/vmalloc.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include "spacc_core.h"

/* Prevent reading past the end of the buffer */
static void spacc_read_from_buf(unsigned char *dst, unsigned char *src,
				int off, int n, int buflen)
{
	if (!dst)
		return;

	while (n > 0 && (off < buflen)) {
		*dst++ = src[off++];
		--n;
	}
}

static void spacc_write_to_buf(unsigned char *dst, const unsigned char *src,
			       int off, int n, int buflen)
{
	if (!src)
		return;

	while (n > 0 && (off < buflen)) {
		dst[off++] = *src++;
		--n;
	}
}

/* Must be called from Jon manager only */
static int spacc_ctx_request(struct spacc_device *spacc,
			     int ctx_id, int ncontig)
{
	int ret = 0;
	int x, y, count;

	if (!spacc)
		return -EINVAL;

	if (ctx_id < -1 || ctx_id >= spacc->config.num_ctx)
		return -EINVAL;

	if (ncontig < 1 || ncontig > spacc->config.num_ctx)
		return -EINVAL;

	/*
	 * Look for contiguous contexts. Free contexts have a ref_cnt of 0.
	 * If specific ctx_id is requested, test the ncontig
	 * and then bump the ref_cnt
	 */
	if (ctx_id != -1) {
		if ((&spacc->ctx[ctx_id])->ncontig != ncontig - 1)
			ret = -1;
		goto NO_FREE_CTX;
	}

	/*
	 * Check to see if ncontig are free loop over all available contexts
	 * to find the first ncontig empty ones
	 */
	for (x = 0; x <= (spacc->config.num_ctx - ncontig); ) {
		count = ncontig;
		while (count) {
			if ((&spacc->ctx[x + count - 1])->ref_cnt != 0) {
				/*
				 * Increment x to past failed count
				 * location
				 */
				x += count;
				break;
			}
			count--;
		}

		if (count != 0)
			ret = -1;
		else {
			ctx_id = x;
			ret = 0;
			break;
		}
	}

NO_FREE_CTX:
	if (ret == 0) {
		/* ctx_id is good so mark used */
		for (y = 0; y < ncontig; y++)
			(&spacc->ctx[ctx_id + y])->ref_cnt++;
		(&spacc->ctx[ctx_id])->ncontig = ncontig - 1;
	} else
		ctx_id = ret;

	return ctx_id;
}

static int spacc_ctx_release(struct spacc_device *spacc, int ctx_id)
{
	int y;
	int ncontig;

	if (ctx_id < 0 || ctx_id >= spacc->config.num_ctx)
		return -EINVAL;

	/* release the base context and contiguous block */
	ncontig = (&spacc->ctx[ctx_id])->ncontig;

	for (y = 0; y <= ncontig; y++) {
		if ((&spacc->ctx[ctx_id + y])->ref_cnt > 0)
			(&spacc->ctx[ctx_id + y])->ref_cnt--;
	}

	if ((&spacc->ctx[ctx_id])->ref_cnt == 0) {
		(&spacc->ctx[ctx_id])->ncontig = 0;

#ifdef CONFIG_CRYPTO_DEV_SPACC_SECURE_MODE
		writel(ctx_id, spacc->regmap + SPACC_REG_SECURE_RELEASE);
#endif

		/* This will wake up a sleeping task, if any */
		up(&spacc->ctx_sem);
	}

	return 0;
}

void spacc_job_init_all(struct spacc_device *spacc)
{
	int x;
	struct spacc_job *job;

	for (x = 0; x < (SPACC_MAX_JOBS); x++) {
		job = &spacc->job[x];
		memset(job, 0, sizeof(struct spacc_job));

		job->job_swid	     = SPACC_JOB_IDX_UNUSED;
		job->job_used	     = SPACC_JOB_IDX_UNUSED;
		spacc->job_lookup[x] = SPACC_JOB_IDX_UNUSED;
		init_waitqueue_head(&job->waitq);
	}
}

/* Get a new job id and use a specific ctx_idx or -1 for a new one */
int spacc_job_request(struct spacc_device *spacc, int ctx_idx)
{
	int x, ret = 0;
	struct spacc_job *job;
	unsigned long lock_flag;

	if (!spacc)
		return -EINVAL;

	spin_lock_irqsave(&spacc->lock, lock_flag);

	/* find the first available job id */
	for (x = 0; x < SPACC_MAX_JOBS; x++) {
		job = &spacc->job[x];
		if (job->job_used == SPACC_JOB_IDX_UNUSED) {
			job->job_used = x;
			break;
		}
	}

	if (x == SPACC_MAX_JOBS)
		ret = -1;
	else {
		/* associate a single context to go with job */
		ret = spacc_ctx_request(spacc, ctx_idx, 1);
		if (ret >= 0) {
			job->ctx_idx = ret;
			ret = x;
		} else
			job->job_used = SPACC_JOB_IDX_UNUSED;
	}

	spin_unlock_irqrestore(&spacc->lock, lock_flag);

	return ret;
}

int spacc_job_release(struct spacc_device *spacc, int job_idx)
{
	int ret = 0;
	struct spacc_job *job;
	unsigned long lock_flag;

	if (!spacc)
		return -EINVAL;

	if (job_idx < 0 || job_idx >= SPACC_MAX_JOBS)
		return -EINVAL;

	spin_lock_irqsave(&spacc->lock, lock_flag);
	job	      = &spacc->job[job_idx];

	if (job->job_swid < SPACC_MAX_JOBS &&
	    spacc->job_lookup[job->job_swid] == job_idx)
		spacc->job_lookup[job->job_swid] = SPACC_JOB_IDX_UNUSED;

	/* release context that goes with job */
	ret		= spacc_ctx_release(spacc, job->ctx_idx);
	job->ctx_idx	= SPACC_CTX_IDX_UNUSED;
	job->job_used	= SPACC_JOB_IDX_UNUSED;

	/* disable any callback */
	job->cb		= NULL;
	spin_unlock_irqrestore(&spacc->lock, lock_flag);

	return ret;
}

/* Return a context structure for a job idx or null if invalid */
struct spacc_ctx *spacc_context_lookup_by_job(struct spacc_device *spacc,
					      int job_idx)
{
	unsigned int ctx_idx;

	if (job_idx < 0 || job_idx >= SPACC_MAX_JOBS)
		return NULL;

	ctx_idx = spacc->job[job_idx].ctx_idx;
	if (ctx_idx >= spacc->config.num_ctx)
		return NULL;

	return &spacc->ctx[ctx_idx];
}

int spacc_process_jb(struct spacc_device *spacc, unsigned long *lock_flag)
{
	int tail;
	int ret = 0;
	struct spacc_job *job;

	/* checks for jobs in the buffer */
	while (spacc->jb_head != spacc->jb_tail) {
		tail = spacc->jb_tail;

		if (spacc->job_buffer[tail].active) {
			ret = spacc_packet_enqueue_ddt_ex
			      (spacc, 0, spacc->job_buffer[tail].job_idx,
			       spacc->job_buffer[tail].src,
			       spacc->job_buffer[tail].dst,
			       spacc->job_buffer[tail].proc_sz,
			       spacc->job_buffer[tail].aad_offset,
			       spacc->job_buffer[tail].pre_aad_sz,
			       spacc->job_buffer[tail].post_aad_sz,
			       spacc->job_buffer[tail].iv_offset,
			       spacc->job_buffer[tail].prio,
			       spacc->job_buffer[tail].aad_copy, lock_flag);

			if (ret == -EBUSY)
				return -EBUSY;

			spacc->job_buffer[tail].active = 0;
			job = (ret != 0)
			      ? &spacc->job[spacc->job_buffer[tail].job_idx]
			      : NULL;

			/*
			 * Consume this slot and advance jb_tail before
			 * dropping the lock for the callback, so the ring is
			 * left consistent. A concurrent spacc_process_jb()
			 * entering during job->cb() then sees this slot
			 * already claimed and starts from the next one.
			 * Advancing after re-acquiring the lock would skip
			 * past whatever the other caller processed meanwhile,
			 * stranding a live job.
			 */
			tail++;
			if (tail == SPACC_MAX_JOB_BUFFERS)
				tail = 0;
			spacc->jb_tail = tail;

			if (job) {
				job->job_err = ret;

				if (spacc->autodetect) {
					/*
					 * pairs with smp_load_acquire() in
					 * spacc_check_modes().
					 */
					smp_store_release(&job->job_done, 1);
					wake_up(&job->waitq);
				} else if (job->cb) {
					spacc_callback cb = job->cb;
					void *cbdata = job->cbdata;

					/*
					 * jb_tail was advanced above and the
					 * lock is about to be dropped, so this
					 * job slot may be recycled while the
					 * callback runs.
					 */
					spin_unlock_irqrestore(&spacc->lock,
							       *lock_flag);
					cb(spacc, cbdata);
					spin_lock_irqsave(&spacc->lock,
							  *lock_flag);
				} else {
					/*
					 * pairs with smp_load_acquire() in
					 * the waiters that open
					 * a job without a callback.
					 */
					smp_store_release(&job->job_done, 1);
					wake_up(&job->waitq);
				}
			}
			continue;
		}

		/* inactive slot: just step over it */
		tail++;
		if (tail == SPACC_MAX_JOB_BUFFERS)
			tail = 0;

		spacc->jb_tail = tail;
	}

	return 0;
}

/* Write appropriate context data which depends on operation and mode */
int spacc_write_context(struct spacc_device *spacc, int job_idx, int op,
			const unsigned char *key, int ksz,
			const unsigned char *iv, int ivsz)
{
	int buflen;
	int ret = 0;
	unsigned char buf[300] __aligned(sizeof(u32));
	struct spacc_ctx *ctx = NULL;
	struct spacc_job *job = NULL;

	if (job_idx < 0 || job_idx >= SPACC_MAX_JOBS)
		return -EINVAL;

	job = &spacc->job[job_idx];
	ctx = spacc_context_lookup_by_job(spacc, job_idx);

	if (!ctx)
		return -EIO;

	switch (op) {
	case SPACC_CRYPTO_OPERATION:
		/*
		 * Get page size and then read so we can do a
		 * read-modify-write cycle
		 */
		buflen = min_t(size_t, sizeof(buf),
			       spacc->config.ciph_page_size);

		pdu_from_dev_s(buf, ctx->ciph_key, buflen >> 2);

		switch (job->enc_mode) {
		case CRYPTO_MODE_SM4_ECB:
		case CRYPTO_MODE_SM4_CBC:
		case CRYPTO_MODE_SM4_CFB:
		case CRYPTO_MODE_SM4_OFB:
		case CRYPTO_MODE_SM4_CTR:
		case CRYPTO_MODE_SM4_CCM:
		case CRYPTO_MODE_SM4_GCM:
		case CRYPTO_MODE_SM4_CS1:
		case CRYPTO_MODE_SM4_CS2:
		case CRYPTO_MODE_SM4_CS3:
		case CRYPTO_MODE_AES_ECB:
		case CRYPTO_MODE_AES_CBC:
		case CRYPTO_MODE_AES_CS1:
		case CRYPTO_MODE_AES_CS2:
		case CRYPTO_MODE_AES_CS3:
		case CRYPTO_MODE_AES_CFB:
		case CRYPTO_MODE_AES_OFB:
		case CRYPTO_MODE_AES_CTR:
		case CRYPTO_MODE_AES_CCM:
		case CRYPTO_MODE_AES_GCM:
			spacc_write_to_buf(buf, key, 0, ksz, buflen);
			if (iv) {
				unsigned char one[4] = { 0, 0, 0, 1 };
				unsigned long enc1, enc2;

				enc1 = CRYPTO_MODE_AES_GCM;
				enc2 = CRYPTO_MODE_SM4_GCM;

				spacc_write_to_buf(buf, iv, 32, ivsz, buflen);
				if (ivsz == 12 &&
				    (job->enc_mode ==  enc1 ||
				     job->enc_mode == enc2))
					spacc_write_to_buf(buf, one, 11 * 4, 4,
							   buflen);
			}
			break;
		case CRYPTO_MODE_SM4_F8:
		case CRYPTO_MODE_AES_F8:
			if (key) {
				spacc_write_to_buf(buf, key + ksz, 0, ksz,
						   buflen);
				spacc_write_to_buf(buf, key, 48, ksz, buflen);
			}
			spacc_write_to_buf(buf, iv, 32,  16, buflen);
			break;
		case CRYPTO_MODE_SM4_XTS:
		case CRYPTO_MODE_AES_XTS:
			if (key) {
				spacc_write_to_buf(buf, key, 0,
						   ksz >> 1, buflen);
				spacc_write_to_buf(buf, key + (ksz >> 1), 48,
						   ksz >> 1, buflen);
				ksz = ksz >> 1;
			}

			spacc_write_to_buf(buf, iv, 32, 16, buflen);
			break;
		case CRYPTO_MODE_MULTI2_ECB:
		case CRYPTO_MODE_MULTI2_CBC:
		case CRYPTO_MODE_MULTI2_OFB:
		case CRYPTO_MODE_MULTI2_CFB:
			spacc_write_to_buf(buf, key, 0, ksz, buflen);
			spacc_write_to_buf(buf, iv, 0x28, ivsz, buflen);
			if (ivsz <= 8) {
				/* default to 128 rounds */
				unsigned char rounds[4] = { 0, 0, 0, 128};

				spacc_write_to_buf(buf, rounds, 0x30, 4,
						   buflen);
			}
			break;
		case CRYPTO_MODE_3DES_CBC:
		case CRYPTO_MODE_3DES_ECB:
		case CRYPTO_MODE_DES_CBC:
		case CRYPTO_MODE_DES_ECB:
			spacc_write_to_buf(buf, iv, 0, 8, buflen);
			spacc_write_to_buf(buf, key, 8, ksz, buflen);
			break;
		case CRYPTO_MODE_KASUMI_ECB:
		case CRYPTO_MODE_KASUMI_F8:
			spacc_write_to_buf(buf, iv, 16, 8, buflen);
			spacc_write_to_buf(buf, key, 0, 16, buflen);
			break;
		case CRYPTO_MODE_SNOW3G_UEA2:
		case CRYPTO_MODE_ZUC_UEA3:
			spacc_write_to_buf(buf, key, 0, 32, buflen);
			break;
		case CRYPTO_MODE_CHACHA20_STREAM:
		case CRYPTO_MODE_CHACHA20_POLY1305:
			spacc_write_to_buf(buf, key, 0, ksz, buflen);
			spacc_write_to_buf(buf, iv, 32, ivsz, buflen);
			break;
		case CRYPTO_MODE_NULL:
			break;
		}

		if (key) {
			job->ckey_sz = SPACC_SET_CIPHER_KEY_SZ(ksz);
			job->first_use = true;
		}

		pdu_to_dev_s(ctx->ciph_key, buf, buflen >> 2);
		break;

	case SPACC_HASH_OPERATION:
		/*
		 * Get page size and then read so we can do a
		 * read-modify-write cycle
		 */
		buflen = min_t(size_t, sizeof(buf),
			       spacc->config.hash_page_size);
		pdu_from_dev_s(buf, ctx->hash_key, buflen >> 2);

		switch (job->hash_mode) {
		case CRYPTO_MODE_MAC_XCBC:
		case CRYPTO_MODE_MAC_SM4_XCBC:
			if (key) {
				spacc_write_to_buf(buf, key + (ksz - 32),
						32, 32, buflen);
				spacc_write_to_buf(buf, key, 0, (ksz - 32),
						buflen);
				job->hkey_sz = SPACC_SET_HASH_KEY_SZ(ksz - 32);
			}
			break;
		case CRYPTO_MODE_HASH_CRC32:
		case CRYPTO_MODE_MAC_SNOW3G_UIA2:
		case CRYPTO_MODE_MAC_ZUC_UIA3:
			if (key) {
				spacc_write_to_buf(buf, key, 0, ksz, buflen);
				job->hkey_sz = SPACC_SET_HASH_KEY_SZ(ksz);
			}
			break;
		case CRYPTO_MODE_MAC_POLY1305:
			spacc_write_to_buf(buf, key, 0, ksz, buflen);
			spacc_write_to_buf(buf, iv, 32, ivsz, buflen);
			break;
		default:
			if (key) {
				job->hkey_sz = SPACC_SET_HASH_KEY_SZ(ksz);
				spacc_write_to_buf(buf, key, 0, ksz, buflen);
			}
		}
		pdu_to_dev_s(ctx->hash_key, buf, buflen >> 2);
		break;
	default:
		ret = -EINVAL;
	}

	memzero_explicit(buf, sizeof(buf));
	return ret;
}

int spacc_read_context(struct spacc_device *spacc, int job_idx,
		       int op, unsigned char *key, int ksz,
		       unsigned char *iv, int ivsz)
{
	int buflen;
	int ret = 0;
	unsigned char buf[300] __aligned(sizeof(u32));
	struct spacc_ctx *ctx = NULL;
	struct spacc_job *job = NULL;

	if (job_idx < 0 || job_idx >= SPACC_MAX_JOBS)
		return -EINVAL;

	job = &spacc->job[job_idx];
	ctx = spacc_context_lookup_by_job(spacc, job_idx);

	if (!ctx)
		return  -EIO;

	switch (op) {
	case SPACC_CRYPTO_OPERATION:
		buflen = min_t(size_t, sizeof(buf),
			       spacc->config.ciph_page_size);
		pdu_from_dev_s(buf, ctx->ciph_key, buflen >> 2);

		switch (job->enc_mode) {
		case CRYPTO_MODE_SM4_ECB:
		case CRYPTO_MODE_SM4_CBC:
		case CRYPTO_MODE_SM4_CFB:
		case CRYPTO_MODE_SM4_OFB:
		case CRYPTO_MODE_SM4_CTR:
		case CRYPTO_MODE_SM4_CCM:
		case CRYPTO_MODE_SM4_GCM:
		case CRYPTO_MODE_SM4_CS1:
		case CRYPTO_MODE_SM4_CS2:
		case CRYPTO_MODE_SM4_CS3:
		case CRYPTO_MODE_AES_ECB:
		case CRYPTO_MODE_AES_CBC:
		case CRYPTO_MODE_AES_CS1:
		case CRYPTO_MODE_AES_CS2:
		case CRYPTO_MODE_AES_CS3:
		case CRYPTO_MODE_AES_CFB:
		case CRYPTO_MODE_AES_OFB:
		case CRYPTO_MODE_AES_CTR:
		case CRYPTO_MODE_AES_CCM:
		case CRYPTO_MODE_AES_GCM:
			spacc_read_from_buf(key, buf, 0, ksz, buflen);
			spacc_read_from_buf(iv, buf,  32, 16, buflen);
			break;
		case CRYPTO_MODE_CHACHA20_STREAM:
			spacc_read_from_buf(key, buf, 0, ksz, buflen);
			spacc_read_from_buf(iv, buf, 32, 16, buflen);
			break;
		case CRYPTO_MODE_SM4_F8:
		case CRYPTO_MODE_AES_F8:
			if (key) {
				spacc_read_from_buf(key + ksz, buf, 0, ksz,
						    buflen);
				spacc_read_from_buf(key, buf, 48, ksz, buflen);
			}
			spacc_read_from_buf(iv, buf, 32, 16, buflen);
			break;
		case CRYPTO_MODE_SM4_XTS:
		case CRYPTO_MODE_AES_XTS:
			if (key) {
				spacc_read_from_buf(key, buf, 0, ksz >> 1,
						    buflen);
				spacc_read_from_buf(key + (ksz >> 1), buf,
						    48, ksz >> 1, buflen);
			}
			spacc_read_from_buf(iv, buf, 32, 16, buflen);
			break;
		case CRYPTO_MODE_MULTI2_ECB:
		case CRYPTO_MODE_MULTI2_CBC:
		case CRYPTO_MODE_MULTI2_OFB:
		case CRYPTO_MODE_MULTI2_CFB:
			spacc_read_from_buf(key, buf, 0, ksz, buflen);
			/* number of rounds at the end of the IV */
			spacc_read_from_buf(iv, buf, 0x28, ivsz, buflen);
			break;
		case CRYPTO_MODE_3DES_CBC:
		case CRYPTO_MODE_3DES_ECB:
			spacc_read_from_buf(iv,  buf, 0,  8, buflen);
			spacc_read_from_buf(key, buf, 8, 24, buflen);
			break;
		case CRYPTO_MODE_DES_CBC:
		case CRYPTO_MODE_DES_ECB:
			spacc_read_from_buf(iv,  buf, 0, 8, buflen);
			spacc_read_from_buf(key, buf, 8, 8, buflen);
			break;
		case CRYPTO_MODE_KASUMI_ECB:
		case CRYPTO_MODE_KASUMI_F8:
			spacc_read_from_buf(iv,  buf, 16,  8, buflen);
			spacc_read_from_buf(key, buf, 0,  16, buflen);
			break;
		case CRYPTO_MODE_SNOW3G_UEA2:
		case CRYPTO_MODE_ZUC_UEA3:
			spacc_read_from_buf(key, buf, 0, 32, buflen);
			break;
		case CRYPTO_MODE_NULL:
			break;
		}
		break;
	default:
		ret = -EINVAL;
	}

	memzero_explicit(buf, sizeof(buf));
	return ret;
}

/* Context manager: This will reset all reference counts, pointers, etc */
void spacc_ctx_init_all(struct spacc_device *spacc)
{
	int x;
	struct spacc_ctx *ctx;

	/* initialize contexts */
	for (x = 0; x < spacc->config.num_ctx; x++) {
		ctx = &spacc->ctx[x];

		/* sets everything including ref_cnt and ncontig to 0 */
		memset(ctx, 0, sizeof(*ctx));

		ctx->ciph_key = spacc->regmap + SPACC_CTX_CIPH_KEY +
				(x * spacc->config.ciph_page_size);
		ctx->hash_key = spacc->regmap + SPACC_CTX_HASH_KEY +
				(x * spacc->config.hash_page_size);
	}
}
