// SPDX-License-Identifier: GPL-2.0

#include <crypto/skcipher.h>
#include <linux/of.h>
#include <linux/vmalloc.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/minmax.h>

#include "spacc_core.h"
#include "spacc_device.h"

static const u8 spacc_ctrl_map[SPACC_CTRL_VER_SIZE][SPACC_CTRL_MAPSIZE] = {
	{ 0, 8, 4, 12, 24, 16, 31, 25, 26, 27, 28, 29, 14, 15 },
	{ 0, 8, 3, 12, 24, 16, 31, 25, 26, 27, 28, 29, 14, 15 },
	{ 0, 4, 8, 13, 15, 16, 24, 25, 26, 27, 28, 29, 30, 31 }
};

static const int keysizes[2][7] = {
	/* 1  2   4   8  16  32   64 */
	{ 5,  8, 16, 24, 32,  0,   0 },  /* cipher key sizes */
	{ 8, 16, 20, 24, 32, 64, 128 },  /* hash key sizes */
};

static const struct enc_config enc_table[] = {
	/* mode			    cipher_alg	 cipher_mode  auxinfo_cs_mode */
	{CRYPTO_MODE_NULL,		 0,		 0,		   0},
	{CRYPTO_MODE_AES_ECB,		 C_AES,		 CM_ECB,	   0},
	{CRYPTO_MODE_AES_CBC,		 C_AES,		 CM_CBC,	   0},
	{CRYPTO_MODE_AES_CS1,		 C_AES,		 CM_CBC,	   1},
	{CRYPTO_MODE_AES_CS2,		 C_AES,		 CM_CBC,	   2},
	{CRYPTO_MODE_AES_CS3,		 C_AES,		 CM_CBC,	   3},
	{CRYPTO_MODE_AES_CFB,		 C_AES,		 CM_CFB,	   0},
	{CRYPTO_MODE_AES_OFB,		 C_AES,		 CM_OFB,	   0},
	{CRYPTO_MODE_AES_CTR,		 C_AES,		 CM_CTR,	   0},
	{CRYPTO_MODE_AES_CCM,		 C_AES,		 CM_CCM,	   0},
	{CRYPTO_MODE_AES_GCM,		 C_AES,		 CM_GCM,	   0},
	{CRYPTO_MODE_AES_F8,		 C_AES,		 CM_F8,		   0},
	{CRYPTO_MODE_AES_XTS,		 C_AES,		 CM_XTS,	   0},
	{CRYPTO_MODE_MULTI2_ECB,	 C_MULTI2,	 CM_ECB,	   0},
	{CRYPTO_MODE_MULTI2_CBC,	 C_MULTI2,	 CM_CBC,	   0},
	{CRYPTO_MODE_MULTI2_OFB,	 C_MULTI2,	 CM_OFB,	   0},
	{CRYPTO_MODE_MULTI2_CFB,	 C_MULTI2,	 CM_CFB,	   0},
	{CRYPTO_MODE_3DES_CBC,		 C_DES,		 CM_CBC,	   0},
	{CRYPTO_MODE_DES_CBC,		 C_DES,		 CM_CBC,	   0},
	{CRYPTO_MODE_3DES_ECB,		 C_DES,		 CM_ECB,	   0},
	{CRYPTO_MODE_DES_ECB,		 C_DES,		 CM_ECB,	   0},
	{CRYPTO_MODE_KASUMI_ECB,	 C_KASUMI,	 CM_ECB,	   0},
	{CRYPTO_MODE_KASUMI_F8,		 C_KASUMI,	 CM_F8,		   0},
	{CRYPTO_MODE_SNOW3G_UEA2,	 C_SNOW3G_UEA2,	 CM_ECB,	   0},
	{CRYPTO_MODE_ZUC_UEA3,		 C_ZUC_UEA3,	 CM_ECB,	   0},
	{CRYPTO_MODE_CHACHA20_STREAM,	 C_CHACHA20,	 CM_CHACHA_STREAM, 0},
	{CRYPTO_MODE_CHACHA20_POLY1305,	 C_CHACHA20,	 CM_CHACHA_AEAD,   0},
	{CRYPTO_MODE_SM4_ECB,		 C_SM4,		 CM_ECB,	   0},
	{CRYPTO_MODE_SM4_CBC,		 C_SM4,		 CM_CBC,	   0},
	{CRYPTO_MODE_SM4_CS1,		 C_SM4,		 CM_CBC,	   1},
	{CRYPTO_MODE_SM4_CS2,		 C_SM4,		 CM_CBC,	   2},
	{CRYPTO_MODE_SM4_CS3,		 C_SM4,		 CM_CBC,	   3},
	{CRYPTO_MODE_SM4_CFB,		 C_SM4,		 CM_CFB,	   0},
	{CRYPTO_MODE_SM4_OFB,		 C_SM4,		 CM_OFB,	   0},
	{CRYPTO_MODE_SM4_CTR,		 C_SM4,		 CM_CTR,	   0},
	{CRYPTO_MODE_SM4_CCM,		 C_SM4,		 CM_CCM,	   0},
	{CRYPTO_MODE_SM4_GCM,		 C_SM4,		 CM_GCM,	   0},
	{CRYPTO_MODE_SM4_F8,		 C_SM4,		 CM_F8,		   0},
	{CRYPTO_MODE_SM4_XTS,		 C_SM4,		 CM_XTS,	   0},
};

static const struct hash_config hash_table[] = {
	/* mode			      hash_alg	   hash_mode     auxinfo_dir */
	{CRYPTO_MODE_NULL,               H_NULL,         0,                0},
	{CRYPTO_MODE_HMAC_SHA1,          H_SHA1,         HM_HMAC,          0},
	{CRYPTO_MODE_HMAC_MD5,           H_MD5,          HM_HMAC,          0},
	{CRYPTO_MODE_HMAC_SHA224,        H_SHA224,       HM_HMAC,          0},
	{CRYPTO_MODE_HMAC_SHA256,        H_SHA256,       HM_HMAC,          0},
	{CRYPTO_MODE_HMAC_SHA384,        H_SHA384,       HM_HMAC,          0},
	{CRYPTO_MODE_HMAC_SHA512,        H_SHA512,       HM_HMAC,          0},
	{CRYPTO_MODE_HMAC_SHA512_224,    H_SHA512_224,   HM_HMAC,          0},
	{CRYPTO_MODE_HMAC_SHA512_256,    H_SHA512_256,   HM_HMAC,          0},
	{CRYPTO_MODE_SSLMAC_MD5,         H_MD5,          HM_SSLMAC,        0},
	{CRYPTO_MODE_SSLMAC_SHA1,        H_SHA1,         HM_SSLMAC,        0},
	{CRYPTO_MODE_HASH_SHA1,          H_SHA1,         HM_RAW,           0},
	{CRYPTO_MODE_HASH_MD5,           H_MD5,          HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA224,        H_SHA224,       HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA256,        H_SHA256,       HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA384,        H_SHA384,       HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA512,        H_SHA512,       HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA512_224,    H_SHA512_224,   HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA512_256,    H_SHA512_256,   HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA3_224,      H_SHA3_224,     HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA3_256,      H_SHA3_256,     HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA3_384,      H_SHA3_384,     HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHA3_512,      H_SHA3_512,     HM_RAW,           0},
	{CRYPTO_MODE_HASH_SHAKE128,      H_SHAKE128,     HM_SHAKE_SHAKE,   0},
	{CRYPTO_MODE_HASH_SHAKE256,      H_SHAKE256,     HM_SHAKE_SHAKE,   0},
	{CRYPTO_MODE_HASH_CSHAKE128,     H_SHAKE128,     HM_SHAKE_CSHAKE,  0},
	{CRYPTO_MODE_HASH_CSHAKE256,     H_SHAKE256,     HM_SHAKE_CSHAKE,  0},
	{CRYPTO_MODE_MAC_KMAC128,        H_SHAKE128,     HM_SHAKE_KMAC,    0},
	{CRYPTO_MODE_MAC_KMAC256,        H_SHAKE256,     HM_SHAKE_KMAC,    0},
	{CRYPTO_MODE_MAC_KMACXOF128,     H_SHAKE128,     HM_SHAKE_KMAC,    1},
	{CRYPTO_MODE_MAC_KMACXOF256,     H_SHAKE256,     HM_SHAKE_KMAC,    1},
	{CRYPTO_MODE_MAC_XCBC,           H_XCBC,         HM_RAW,           0},
	{CRYPTO_MODE_MAC_CMAC,           H_CMAC,         HM_RAW,           0},
	{CRYPTO_MODE_MAC_KASUMI_F9,      H_KF9,          HM_RAW,           0},
	{CRYPTO_MODE_MAC_SNOW3G_UIA2,    H_SNOW3G_UIA2,  HM_RAW,           0},
	{CRYPTO_MODE_MAC_ZUC_UIA3,       H_ZUC_UIA3,     HM_RAW,           0},
	{CRYPTO_MODE_MAC_POLY1305,       H_POLY1305,     HM_RAW,           0},
	{CRYPTO_MODE_HASH_CRC32,         H_CRC32_I3E802_3, HM_RAW,         0},
	{CRYPTO_MODE_MAC_MICHAEL,        H_MICHAEL,      HM_RAW,           0},
	{CRYPTO_MODE_HASH_SM3,           H_SM3,          HM_RAW,           0},
	{CRYPTO_MODE_HMAC_SM3,           H_SM3,          HM_HMAC,          0},
	{CRYPTO_MODE_MAC_SM4_XCBC,       H_SM4_XCBC_MAC, HM_RAW,           0},
	{CRYPTO_MODE_MAC_SM4_CMAC,       H_SM4_CMAC,     HM_RAW,           0},
};

/* bits are 40, 64, 128, 192, 256, and top bit for hash */
static const unsigned char template[] = {
	[CRYPTO_MODE_NULL]              = 0,
	[CRYPTO_MODE_AES_ECB]           = 28,	/* AESECB 128/224/256 */
	[CRYPTO_MODE_AES_CBC]           = 28,	/* AESCBC 128/224/256 */
	[CRYPTO_MODE_AES_CTR]           = 28,	/* AESCTR 128/224/256 */
	[CRYPTO_MODE_AES_CCM]           = 28,	/* AESCCM 128/224/256 */
	[CRYPTO_MODE_AES_GCM]           = 28,	/* AESGCM 128/224/256 */
	[CRYPTO_MODE_AES_F8]            = 28,	/* AESF8  128/224/256 */
	[CRYPTO_MODE_AES_XTS]           = 20,	/* AESXTS 128/256 */
	[CRYPTO_MODE_AES_CFB]           = 28,	/* AESCFB 128/224/256 */
	[CRYPTO_MODE_AES_OFB]           = 28,	/* AESOFB 128/224/256 */
	[CRYPTO_MODE_AES_CS1]           = 28,	/* AESCS1 128/224/256 */
	[CRYPTO_MODE_AES_CS2]           = 28,	/* AESCS2 128/224/256 */
	[CRYPTO_MODE_AES_CS3]           = 28,	/* AESCS3 128/224/256 */
	[CRYPTO_MODE_MULTI2_ECB]        = 0,	/* MULTI2 */
	[CRYPTO_MODE_MULTI2_CBC]        = 0,	/* MULTI2 */
	[CRYPTO_MODE_MULTI2_OFB]        = 0,	/* MULTI2 */
	[CRYPTO_MODE_MULTI2_CFB]        = 0,	/* MULTI2 */
	[CRYPTO_MODE_3DES_CBC]          = 8,	/* 3DES CBC */
	[CRYPTO_MODE_3DES_ECB]          = 8,	/* 3DES ECB */
	[CRYPTO_MODE_DES_CBC]           = 2,	/* DES CBC */
	[CRYPTO_MODE_DES_ECB]           = 2,	/* DES ECB */
	[CRYPTO_MODE_KASUMI_ECB]        = 4,	/* KASUMI ECB */
	[CRYPTO_MODE_KASUMI_F8]         = 4,	/* KASUMI F8 */
	[CRYPTO_MODE_SNOW3G_UEA2]       = 4,	/* SNOW3G */
	[CRYPTO_MODE_ZUC_UEA3]          = 4,	/* ZUC */
	[CRYPTO_MODE_CHACHA20_STREAM]   = 16,	/* CHACHA20 */
	[CRYPTO_MODE_CHACHA20_POLY1305] = 16,	/* CHACHA20 */
	[CRYPTO_MODE_SM4_ECB]           = 4,	/* SM4ECB 128 */
	[CRYPTO_MODE_SM4_CBC]           = 4,	/* SM4CBC 128 */
	[CRYPTO_MODE_SM4_CFB]           = 4,	/* SM4CFB 128 */
	[CRYPTO_MODE_SM4_OFB]           = 4,	/* SM4OFB 128 */
	[CRYPTO_MODE_SM4_CTR]           = 4,	/* SM4CTR 128 */
	[CRYPTO_MODE_SM4_CCM]           = 4,	/* SM4CCM 128 */
	[CRYPTO_MODE_SM4_GCM]           = 4,	/* SM4GCM 128 */
	[CRYPTO_MODE_SM4_F8]            = 4,	/* SM4F8  128 */
	[CRYPTO_MODE_SM4_XTS]           = 4,	/* SM4XTS 128 */
	[CRYPTO_MODE_SM4_CS1]           = 4,	/* SM4CS1 128 */
	[CRYPTO_MODE_SM4_CS2]           = 4,	/* SM4CS2 128 */
	[CRYPTO_MODE_SM4_CS3]           = 4,	/* SM4CS3 128 */

	[CRYPTO_MODE_HASH_MD5]          = 242,
	[CRYPTO_MODE_HMAC_MD5]          = 242,
	[CRYPTO_MODE_HASH_SHA1]         = 242,
	[CRYPTO_MODE_HMAC_SHA1]         = 242,
	[CRYPTO_MODE_HASH_SHA224]       = 242,
	[CRYPTO_MODE_HMAC_SHA224]       = 242,
	[CRYPTO_MODE_HASH_SHA256]       = 242,
	[CRYPTO_MODE_HMAC_SHA256]       = 242,
	[CRYPTO_MODE_HASH_SHA384]       = 242,
	[CRYPTO_MODE_HMAC_SHA384]       = 242,
	[CRYPTO_MODE_HASH_SHA512]       = 242,
	[CRYPTO_MODE_HMAC_SHA512]       = 242,
	[CRYPTO_MODE_HASH_SHA512_224]   = 242,
	[CRYPTO_MODE_HMAC_SHA512_224]   = 242,
	[CRYPTO_MODE_HASH_SHA512_256]   = 242,
	[CRYPTO_MODE_HMAC_SHA512_256]   = 242,
	[CRYPTO_MODE_MAC_XCBC]          = 130,	/* XCBC */
	[CRYPTO_MODE_MAC_CMAC]          = 154,	/* CMAC */
	[CRYPTO_MODE_MAC_KASUMI_F9]     = 130,	/* KASUMI */
	[CRYPTO_MODE_MAC_SNOW3G_UIA2]   = 130,	/* SNOW */
	[CRYPTO_MODE_MAC_ZUC_UIA3]      = 130,	/* ZUC */
	[CRYPTO_MODE_MAC_POLY1305]      = 144,
	[CRYPTO_MODE_SSLMAC_MD5]        = 130,
	[CRYPTO_MODE_SSLMAC_SHA1]       = 132,
	[CRYPTO_MODE_HASH_CRC32]        = 0,
	[CRYPTO_MODE_MAC_MICHAEL]       = 129,

	[CRYPTO_MODE_HASH_SHA3_224]     = 242,
	[CRYPTO_MODE_HASH_SHA3_256]     = 242,
	[CRYPTO_MODE_HASH_SHA3_384]     = 242,
	[CRYPTO_MODE_HASH_SHA3_512]     = 242,
	[CRYPTO_MODE_HASH_SHAKE128]     = 242,
	[CRYPTO_MODE_HASH_SHAKE256]     = 242,
	[CRYPTO_MODE_HASH_CSHAKE128]    = 130,
	[CRYPTO_MODE_HASH_CSHAKE256]    = 130,
	[CRYPTO_MODE_MAC_KMAC128]       = 242,
	[CRYPTO_MODE_MAC_KMAC256]       = 242,
	[CRYPTO_MODE_MAC_KMACXOF128]    = 242,
	[CRYPTO_MODE_MAC_KMACXOF256]    = 242,
	[CRYPTO_MODE_HASH_SM3]          = 242,
	[CRYPTO_MODE_HMAC_SM3]          = 242,
	[CRYPTO_MODE_MAC_SM4_XCBC]      = 130,
	[CRYPTO_MODE_MAC_SM4_CMAC]      = 130,
};

int spacc_sg_to_ddt(struct device *dev, struct scatterlist *sg,
		    int nbytes, struct pdu_ddt *ddt, int dma_direction)
{
	int i;
	int nents;
	int rc = 0;
	int frags = 0;
	int orig_nents;
	struct scatterlist *sg_entry;

	/* Count the SG entries needed to cover the requested length. */
	orig_nents = sg_nents_for_len(sg, nbytes);
	if (orig_nents <= 0)
		return orig_nents;

	nents = dma_map_sg(dev, sg, orig_nents, dma_direction);
	if (nents <= 0)
		return -ENOMEM;

	/*
	 * Each DDT entry must be <= 64KB (SPACC_DMA_BOUNDARY, the HW per-entry
	 * maximum) and must not straddle a 64KB boundary. A single mapped
	 * segment can violate either, so it is split across multiple entries.
	 * Count the post-split fragments first to size the DDT exactly (and
	 * to reject a request that would exceed PDU_MAX_DDT), then fill it.
	 */
	for_each_sg(sg, sg_entry, nents, i) {
		dma_addr_t addr = sg_dma_address(sg_entry);
		u32 len = sg_dma_len(sg_entry);

		while (len) {
			u32 to_bndry = SPACC_DMA_BOUNDARY -
				       (addr & (SPACC_DMA_BOUNDARY - 1));
			u32 chunk = min3(len, (u32)SPACC_DMA_BOUNDARY, to_bndry);

			frags++;
			addr += chunk;
			len  -= chunk;
		}
	}

	if (frags > PDU_MAX_DDT) {
		dma_unmap_sg(dev, sg, orig_nents, dma_direction);
		return -EMSGSIZE;
	}

	rc = pdu_ddt_init(dev, ddt, frags | 0x80000000);
	if (rc < 0) {
		dma_unmap_sg(dev, sg, orig_nents, dma_direction);
		return -EIO;
	}

	for_each_sg(sg, sg_entry, nents, i) {
		dma_addr_t addr = sg_dma_address(sg_entry);
		u32 len = sg_dma_len(sg_entry);

		while (len) {
			u32 to_bndry = SPACC_DMA_BOUNDARY -
				       (addr & (SPACC_DMA_BOUNDARY - 1));
			u32 chunk = min3(len, (u32)SPACC_DMA_BOUNDARY, to_bndry);

			pdu_ddt_add(dev, ddt, addr, chunk);
			addr += chunk;
			len  -= chunk;
		}
	}

	return orig_nents;
}

int spacc_set_operation(struct spacc_device *spacc, int handle, int op,
			u32 prot, u32 icvcmd, u32 icvoff,
			u32 icvsz, u32 sec_key)
{
	int ret = 0;
	struct spacc_job *job = NULL;

	if (handle < 0 || handle >= SPACC_MAX_JOBS)
		return -EINVAL;

	job = &spacc->job[handle];

	job->op = op;
	if (op == OP_ENCRYPT)
		job->ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_ENCRYPT);
	else
		job->ctrl &= ~SPACC_CTRL_MASK(SPACC_CTRL_ENCRYPT);

	switch (prot) {
	case ICV_HASH:
		/* HASH of plaintext */
		job->ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_ICV_PT);
		break;
	case ICV_HASH_ENCRYPT:
		/*
		 * HASH the plaintext and encrypt the lot
		 * ICV_PT and ICV_APPEND must be set too
		 */
		job->ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_ICV_ENC);
		job->ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_ICV_PT);
		 /* this mode is not valid when BIT_ALIGN != 0 */
		job->ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_ICV_APPEND);
		break;
	case ICV_ENCRYPT_HASH:
		/* HASH the ciphertext */
		job->ctrl &= ~SPACC_CTRL_MASK(SPACC_CTRL_ICV_PT);
		job->ctrl &= ~SPACC_CTRL_MASK(SPACC_CTRL_ICV_ENC);
		break;
	case ICV_IGNORE:
		break;
	default:
		ret = -EINVAL;
	}

	job->icv_len = icvsz;

	switch (icvcmd) {
	case IP_ICV_OFFSET:
		job->icv_offset = icvoff;
		job->ctrl &= ~SPACC_CTRL_MASK(SPACC_CTRL_ICV_APPEND);
		break;
	case IP_ICV_APPEND:
		job->ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_ICV_APPEND);
		break;
	case IP_ICV_IGNORE:
		break;
	default:
		ret = -EINVAL;
	}

	if (sec_key)
		job->ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_SEC_KEY);

	return ret;
}

static int _spacc_fifo_full(struct spacc_device *spacc, u32 prio)
{
	if (spacc->config.is_qos)
		return readl(spacc->regmap + SPACC_REG_FIFO_STAT) &
		       SPACC_FIFO_STAT_CMDX_FULL(prio);
	else
		return readl(spacc->regmap + SPACC_REG_FIFO_STAT) &
		       SPACC_FIFO_STAT_CMD0_FULL;
}

int spacc_packet_enqueue_ddt_ex(struct spacc_device *spacc, int use_jb,
				int job_idx, struct pdu_ddt *src_ddt,
				struct pdu_ddt *dst_ddt, u32 proc_sz,
				u32 aad_offset, u32 pre_aad_sz, u32 post_aad_sz,
				u32 iv_offset, u32 prio, bool aad_copy,
				unsigned long *lock_flag)
{
	int job_index;
	int proc_len;
	struct spacc_job *job;

	if (job_idx < 0 || job_idx >= SPACC_MAX_JOBS)
		return -EINVAL;

	/*
	 * Handle priority jobs using cmd fifos, high priority
	 * defaults to cmd0 fifo, medium to cmd1 fifo and low
	 * to cmd2 fifo
	 */
	switch (prio)  {
	case SPACC_SW_CTRL_PRIO_MED:
		if (spacc->config.cmd1_fifo_depth == 0)
			return -EINVAL;
		break;
	case SPACC_SW_CTRL_PRIO_LOW:
		if (spacc->config.cmd2_fifo_depth == 0)
			return -EINVAL;
		break;
	}

	job = &spacc->job[job_idx];

	if (use_jb && spacc_process_jb(spacc, lock_flag) != 0)
		goto fifo_full;

	if (_spacc_fifo_full(spacc, prio)) {
		if (use_jb)
			goto fifo_full;
		else
			return -EBUSY;
	}

	/*
	 * Compute the length we must process, in decrypt mode
	 * with an ICV (hash, hmac or CCM modes)
	 * we must subtract the icv length from the buffer size
	 */
	if (proc_sz == SPACC_AUTO_SIZE) {
		proc_len = src_ddt->len;

		if (job->op == OP_DECRYPT &&
		    (job->hash_mode > 0 ||
		     job->enc_mode == CRYPTO_MODE_AES_CCM ||
		     job->enc_mode == CRYPTO_MODE_AES_GCM)  &&
		    !(job->ctrl & SPACC_CTRL_MASK(SPACC_CTRL_ICV_ENC)))
			proc_len = src_ddt->len - job->icv_len;
	} else
		proc_len = proc_sz;

	if ((u32)(proc_len - post_aad_sz) > spacc->config.max_msg_size)
		return -EMSGSIZE;

	/*
	 * pre_aad_sz is a pure length here, bounded like proc_len by
	 * max_msg_size (read from PROC_LEN: 16KB/32KB/64KB/256KB/512KB).
	 * AAD copy is requested explicitly via aad_copy, not by any bit of
	 * the length.
	 */
	if (pre_aad_sz > spacc->config.max_msg_size)
		return -EMSGSIZE;

	if (aad_copy)
		job->ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_AAD_COPY);
	else
		job->ctrl &= ~SPACC_CTRL_MASK(SPACC_CTRL_AAD_COPY);

	job->pre_aad_sz  = pre_aad_sz;
	job->post_aad_sz = post_aad_sz;

	/* DDT DMA Support only, probe rejects non-DDT parts */
	pdu_io_cached_write(spacc->dptr, spacc->regmap +
			SPACC_REG_SRC_PTR, (u32)src_ddt->phys,
			&spacc->cache.src_ptr);
	pdu_io_cached_write(spacc->dptr, spacc->regmap +
			SPACC_REG_DST_PTR, (u32)dst_ddt->phys,
				&spacc->cache.dst_ptr);

	pdu_io_cached_write(spacc->dptr, spacc->regmap + SPACC_REG_PROC_LEN,
			    proc_len - job->post_aad_sz,
			    &spacc->cache.proc_len);
	pdu_io_cached_write(spacc->dptr, spacc->regmap + SPACC_REG_ICV_LEN,
			    job->icv_len, &spacc->cache.icv_len);
	pdu_io_cached_write(spacc->dptr, spacc->regmap + SPACC_REG_ICV_OFFSET,
			    job->icv_offset, &spacc->cache.icv_offset);
	pdu_io_cached_write(spacc->dptr, spacc->regmap + SPACC_REG_PRE_AAD_LEN,
			    job->pre_aad_sz, &spacc->cache.pre_aad);
	pdu_io_cached_write(spacc->dptr, spacc->regmap + SPACC_REG_POST_AAD_LEN,
			    job->post_aad_sz, &spacc->cache.post_aad);
	pdu_io_cached_write(spacc->dptr, spacc->regmap + SPACC_REG_IV_OFFSET,
			    iv_offset, &spacc->cache.iv_offset);
	pdu_io_cached_write(spacc->dptr, spacc->regmap + SPACC_REG_OFFSET,
			    aad_offset, &spacc->cache.offset);
	pdu_io_cached_write(spacc->dptr, spacc->regmap + SPACC_REG_AUX_INFO,
			    AUX_DIR(job->auxinfo_dir) |
			    AUX_BIT_ALIGN(job->auxinfo_bit_align) |
			    AUX_CBC_CS(job->auxinfo_cs_mode),
			    &spacc->cache.aux);

	if (job->first_use) {
		writel(job->ckey_sz | SPACC_SET_KEY_CTX(job->ctx_idx),
		       spacc->regmap + SPACC_REG_KEY_SZ);
		writel(job->hkey_sz | SPACC_SET_KEY_CTX(job->ctx_idx),
		       spacc->regmap + SPACC_REG_KEY_SZ);
	}

	{
		unsigned int swid = spacc->job_next_swid;
		unsigned int tries;

		for (tries = 0; tries < SPACC_MAX_JOBS; tries++) {
			if (spacc->job_lookup[swid] == SPACC_JOB_IDX_UNUSED)
				break;
			swid = (swid + 1) % SPACC_MAX_JOBS;
		}

		if (tries == SPACC_MAX_JOBS) {
			/*
			 * fail loudly rather than silently corrupting
			 * tracking if it ever isn't.
			 */
			return -EBUSY;
		}

		job->job_swid = swid;
		spacc->job_lookup[swid] = job_idx;
		spacc->job_next_swid = (swid + 1) % SPACC_MAX_JOBS;
	}

	writel(SPACC_SW_CTRL_ID_SET(job->job_swid) |
	       SPACC_SW_CTRL_PRIO_SET(prio),
	       spacc->regmap + SPACC_REG_SW_CTRL);
	writel(job->ctrl, spacc->regmap + SPACC_REG_CTRL);

	/* clear an expansion key after the first call */
	if (job->first_use) {
		job->first_use = false;
		job->ctrl &= ~SPACC_CTRL_MASK(SPACC_CTRL_KEY_EXP);
	}

	return 0;

fifo_full:
	job_index = spacc->jb_head + 1;
	if (job_index == SPACC_MAX_JOB_BUFFERS)
		job_index = 0;

	if (job_index == spacc->jb_tail)
		return -EBUSY;

	spacc->job_buffer[spacc->jb_head] = (struct spacc_job_buffer) {
		.active		= 1,
		.job_idx	= job_idx,
		.src		= src_ddt,
		.dst		= dst_ddt,
		.proc_sz	= proc_sz,
		.aad_offset	= aad_offset,
		.pre_aad_sz	= pre_aad_sz,
		.post_aad_sz	= post_aad_sz,
		.iv_offset	= iv_offset,
		.prio		= prio,
		.aad_copy	= aad_copy
	};

	spacc->jb_head = job_index;

	return 0;
}

int spacc_packet_enqueue_ddt(struct spacc_device *spacc, int job_idx,
			     struct pdu_ddt *src_ddt, struct pdu_ddt *dst_ddt,
			     u32 proc_sz, u32 aad_offset, u32 pre_aad_sz,
			     u32 post_aad_sz, u32 iv_offset, u32 prio,
			     bool aad_copy)
{
	int ret = 0;
	unsigned long lock_flags;

	spin_lock_irqsave(&spacc->lock, lock_flags);
	ret = spacc_packet_enqueue_ddt_ex(spacc, 1, job_idx, src_ddt,
					  dst_ddt, proc_sz, aad_offset,
					  pre_aad_sz, post_aad_sz,
					  iv_offset, prio, aad_copy,
					  &lock_flags);
	spin_unlock_irqrestore(&spacc->lock, lock_flags);

	return ret;
}

/*
 * Plain hashes and HMAC accept arbitrary key lengths, so they keep the bit-7
 * "any size" fast path. The block-cipher MAC modes have a fixed key size that
 * must be validated against the (autodetected) capability bits. Add other
 * keyed cipher-MAC modes here once their valid key sizes are confirmed.
 */
static bool spacc_mode_has_fixed_keysize(int mode)
{
	switch (mode) {
	case CRYPTO_MODE_MAC_CMAC:
	case CRYPTO_MODE_MAC_XCBC:
	case CRYPTO_MODE_MAC_SM4_CMAC:
	case CRYPTO_MODE_MAC_SM4_XCBC:
		return true;
	default:
		return false;
	}
}

/* Check if the keysize is supported for the input mode */
int spacc_is_mode_keysize_supported(struct spacc_device *spacc, int mode,
				    int keysize, int keysz_index)
{
	int x;

	if (mode < 0 || mode >= CRYPTO_MODE_LAST)
		return SPACC_MODE_NOT_SUPPORTED;

	if (mode == CRYPTO_MODE_NULL ||
	    ((spacc->config.modes[mode] & 128) &&
	      !spacc_mode_has_fixed_keysize(mode)))
		return SPACC_MODE_SUPPORTED;

	/* check for valid keysizes */
	for (x = 0; x < ARRAY_SIZE(keysizes[0]); x++) {
		if (keysizes[keysz_index][x] == keysize) {
			if (spacc->config.modes[mode] & (1 << x))
				return SPACC_MODE_SUPPORTED;
			else
				return SPACC_MODE_NOT_SUPPORTED;
		}
	}

	return SPACC_MODE_NOT_SUPPORTED;
}

/* releases a crypto context back into appropriate module's pool */
int spacc_close(struct spacc_device *dev, int handle)
{
	return spacc_job_release(dev, handle);
}

static void spacc_static_modes(struct spacc_device *spacc, int x, int y)
{
	/* disable the algos that are not supported here */
	switch (x) {
	case CRYPTO_MODE_AES_F8:
	case CRYPTO_MODE_AES_CFB:
	case CRYPTO_MODE_AES_OFB:
	case CRYPTO_MODE_MULTI2_ECB:
	case CRYPTO_MODE_MULTI2_CBC:
	case CRYPTO_MODE_MULTI2_CFB:
	case CRYPTO_MODE_MULTI2_OFB:
	case CRYPTO_MODE_MAC_POLY1305:
	case CRYPTO_MODE_HASH_CRC32:
		/* disable the modes */
		spacc->config.modes[x] &= ~(1 << y);
		break;
	default:
		break; /* algos are enabled */
	}
}

int spacc_static_config(struct spacc_device *spacc)
{
	int x, y;

	for (x = 0; x < ARRAY_SIZE(template); x++) {
		spacc->config.modes[x] = template[x];

		for (y = 0; y < (ARRAY_SIZE(keysizes[0])); y++) {
			/* list static modes */
			spacc_static_modes(spacc, x, y);
		}
	}

	return 0;
}

/*
 * Allocate a job for spacc module context and initialize
 * it with an appropriate type.
 */
int spacc_open(struct spacc_device *spacc, int enc, int hash, int ctxid,
	       int secure_mode, spacc_callback cb, void *cbdata)
{
	size_t i;
	int ret = 0;
	u32 ctrl = 0;
	int job_idx = 0;
	struct spacc_job *job = NULL;
	const struct enc_config *enc_cfg = NULL;
	const struct hash_config *hash_cfg = NULL;
	unsigned long flags;

	if (ctxid == -1) {
		if (down_trylock(&spacc->ctx_sem)) {
			dev_dbg(spacc->dptr, "No free HW context, fallback\n");
			return -EBUSY;
		}
	}

	spin_lock_irqsave(&spacc->ctx_lock, flags);
	job_idx = spacc_job_request(spacc, ctxid);

	if (job_idx < 0) {
		spin_unlock_irqrestore(&spacc->ctx_lock, flags);
		dev_dbg(spacc->dptr, "Failed to acquire context\n");
		ret = -EIO;
		goto err_release_sem;
	}

	job = &spacc->job[job_idx];
	spin_unlock_irqrestore(&spacc->ctx_lock, flags);

	if (secure_mode && job->ctx_idx >= spacc->config.num_sec_ctx) {
		dev_dbg(spacc->dptr, "ERR: For secure contexts\n");
		dev_dbg(spacc->dptr,
			"ERR: Job ctx ID is outside allowed range\n");
		ret = -EIO;
		goto err_release_job;
	}

	job->auxinfo_cs_mode	= 0;
	job->auxinfo_bit_align	= 0;
	job->auxinfo_dir	= 0;
	job->icv_len		= 0;

	/* Process encryption mode using the lookup table */
	for (i = 0; i < ARRAY_SIZE(enc_table); ++i) {
		if (enc == enc_table[i].mode) {
			enc_cfg = &enc_table[i];
			ctrl |= SPACC_CTRL_SET(SPACC_CTRL_CIPH_ALG,
					       enc_cfg->cipher_alg);
			ctrl |= SPACC_CTRL_SET(SPACC_CTRL_CIPH_MODE,
					       enc_cfg->cipher_mode);
			job->auxinfo_cs_mode = enc_cfg->auxinfo_cs_mode;
			break;
		}
	}

	if (enc != CRYPTO_MODE_NULL && !enc_cfg) {
		ret = -EOPNOTSUPP;
		goto err_release_job;
	}

	/* Process hash mode using the lookup table */
	for (i = 0; i < ARRAY_SIZE(hash_table); ++i) {
		if (hash == hash_table[i].mode) {
			hash_cfg = &hash_table[i];
			ctrl |= SPACC_CTRL_SET(SPACC_CTRL_HASH_ALG,
					       hash_cfg->hash_alg);
			ctrl |= SPACC_CTRL_SET(SPACC_CTRL_HASH_MODE,
					       hash_cfg->hash_mode);
			job->auxinfo_dir = hash_cfg->auxinfo_dir;
			break;
		}
	}

	if (hash != CRYPTO_MODE_NULL && !hash_cfg) {
		ret = -EOPNOTSUPP;
		goto err_release_job;
	}

	ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_MSG_BEGIN) |
		SPACC_CTRL_MASK(SPACC_CTRL_MSG_END);

	/* Success path */
	job->first_use		= true;
	job->enc_mode		= enc;
	job->hash_mode		= hash;
	job->ckey_sz		= 0;
	job->hkey_sz		= 0;
	job->job_done		= 0;
	job->job_swid		= 0;
	job->job_secure		= !!secure_mode;
	job->auxinfo_bit_align	= 0;
	job->job_err		= -EINPROGRESS;
	job->ctrl		= ctrl | SPACC_CTRL_SET(SPACC_CTRL_CTX_IDX,
							job->ctx_idx);
	job->cb			= cb;
	job->cbdata		= cbdata;

	return job_idx;

err_release_job:
	spacc_job_release(spacc, job_idx);
	return ret;

err_release_sem:
	if (ctxid == -1)
		up(&spacc->ctx_sem);

	return ret;
}

void spacc_fini(struct spacc_device *spacc)
{
	kvfree(spacc->ctx);
	kvfree(spacc->job);
}

int spacc_init(void __iomem *baseaddr, struct spacc_device *spacc,
	       struct pdu_info *info, struct device *dev)
{
#ifdef CONFIG_CRYPTO_DEV_SPACC_CONFIG_DEBUG
	unsigned long id;
	char version_string[2][16]  = { "SPACC", "SPACC-PDU" };
	char idx_string[2][16]      = { "(Normal Port)", "(Secure Port)" };
	char dma_type_string[4][16] = { "Unknown", "Scattergather", "Linear",
					"Unknown" };
#endif

	memset(spacc, 0, sizeof(*spacc));

	spacc->dptr = dev;

	spin_lock_init(&spacc->lock);
	spin_lock_init(&spacc->ctx_lock);

	spacc->regmap = baseaddr;

	/* version info */
	spacc->config.version		= info->spacc_version.version;
	spacc->config.pdu_version	= (info->pdu_config.major << 4) |
					   info->pdu_config.minor;
	spacc->config.project		= info->spacc_version.project;
	spacc->config.is_pdu		= info->spacc_version.is_pdu;
	spacc->config.is_qos		= info->spacc_version.qos;

	spacc->config.is_partial	= info->spacc_version.partial;
	spacc->config.num_ctx		= info->spacc_config.num_ctx;

	/* The count is set to the number of hardware contexts available. */
	sema_init(&spacc->ctx_sem, spacc->config.num_ctx);

	spacc->config.ciph_page_size	= 1U <<
					  info->spacc_config.ciph_ctx_page_size;

	spacc->config.hash_page_size	= 1U <<
					  info->spacc_config.hash_ctx_page_size;

	spacc->config.dma_type		= info->spacc_config.dma_type;

	/* DDT (scatter-gather) DMA support only */
	if (spacc->config.dma_type != SPACC_DMA_DDT) {
		dev_err(spacc->dptr,
			"unsupported DMA type %u; driver supports DDT only\n",
			spacc->config.dma_type);
		return -ENODEV;
	}

	spacc->config.idx		= info->spacc_version.vspacc_id;
	spacc->config.cmd0_fifo_depth	= info->spacc_config.cmd0_fifo_depth;
	spacc->config.cmd1_fifo_depth	= info->spacc_config.cmd1_fifo_depth;
	spacc->config.cmd2_fifo_depth	= info->spacc_config.cmd2_fifo_depth;
	spacc->config.stat_fifo_depth	= info->spacc_config.stat_fifo_depth;
	spacc->config.fifo_cnt		= 1;
	spacc->config.is_ivimport	= info->spacc_version.ivimport;
	spacc->wd_cnt_limit		= false;

	/* ctrl register map */
	if (spacc->config.version <= 0x4E)
		spacc->config.ctrl_map	= spacc_ctrl_map[SPACC_CTRL_VER_0];
	else if (spacc->config.version <= 0x60)
		spacc->config.ctrl_map	= spacc_ctrl_map[SPACC_CTRL_VER_1];
	else
		spacc->config.ctrl_map	= spacc_ctrl_map[SPACC_CTRL_VER_2];

	spacc->job_next_swid		= 0;
	spacc->wdcnt			= 0;
	spacc->config.wd_timer		= SPACC_WD_TIMER_INIT;

	/*
	 * Version 4.10 uses IRQ, above uses WD and we don't support
	 * below 4.00
	 */
	if (spacc->config.version < 0x40) {
		dev_dbg(spacc->dptr, "ERR: Unsupported SPAcc version\n");
		return -EIO;
	} else if (spacc->config.version < 0x4B)
		spacc->op_mode = SPACC_OP_MODE_IRQ;
	else
		spacc->op_mode = SPACC_OP_MODE_WD;

	/*
	 * Set threshold and enable irq on 4.11 and newer cores, we can
	 * derive this from the HW reported depths.
	 */
	if (spacc->config.stat_fifo_depth == 1)
		spacc->config.ideal_stat_level = 1;
	else if (spacc->config.stat_fifo_depth <= 4)
		spacc->config.ideal_stat_level =
			spacc->config.stat_fifo_depth - 1;
	else if (spacc->config.stat_fifo_depth <= 8)
		spacc->config.ideal_stat_level =
			spacc->config.stat_fifo_depth - 2;
	else
		spacc->config.ideal_stat_level =
			spacc->config.stat_fifo_depth - 4;

	/* determine max proclen value */
	writel(0xFFFFFFFF, spacc->regmap + SPACC_REG_PROC_LEN);
	spacc->config.max_msg_size = readl(spacc->regmap + SPACC_REG_PROC_LEN);

#ifdef CONFIG_CRYPTO_DEV_SPACC_CONFIG_DEBUG

	/* read config info */
	if (spacc->config.is_pdu) {
		dev_dbg(spacc->dptr, "PDU:\n");
		dev_dbg(spacc->dptr,
			"   MAJOR      : %u\n", info->pdu_config.major);
		dev_dbg(spacc->dptr,
			"   MINOR      : %u\n", info->pdu_config.minor);
	}

	id = readl(spacc->regmap + SPACC_REG_ID);
	dev_dbg(spacc->dptr, "SPACC ID: (%08lx)\n", (unsigned long)id);
	dev_dbg(spacc->dptr, "   MAJOR      : %x\n", info->spacc_version.major);
	dev_dbg(spacc->dptr, "   MINOR      : %x\n", info->spacc_version.minor);
	dev_dbg(spacc->dptr, "   QOS        : %x\n", info->spacc_version.qos);
	dev_dbg(spacc->dptr, "   IVIMPORT   : %x\n", spacc->config.is_ivimport);

	if (spacc->config.version >= 0x48)
		dev_dbg(spacc->dptr,
			"   TYPE       : %lx (%s)\n", SPACC_ID_TYPE(id),
			version_string[SPACC_ID_TYPE(id) & 1]);

	dev_dbg(spacc->dptr, "   AUX        : %x\n", info->spacc_version.aux);
	dev_dbg(spacc->dptr, "   IDX        : %lx %s\n", SPACC_ID_VIDX(id),
		spacc->config.is_secure ?
		(idx_string[spacc->config.is_secure_port & 1]) : "");
	dev_dbg(spacc->dptr,
		"   PARTIAL    : %x\n", info->spacc_version.partial);
	dev_dbg(spacc->dptr,
		"   PROJECT    : %x\n", info->spacc_version.project);

	if (spacc->config.version >= 0x48)
		id = readl(spacc->regmap + SPACC_REG_CONFIG);
	else
		id = 0xFFFFFFFF;

	dev_dbg(spacc->dptr, "SPACC CFG: (%08lx)\n", id);
	dev_dbg(spacc->dptr, "  CTX CNT    : %u\n", info->spacc_config.num_ctx);
	dev_dbg(spacc->dptr,
		"   VSPACC CNT : %u\n", info->spacc_config.num_vspacc);
	dev_dbg(spacc->dptr, "   CIPH SZ    : %-3lu bytes\n", 1UL <<
		info->spacc_config.ciph_ctx_page_size);
	dev_dbg(spacc->dptr, "   HASH SZ    : %-3lu bytes\n", 1UL <<
		info->spacc_config.hash_ctx_page_size);
	dev_dbg(spacc->dptr,
		"   DMA TYPE   : %u (%s)\n", info->spacc_config.dma_type,
		dma_type_string[info->spacc_config.dma_type & 3]);
	dev_dbg(spacc->dptr, "   MAX PROCLEN: %lu bytes\n", (unsigned long)
		spacc->config.max_msg_size);
	dev_dbg(spacc->dptr, "   FIFO CONFIG :\n");
	dev_dbg(spacc->dptr, "CMD0 DEPTH: %d\n", spacc->config.cmd0_fifo_depth);

	if (spacc->config.is_qos) {
		dev_dbg(spacc->dptr, "      CMD1 DEPTH: %d\n",
			spacc->config.cmd1_fifo_depth);
		dev_dbg(spacc->dptr, "      CMD2 DEPTH: %d\n",
			spacc->config.cmd2_fifo_depth);
	}
	dev_dbg(spacc->dptr, "STAT DEPTH: %d\n", spacc->config.stat_fifo_depth);

	if (spacc->config.dma_type == SPACC_DMA_DDT) {
		writel(0x1234567F, baseaddr + SPACC_REG_DST_PTR);
		writel(0xDEADBEEF, baseaddr + SPACC_REG_SRC_PTR);

		if (((readl(baseaddr + SPACC_REG_DST_PTR)) !=
					(0x1234567F & SPACC_DST_PTR_PTR)) ||
		    ((readl(baseaddr + SPACC_REG_SRC_PTR)) !=
		     (0xDEADBEEF & SPACC_SRC_PTR_PTR))) {
			dev_dbg(spacc->dptr, "ERR: Failed to set pointers\n");
			goto ERR;
		}
	}
#endif

	/*
	 * Zero the IRQ CTRL/EN register
	 * (to make sure we're in a sane state)
	 */
	writel(0, spacc->regmap + SPACC_REG_IRQ_CTRL);
	writel(0, spacc->regmap + SPACC_REG_IRQ_EN);
	writel(0xFFFFFFFF, spacc->regmap + SPACC_REG_IRQ_STAT);

	/* init cache */
	memset(&spacc->cache, 0, sizeof(spacc->cache));
	writel(0, spacc->regmap + SPACC_REG_SRC_PTR);
	writel(0, spacc->regmap + SPACC_REG_DST_PTR);
	writel(0, spacc->regmap + SPACC_REG_PROC_LEN);
	writel(0, spacc->regmap + SPACC_REG_ICV_LEN);
	writel(0, spacc->regmap + SPACC_REG_ICV_OFFSET);
	writel(0, spacc->regmap + SPACC_REG_PRE_AAD_LEN);
	writel(0, spacc->regmap + SPACC_REG_POST_AAD_LEN);
	writel(0, spacc->regmap + SPACC_REG_IV_OFFSET);
	writel(0, spacc->regmap + SPACC_REG_OFFSET);
	writel(0, spacc->regmap + SPACC_REG_AUX_INFO);

	spacc->ctx = kvmalloc_array(spacc->config.num_ctx,
				    sizeof(struct spacc_ctx), GFP_KERNEL);
	if (!spacc->ctx)
		goto ERR;

	spacc->job = kvmalloc_array(SPACC_MAX_JOBS, sizeof(struct spacc_job),
				    GFP_KERNEL);
	if (!spacc->job)
		goto ERR;

	/* initialize job_idx and lookup table */
	spacc_job_init_all(spacc);

	/* initialize contexts */
	spacc_ctx_init_all(spacc);

	return 0;
ERR:
	spacc_fini(spacc);
	dev_dbg(spacc->dptr, "ERR: Crypto Failed\n");

	return -EIO;
}

void spacc_pop_jobs(struct work_struct *data)
{
	int num = 0;
	unsigned long lock_flag;
	struct spacc_priv *priv = container_of(data, struct spacc_priv,
					       pop_jobs);
	struct spacc_device *spacc = &priv->spacc;

	spin_lock_irqsave(&spacc->lock, lock_flag);
	spacc->wdcnt = 0;
	spin_unlock_irqrestore(&spacc->lock, lock_flag);

	spacc_pop_packets(spacc, &num);
}

void spacc_remove(struct platform_device *pdev)
{
	struct spacc_device *spacc;
	struct spacc_priv *priv = platform_get_drvdata(pdev);

	/* free test vector memory */
	spacc = &priv->spacc;
	spacc_fini(spacc);

	/* devm functions do proper cleanup */
	pdu_mem_deinit(&pdev->dev);
}

int spacc_set_key_exp(struct spacc_device *spacc, int job_idx)
{
	struct spacc_ctx *ctx = NULL;
	struct spacc_job *job = NULL;

	if (job_idx < 0 || job_idx >= SPACC_MAX_JOBS) {
		dev_dbg(spacc->dptr,
			"ERR: Invalid Job id specified (out of range)\n");
		return -EINVAL;
	}

	job = &spacc->job[job_idx];
	ctx = spacc_context_lookup_by_job(spacc, job_idx);

	if (!ctx) {
		dev_dbg(spacc->dptr, "ERR: Failed to find ctx id\n");
		return -EIO;
	}

	job->ctrl |= SPACC_CTRL_MASK(SPACC_CTRL_KEY_EXP);

	return 0;
}

int spacc_compute_xcbc_key(struct spacc_device *spacc, int mode_id,
			   int job_idx, const unsigned char *key,
			   int keylen, unsigned char *xcbc_out)
{
	int i;
	int usecbc;
	int handle;
	int err = 0;
	int ctx_idx;
	unsigned char *buf;
	dma_addr_t bufphys;
	struct pdu_ddt ddt;
	unsigned char iv[16];
	struct spacc_job *job;

	if (job_idx >= 0 && job_idx < SPACC_MAX_JOBS)
		ctx_idx = spacc->job[job_idx].ctx_idx;
	else
		ctx_idx = -1;

	if (mode_id == CRYPTO_MODE_MAC_XCBC) {
		/* figure out if we can schedule the key */
		if (spacc_is_mode_keysize_supported(spacc, CRYPTO_MODE_AES_ECB,
						    16, 0))
			usecbc = 0;
		else if (spacc_is_mode_keysize_supported(spacc,
							 CRYPTO_MODE_AES_CBC,
							 16, 0))
			usecbc = 1;
		else
			return -EINVAL;
	} else if (mode_id == CRYPTO_MODE_MAC_SM4_XCBC) {
		/* figure out if we can schedule the key */
		if (spacc_is_mode_keysize_supported(spacc, CRYPTO_MODE_SM4_ECB,
						    16, 0))
			usecbc = 0;
		else if (spacc_is_mode_keysize_supported(spacc,
							 CRYPTO_MODE_SM4_CBC,
							 16, 0))
			usecbc = 1;
		else
			return -EINVAL;
	} else
		return -EINVAL;

	memset(iv, 0, sizeof(iv));
	memset(&ddt, 0, sizeof(ddt));

	buf = dma_alloc_coherent(spacc->dptr, 64, &bufphys, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	handle = -1;

	/* set to 1111...., 2222...., 333... */
	for (i = 0; i < 48; i++)
		buf[i] = (i >> 4) + 1;

	/* build DDT */
	err = pdu_ddt_init(spacc->dptr, &ddt, 1);
	if (err)
		goto xcbc_err;

	pdu_ddt_add(spacc->dptr, &ddt, bufphys, 48);

	/* open a handle in either CBC or ECB mode */
	if (mode_id == CRYPTO_MODE_MAC_XCBC) {
		handle = spacc_open(spacc, (usecbc ?
				    CRYPTO_MODE_AES_CBC : CRYPTO_MODE_AES_ECB),
				    CRYPTO_MODE_NULL, ctx_idx, 0, NULL, NULL);

		if (handle < 0) {
			err = handle;
			goto xcbc_err;
		}
	} else if (mode_id == CRYPTO_MODE_MAC_SM4_XCBC) {
		handle = spacc_open(spacc, (usecbc ?
				    CRYPTO_MODE_SM4_CBC : CRYPTO_MODE_SM4_ECB),
				    CRYPTO_MODE_NULL, ctx_idx, 0, NULL, NULL);
		if (handle < 0) {
			err = handle;
			goto xcbc_err;
		}
	}

	spacc_set_operation(spacc, handle, OP_ENCRYPT, 0, 0, 0, 0, 0);
	job = &spacc->job[handle];

	if (usecbc) {
		/*
		 * We can do the ECB work in CBC using three
		 * jobs with the IVreset to zero each time
		 */
		for (i = 0; i < 3; i++) {
			spacc_write_context(spacc, handle,
					    SPACC_CRYPTO_OPERATION, key,
					    keylen, iv, 16);
			err = spacc_packet_enqueue_ddt(spacc, handle, &ddt,
						       &ddt, 16, (i * 16) |
						       ((i * 16) << 16), 0, 0,
						       0, 0, false);
			if (err != 0)
				goto xcbc_err;

			wait_event(job->waitq,
				/*
				 * Pairs with smp_store_release() of
				 * job_done in completion path.
				 */
				smp_load_acquire(&job->job_done));

			job->job_done = 0;
			err = job->job_err;
			if (err != 0)
				goto xcbc_err;
		}
	} else {
		/*
		 * Do the 48 bytes as a single SPAcc job this is the ideal case
		 * but only possible if ECB was enabled in the core
		 */
		spacc_write_context(spacc, handle, SPACC_CRYPTO_OPERATION,
				    key, keylen, iv, 16);
		err = spacc_packet_enqueue_ddt(spacc, handle, &ddt, &ddt, 48,
					       0, 0, 0, 0, 0, false);
		if (err != 0)
			goto xcbc_err;

		wait_event(job->waitq,
			/*
			 * Pairs with smp_store_release() of
			 * job_done in completion path.
			 */
			smp_load_acquire(&job->job_done));

		job->job_done = 0;
		err = job->job_err;
		if (err != 0)
			goto xcbc_err;
	}

	memcpy(xcbc_out, buf, 48);

xcbc_err:
	memzero_explicit(buf, 64);
	dma_free_coherent(spacc->dptr, 64, buf, bufphys);
	pdu_ddt_free(&ddt);

	if (handle >= 0)
		spacc_close(spacc, handle);

	if (err)
		return -EINVAL;

	return 0;
}

void spacc_set_priority(struct spacc_device *spacc, int priority)
{
	u32 vspacc_prio_reg;

	if (!spacc || !spacc->regmap)
		return;

	if (priority < 0 || priority > 15) {
		dev_warn(spacc->dptr,
			 "Invalid VSPAcc priority %d (valid:0-15)\n", priority);
		return;
	}

	/* Build new register value with mode = 0 (WEIGHTED),
	 * weight = priority.
	 */
	vspacc_prio_reg = VPRIO_SET(0, priority);

	/* Write to the SPAcc virtual priority register */
	writel(vspacc_prio_reg, spacc->regmap + SPACC_REG_VIRTUAL_PRIO);

	dev_dbg(spacc->dptr, "Set VSPAcc priority: %d (reg = 0x%08x)\n",
		priority, vspacc_prio_reg);
}
