/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * AES block cipher using AES-NI instructions
 *
 * Copyright 2026 Google LLC
 */

#include <asm/fpu/api.h>

static __ro_after_init DEFINE_STATIC_KEY_FALSE(have_aesni);

/* The assembly code assumes the following offsets. */
static_assert(offsetof(struct aes_enckey, nrounds) == 4);
static_assert(offsetof(struct aes_enckey, k.rndkeys) == 16);
static_assert(offsetof(struct aes_key, nrounds) == 4);
static_assert(offsetof(struct aes_key, k.rndkeys) == 16);
static_assert(offsetof(struct aes_key, inv_k.inv_rndkeys) == 256);

void aes128_expandkey_aesni(u32 rndkeys[], u32 *inv_rndkeys,
			    const u8 in_key[AES_KEYSIZE_128]);
void aes256_expandkey_aesni(u32 rndkeys[], u32 *inv_rndkeys,
			    const u8 in_key[AES_KEYSIZE_256]);
void aes_encrypt_aesni(u8 dst[AES_BLOCK_SIZE], const u8 src[AES_BLOCK_SIZE],
		       const struct aes_enckey *key);
void aes_decrypt_aesni(u8 dst[AES_BLOCK_SIZE], const u8 src[AES_BLOCK_SIZE],
		       const struct aes_key *key);

/*
 * Expand an AES key using AES-NI if supported and usable or generic code
 * otherwise.  The expanded key format is compatible between the two cases.  The
 * outputs are @k->rndkeys (required) and @inv_k->inv_rndkeys (optional).
 *
 * We could just always use the generic key expansion code.  AES key expansion
 * is usually less performance-critical than AES en/decryption.  However,
 * there's still *some* value in speed here, as well as in non-key-dependent
 * execution time which AES-NI provides.  So, do use AES-NI to expand AES-128
 * and AES-256 keys.  (Don't bother with AES-192, as it's almost never used.)
 */
static void aes_preparekey_arch(union aes_enckey_arch *k,
				union aes_invkey_arch *inv_k,
				const u8 *in_key, int key_len, int nrounds)
{
	u32 *rndkeys = k->rndkeys;
	u32 *inv_rndkeys = inv_k ? inv_k->inv_rndkeys : NULL;

	if (static_branch_likely(&have_aesni) && key_len != AES_KEYSIZE_192 &&
	    irq_fpu_usable()) {
		kernel_fpu_begin();
		if (key_len == AES_KEYSIZE_128)
			aes128_expandkey_aesni(rndkeys, inv_rndkeys, in_key);
		else
			aes256_expandkey_aesni(rndkeys, inv_rndkeys, in_key);
		kernel_fpu_end();
	} else {
		aes_expandkey_generic(rndkeys, inv_rndkeys, in_key, key_len);
	}
}

static void aes_encrypt_arch(const struct aes_enckey *key,
			     u8 out[AES_BLOCK_SIZE],
			     const u8 in[AES_BLOCK_SIZE])
{
	if (static_branch_likely(&have_aesni) && irq_fpu_usable()) {
		kernel_fpu_begin();
		aes_encrypt_aesni(out, in, key);
		kernel_fpu_end();
	} else {
		aes_encrypt_generic(key->k.rndkeys, key->nrounds, out, in);
	}
}

static void aes_decrypt_arch(const struct aes_key *key,
			     u8 out[AES_BLOCK_SIZE],
			     const u8 in[AES_BLOCK_SIZE])
{
	if (static_branch_likely(&have_aesni) && irq_fpu_usable()) {
		kernel_fpu_begin();
		aes_decrypt_aesni(out, in, key);
		kernel_fpu_end();
	} else {
		aes_decrypt_generic(key->inv_k.inv_rndkeys, key->nrounds,
				    out, in);
	}
}

#if IS_ENABLED(CONFIG_CRYPTO_LIB_AES_ECB)
void aes_ecb_encrypt_aesni(u8 *dst, const u8 *src, long nblocks,
			   const struct aes_enckey *key);
void aes_ecb_decrypt_aesni(u8 *dst, const u8 *src, long nblocks,
			   const struct aes_key *key);

/* len is always a positive multiple of AES_BLOCK_SIZE here. */
#define aes_ecb_encrypt_arch aes_ecb_encrypt_arch
static bool aes_ecb_encrypt_arch(u8 *dst, const u8 *src, size_t len,
				 const struct aes_enckey *key)
{
	if (!static_branch_likely(&have_aesni) || unlikely(!irq_fpu_usable()))
		return false;
	kernel_fpu_begin();
	aes_ecb_encrypt_aesni(dst, src, len / AES_BLOCK_SIZE, key);
	kernel_fpu_end();
	return true;
}

/* len is always a positive multiple of AES_BLOCK_SIZE here. */
#define aes_ecb_decrypt_arch aes_ecb_decrypt_arch
static bool aes_ecb_decrypt_arch(u8 *dst, const u8 *src, size_t len,
				 const struct aes_key *key)
{
	if (!static_branch_likely(&have_aesni) || unlikely(!irq_fpu_usable()))
		return false;
	kernel_fpu_begin();
	aes_ecb_decrypt_aesni(dst, src, len / AES_BLOCK_SIZE, key);
	kernel_fpu_end();
	return true;
}
#endif /* CONFIG_CRYPTO_LIB_AES_ECB */

#if IS_ENABLED(CONFIG_CRYPTO_LIB_AES_CBC)
void aes_cbc_encrypt_aesni(u8 *dst, const u8 *src, long nblocks,
			   u8 iv[AES_BLOCK_SIZE], const struct aes_enckey *key);
void aes_cbc_decrypt_aesni(u8 *dst, const u8 *src, long nblocks,
			   u8 iv[AES_BLOCK_SIZE], const struct aes_key *key);
void aes_cbc_cts_encrypt_aesni(u8 *dst, const u8 *src, long pn_len,
			       const u8 iv[AES_BLOCK_SIZE],
			       const struct aes_enckey *key);
void aes_cbc_cts_decrypt_aesni(u8 *dst, const u8 *src, long pn_len,
			       const u8 iv[AES_BLOCK_SIZE],
			       const struct aes_key *key);

/* len is always a positive multiple of AES_BLOCK_SIZE here. */
#define aes_cbc_encrypt_arch aes_cbc_encrypt_arch
static bool aes_cbc_encrypt_arch(u8 *dst, const u8 *src, size_t len,
				 u8 iv[AES_BLOCK_SIZE],
				 const struct aes_enckey *key)
{
	if (!static_branch_likely(&have_aesni) || unlikely(!irq_fpu_usable()))
		return false;
	kernel_fpu_begin();
	aes_cbc_encrypt_aesni(dst, src, len / AES_BLOCK_SIZE, iv, key);
	kernel_fpu_end();
	return true;
}

/* len is always a positive multiple of AES_BLOCK_SIZE here. */
#define aes_cbc_decrypt_arch aes_cbc_decrypt_arch
static bool aes_cbc_decrypt_arch(u8 *dst, const u8 *src, size_t len,
				 u8 iv[AES_BLOCK_SIZE],
				 const struct aes_key *key)
{
	if (!static_branch_likely(&have_aesni) || unlikely(!irq_fpu_usable()))
		return false;
	kernel_fpu_begin();
	aes_cbc_decrypt_aesni(dst, src, len / AES_BLOCK_SIZE, iv, key);
	kernel_fpu_end();
	return true;
}

/* len can be any value greater than AES_BLOCK_SIZE here. */
#define aes_cbc_cts_encrypt_arch aes_cbc_cts_encrypt_arch
static bool aes_cbc_cts_encrypt_arch(u8 *dst, const u8 *src, size_t len,
				     u8 iv[AES_BLOCK_SIZE],
				     const struct aes_enckey *key)
{
	const size_t cbc_blocks = (len - AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	const size_t pn_len = ((len - 1) % AES_BLOCK_SIZE) + 1;

	if (!static_branch_likely(&have_aesni) || unlikely(!irq_fpu_usable()))
		return false;

	kernel_fpu_begin();
	if (cbc_blocks) {
		aes_cbc_encrypt_aesni(dst, src, cbc_blocks, iv, key);
		dst += cbc_blocks * AES_BLOCK_SIZE;
		src += cbc_blocks * AES_BLOCK_SIZE;
	}
	/* Encrypt the last 17 to 32 bytes. */
	aes_cbc_cts_encrypt_aesni(dst, src, pn_len, iv, key);
	kernel_fpu_end();
	return true;
}

/* len can be any value greater than AES_BLOCK_SIZE here. */
#define aes_cbc_cts_decrypt_arch aes_cbc_cts_decrypt_arch
static bool aes_cbc_cts_decrypt_arch(u8 *dst, const u8 *src, size_t len,
				     u8 iv[AES_BLOCK_SIZE],
				     const struct aes_key *key)
{
	const size_t cbc_blocks = (len - AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	const size_t pn_len = ((len - 1) % AES_BLOCK_SIZE) + 1;

	if (!static_branch_likely(&have_aesni) || unlikely(!irq_fpu_usable()))
		return false;

	kernel_fpu_begin();
	if (cbc_blocks) {
		aes_cbc_decrypt_aesni(dst, src, cbc_blocks, iv, key);
		dst += cbc_blocks * AES_BLOCK_SIZE;
		src += cbc_blocks * AES_BLOCK_SIZE;
	}
	/* Decrypt the last 17 to 32 bytes. */
	aes_cbc_cts_decrypt_aesni(dst, src, pn_len, iv, key);
	kernel_fpu_end();
	return true;
}
#endif /* CONFIG_CRYPTO_LIB_AES_CBC */

#define aes_mod_init_arch aes_mod_init_arch
static void aes_mod_init_arch(void)
{
	if (boot_cpu_has(X86_FEATURE_AES))
		static_branch_enable(&have_aesni);
}
