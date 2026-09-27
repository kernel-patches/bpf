/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 VRULL GmbH
 * Copyright (C) 2023 SiFive, Inc.
 * Copyright 2024 Google LLC
 */

#include <asm/simd.h>
#include <asm/vector.h>

static __ro_after_init DEFINE_STATIC_KEY_FALSE(have_zvkned);

/* The assembly code assumes the following offsets. */
static_assert(offsetof(struct aes_enckey, len) == 0);
static_assert(offsetof(struct aes_enckey, k.rndkeys) == 16);
static_assert(offsetof(struct aes_key, len) == 0);
static_assert(offsetof(struct aes_key, k.rndkeys) == 16);

void aes_encrypt_zvkned(const struct aes_enckey *key, u8 out[AES_BLOCK_SIZE],
			const u8 in[AES_BLOCK_SIZE]);
void aes_decrypt_zvkned(const struct aes_key *key, u8 out[AES_BLOCK_SIZE],
			const u8 in[AES_BLOCK_SIZE]);

static void aes_preparekey_arch(union aes_enckey_arch *k,
				union aes_invkey_arch *inv_k,
				const u8 *in_key, int key_len, int nrounds)
{
	aes_expandkey_generic(k->rndkeys, inv_k ? inv_k->inv_rndkeys : NULL,
			      in_key, key_len);
}

static void aes_encrypt_arch(const struct aes_enckey *key,
			     u8 out[AES_BLOCK_SIZE],
			     const u8 in[AES_BLOCK_SIZE])
{
	if (static_branch_likely(&have_zvkned) && likely(may_use_simd())) {
		kernel_vector_begin();
		aes_encrypt_zvkned(key, out, in);
		kernel_vector_end();
	} else {
		aes_encrypt_generic(key->k.rndkeys, key->nrounds, out, in);
	}
}

static void aes_decrypt_arch(const struct aes_key *key,
			     u8 out[AES_BLOCK_SIZE],
			     const u8 in[AES_BLOCK_SIZE])
{
	/*
	 * Note that the Zvkned code uses the standard round keys, while the
	 * fallback uses the inverse round keys.  Thus both must be present.
	 */
	if (static_branch_likely(&have_zvkned) && likely(may_use_simd())) {
		kernel_vector_begin();
		aes_decrypt_zvkned(key, out, in);
		kernel_vector_end();
	} else {
		aes_decrypt_generic(key->inv_k.inv_rndkeys, key->nrounds,
				    out, in);
	}
}

#if IS_ENABLED(CONFIG_CRYPTO_LIB_AES_ECB)
void aes_ecb_encrypt_zvkned(u8 *dst, const u8 *src, size_t len,
			    const struct aes_enckey *key);
void aes_ecb_decrypt_zvkned(u8 *dst, const u8 *src, size_t len,
			    const struct aes_key *key);

/* len is always a positive multiple of AES_BLOCK_SIZE here. */
#define aes_ecb_encrypt_arch aes_ecb_encrypt_arch
static bool aes_ecb_encrypt_arch(u8 *dst, const u8 *src, size_t len,
				 const struct aes_enckey *key)
{
	if (!static_branch_likely(&have_zvkned) || unlikely(!may_use_simd()))
		return false;
	kernel_vector_begin();
	aes_ecb_encrypt_zvkned(dst, src, len, key);
	kernel_vector_end();
	return true;
}

/* len is always a positive multiple of AES_BLOCK_SIZE here. */
#define aes_ecb_decrypt_arch aes_ecb_decrypt_arch
static bool aes_ecb_decrypt_arch(u8 *dst, const u8 *src, size_t len,
				 const struct aes_key *key)
{
	if (!static_branch_likely(&have_zvkned) || unlikely(!may_use_simd()))
		return false;
	kernel_vector_begin();
	aes_ecb_decrypt_zvkned(dst, src, len, key);
	kernel_vector_end();
	return true;
}
#endif /* CONFIG_CRYPTO_LIB_AES_ECB */

#if IS_ENABLED(CONFIG_CRYPTO_LIB_AES_CBC)
void aes_cbc_encrypt_zvkned(u8 *dst, const u8 *src, size_t len,
			    u8 iv[AES_BLOCK_SIZE], const struct aes_enckey *key);
void aes_cbc_decrypt_zvkned(u8 *dst, const u8 *src, size_t len,
			    u8 iv[AES_BLOCK_SIZE], const struct aes_key *key);
void aes_cbc_cts_crypt_zvkned(u8 *dst, const u8 *src, size_t len,
			      const u8 iv[AES_BLOCK_SIZE],
			      aes_encrypt_arg key, bool enc);

/* len is always a positive multiple of AES_BLOCK_SIZE here. */
#define aes_cbc_encrypt_arch aes_cbc_encrypt_arch
static bool aes_cbc_encrypt_arch(u8 *dst, const u8 *src, size_t len,
				 u8 iv[AES_BLOCK_SIZE],
				 const struct aes_enckey *key)
{
	if (!static_branch_likely(&have_zvkned) || unlikely(!may_use_simd()))
		return false;
	kernel_vector_begin();
	aes_cbc_encrypt_zvkned(dst, src, len, iv, key);
	kernel_vector_end();
	return true;
}

/* len is always a positive multiple of AES_BLOCK_SIZE here. */
#define aes_cbc_decrypt_arch aes_cbc_decrypt_arch
static bool aes_cbc_decrypt_arch(u8 *dst, const u8 *src, size_t len,
				 u8 iv[AES_BLOCK_SIZE],
				 const struct aes_key *key)
{
	if (!static_branch_likely(&have_zvkned) || unlikely(!may_use_simd()))
		return false;
	kernel_vector_begin();
	aes_cbc_decrypt_zvkned(dst, src, len, iv, key);
	kernel_vector_end();
	return true;
}

/* len can be any value greater than AES_BLOCK_SIZE here. */
#define aes_cbc_cts_encrypt_arch aes_cbc_cts_encrypt_arch
static bool aes_cbc_cts_encrypt_arch(u8 *dst, const u8 *src, size_t len,
				     u8 iv[AES_BLOCK_SIZE],
				     const struct aes_enckey *key)
{
	if (!static_branch_likely(&have_zvkned) || unlikely(!may_use_simd()))
		return false;

	kernel_vector_begin();
	aes_cbc_cts_crypt_zvkned(dst, src, len, iv, key, true);
	kernel_vector_end();
	return true;
}

/* len can be any value greater than AES_BLOCK_SIZE here. */
#define aes_cbc_cts_decrypt_arch aes_cbc_cts_decrypt_arch
static bool aes_cbc_cts_decrypt_arch(u8 *dst, const u8 *src, size_t len,
				     u8 iv[AES_BLOCK_SIZE],
				     const struct aes_key *key)
{
	if (!static_branch_likely(&have_zvkned) || unlikely(!may_use_simd()))
		return false;

	kernel_vector_begin();
	aes_cbc_cts_crypt_zvkned(dst, src, len, iv, key, false);
	kernel_vector_end();
	return true;
}
#endif /* CONFIG_CRYPTO_LIB_AES_CBC */

#define aes_mod_init_arch aes_mod_init_arch
static void aes_mod_init_arch(void)
{
	if (riscv_isa_extension_available(NULL, ZVKNED) &&
	    riscv_vector_vlen() >= 128)
		static_branch_enable(&have_zvkned);
}
