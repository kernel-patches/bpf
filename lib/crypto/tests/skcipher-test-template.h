/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Shared KUnit test cases for length-preserving symmetric ciphers, including a
 * benchmark
 *
 * Copyright 2026 Google LLC
 */

/*
 * This file implements KUnit test cases shared by the different KUnit test
 * suites for length-preserving symmetric ciphers.
 *
 * Test suites including this file must #define the following:
 *
 * Data structs:
 *
 * - SKCIPHER_KEY: name of key struct
 *
 * Constants:
 *
 * - SKCIPHER_VALID_KEY_LENS: array of all valid key lengths in bytes
 *
 * - SKCIPHER_MAX_KEY_LEN: max key length in bytes (assumed to fit on stack)
 *
 * - SKCIPHER_IV_LEN: length of the initialization vector.  If
 *   SKCIPHER_INCREMENTAL is defined, the initialization vector buffer is also
 *   assumed to contain the carried-forward state.
 *
 * - SKCIPHER_MIN_DATA_LEN: minimum valid data length in bytes.  Must be a
 *   (possibly zero) multiple of SKCIPHER_DATA_LEN_ALIGN, and a (possibly zero)
 *   multiple of SKCIPHER_NONFINAL_DATA_LEN_ALIGN if that is defined.
 *
 * - SKCIPHER_DATA_LEN_ALIGN: valid data lengths are multiples of this.
 *   Must be a power of 2.
 *
 * - SKCIPHER_MONTE_CARLO_CHECKSUM: checksum of a deterministically generated
 *   series of ciphertexts (see test_skcipher_monte_carlo())
 *
 * Functions:
 *
 * - SKCIPHER_PREPAREKEY(key, raw_key, key_len): key preparation, returning 0 or
 *   -EINVAL.
 *
 * - SKCIPHER_ENCRYPT(dst, src, len, iv, key, cont) and
 *   SKCIPHER_DECRYPT(dst, src, len, iv, key, cont): en/decryption functions.
 *   'iv' is the IV state, which is updated in place.  'cont' is false on the
 *   first call for a message and true on any subsequent calls.
 *
 * Optionally, test suites may #define the following:
 *
 * - SKCIPHER_ENCKEY: encryption-only key struct.  If defined,
 *   SKCIPHER_ENCRYPT must accept either SKCIPHER_KEY or SKCIPHER_ENCKEY.
 *
 * - SKCIPHER_PREPAREENCKEY(key, raw_key, key_len):
 *   function to prepare a struct SKCIPHER_ENCKEY.
 *
 * - SKCIPHER_IS_KEY_LEN_ALLOWED(key_len): returns false if a key length in
 *   SKCIPHER_VALID_KEY_LENS is currently disallowed (e.g. due to FIPS mode).
 *
 * - SKCIPHER_INCREMENTAL: if defined, en/decryption may be split across
 *   multiple calls.  The length of each non-final call must be a multiple of
 *   SKCIPHER_NONFINAL_DATA_LEN_ALIGN and at least SKCIPHER_MIN_DATA_LEN, and
 *   the updated IV state must be passed to the next call.  In this case, if the
 *   total length is a multiple of SKCIPHER_NONFINAL_DATA_LEN_ALIGN (or if
 *   SKCIPHER_NEXT_IV_ALWAYS_DEFINED is also defined), the final IV state is
 *   expected to be the same regardless of how the message was split.
 *
 * - SKCIPHER_NONFINAL_DATA_LEN_ALIGN: non-final calls require a data length
 *   that is a multiple of this.  Must be a power of 2 and a multiple of
 *   SKCIPHER_DATA_LEN_ALIGN.
 *
 * - SKCIPHER_NEXT_IV_ALWAYS_DEFINED: if defined alongside SKCIPHER_INCREMENTAL,
 *   the final IV state is well-defined for all valid data lengths, not just
 *   multiples of SKCIPHER_NONFINAL_DATA_LEN_ALIGN.
 *
 * After including this file, include SKCIPHER_KUNIT_CASES in the kunit_case
 * array.  This file also provides struct skcipher_testvec and
 * skcipher_run_testvecs() for running known-answer test vectors.
 */

#include <crypto/blake2s.h>
#include <kunit/run-in-irq-context.h>
#include <kunit/test.h>
#include <linux/preempt.h>
#include <linux/timekeeping.h>
#include "test-utils.h"

#ifndef SKCIPHER_IS_KEY_LEN_ALLOWED
#define SKCIPHER_IS_KEY_LEN_ALLOWED(key_len) ((void)(key_len), true)
#endif

#define SKCIPHER_IS_POWER_OF_2(x) ((x) != 0 && ((x) & ((x) - 1)) == 0)

static_assert(SKCIPHER_IS_POWER_OF_2(SKCIPHER_DATA_LEN_ALIGN));
static_assert(SKCIPHER_MIN_DATA_LEN % SKCIPHER_DATA_LEN_ALIGN == 0);
#ifdef SKCIPHER_INCREMENTAL
static_assert(SKCIPHER_IS_POWER_OF_2(SKCIPHER_NONFINAL_DATA_LEN_ALIGN));
static_assert(SKCIPHER_NONFINAL_DATA_LEN_ALIGN % SKCIPHER_DATA_LEN_ALIGN == 0);
static_assert(SKCIPHER_MIN_DATA_LEN % SKCIPHER_NONFINAL_DATA_LEN_ALIGN == 0);
#endif

/* Size to use for IV buffers.  Avoids zero-length arrays. */
#define SKCIPHER_IV_BUF_SIZE (SKCIPHER_IV_LEN > 0 ? SKCIPHER_IV_LEN : 1)

struct skcipher_testvec {
	const char *name;
	const char *key;
	size_t key_len;
	const char *iv; /* Unused if SKCIPHER_IV_LEN == 0 */
	const char *ptext;
	const char *ctext;
	size_t data_len;
	/* Optional: the expected IV state after en/decrypting the message */
	const char *next_iv;
};

static void skcipher_crypt(u8 *dst, const u8 *src, size_t len, u8 *iv,
			   const struct SKCIPHER_KEY *key, bool cont, bool enc)
{
	if (enc)
		SKCIPHER_ENCRYPT(dst, src, len, iv, key, cont);
	else
		SKCIPHER_DECRYPT(dst, src, len, iv, key, cont);
}

static void skcipher_copy_iv(u8 *dst, const u8 *src)
{
	if (SKCIPHER_IV_LEN)
		memcpy(dst, src, SKCIPHER_IV_LEN);
}

/*
 * Return true if the IV state is defined after en/decrypting a message of
 * length @data_len.
 */
static bool skcipher_is_next_iv_defined(size_t data_len)
{
#if defined(SKCIPHER_INCREMENTAL) && defined(SKCIPHER_NEXT_IV_ALWAYS_DEFINED)
	return SKCIPHER_IV_LEN != 0;
#elif defined(SKCIPHER_INCREMENTAL)
	return SKCIPHER_IV_LEN != 0 &&
	       data_len % SKCIPHER_NONFINAL_DATA_LEN_ALIGN == 0;
#else
	return false;
#endif
}

/* Return true if data_len is a valid data length. */
static bool skcipher_is_data_len_valid(size_t data_len)
{
	return data_len >= SKCIPHER_MIN_DATA_LEN &&
	       data_len % SKCIPHER_DATA_LEN_ALIGN == 0;
}

/*
 * Generate a random valid data length that is <= @max_len.  @max_len must be at
 * least SKCIPHER_MIN_DATA_LEN.
 */
static size_t skcipher_rand_data_len(size_t max_len)
{
	size_t len = round_down(rand_length(max_len), SKCIPHER_DATA_LEN_ALIGN);

	return max(len, SKCIPHER_MIN_DATA_LEN);
}

/* Return true if key_len is a valid key length and is currently allowed. */
static bool skcipher_is_key_len_expected_valid(size_t key_len)
{
	for (size_t i = 0; i < ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS); i++) {
		if (SKCIPHER_VALID_KEY_LENS[i] == key_len)
			return SKCIPHER_IS_KEY_LEN_ALLOWED(key_len);
	}
	return false;
}

/* Select a random key length that is valid and currently allowed. */
static size_t skcipher_rand_key_len(void)
{
	size_t key_len;

	do {
		key_len = SKCIPHER_VALID_KEY_LENS
			[rand32() % ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS)];
	} while (!SKCIPHER_IS_KEY_LEN_ALLOWED(key_len));
	return key_len;
}

struct skcipher_test_keys {
	struct SKCIPHER_KEY keys[ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS)];
	size_t num_keys;
};

/*
 * Allocate and prepare one struct SKCIPHER_KEY for each currently-allowed key
 * length in SKCIPHER_VALID_KEY_LENS, using random key bytes.
 */
static struct skcipher_test_keys *skcipher_alloc_test_keys(struct kunit *test)
{
	struct skcipher_test_keys *keys = alloc_buf(test, sizeof(*keys));
	u8 raw_key[SKCIPHER_MAX_KEY_LEN];
	int err;

	keys->num_keys = 0;
	for (size_t i = 0; i < ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS); i++) {
		size_t key_len = SKCIPHER_VALID_KEY_LENS[i];

		KUNIT_ASSERT_LE(test, key_len, SKCIPHER_MAX_KEY_LEN);
		if (!SKCIPHER_IS_KEY_LEN_ALLOWED(key_len))
			continue;
		rand_bytes(raw_key, key_len);
		err = SKCIPHER_PREPAREKEY(&keys->keys[keys->num_keys++],
					  raw_key, key_len);
		KUNIT_ASSERT_EQ(test, 0, err);
	}
	KUNIT_ASSERT_GT(test, keys->num_keys, 0);
	return keys;
}

static const struct SKCIPHER_KEY *
skcipher_pick_key(const struct skcipher_test_keys *keys, size_t idx)
{
	return &keys->keys[idx % keys->num_keys];
}

/*
 * Allocate a KUnit-managed IV state buffer that is immediately followed by an
 * unmapped page.  If SKCIPHER_IV_LEN == 0, the returned pointer points to the
 * unmapped page itself, so any access to the IV state will fault.
 */
static u8 *skcipher_alloc_guarded_iv(struct kunit *test)
{
	return alloc_guarded_buf(test, SKCIPHER_IV_BUF_SIZE) +
	       SKCIPHER_IV_BUF_SIZE - SKCIPHER_IV_LEN;
}

/*
 * Run the given test vectors.  This is called by each test suite, which defines
 * its own test vectors after including this file.
 */
static __maybe_unused void
skcipher_run_testvecs(struct kunit *test, const struct skcipher_testvec *tvs,
		      size_t num_tvs)
{
	const size_t max_data_len = 512;
	struct SKCIPHER_KEY *key = alloc_buf(test, sizeof(*key));
	u8 *out = alloc_buf(test, max_data_len);
	u8 iv[SKCIPHER_IV_BUF_SIZE];
	int err;

	for (size_t i = 0; i < num_tvs; i++) {
		const struct skcipher_testvec *tv = &tvs[i];

		if (!SKCIPHER_IS_KEY_LEN_ALLOWED(tv->key_len))
			continue;

		KUNIT_ASSERT_LE(test, tv->data_len, max_data_len);
		KUNIT_ASSERT_TRUE(test,
				  skcipher_is_data_len_valid(tv->data_len));
		if (tv->next_iv)
			KUNIT_ASSERT_TRUE(test, skcipher_is_next_iv_defined(
							tv->data_len));

		err = SKCIPHER_PREPAREKEY(key, tv->key, tv->key_len);
		KUNIT_ASSERT_EQ_MSG(test, 0, err,
				    "Failed to prepare key for %s", tv->name);

		skcipher_copy_iv(iv, tv->iv);
		SKCIPHER_ENCRYPT(out, tv->ptext, tv->data_len, iv, key, false);
		KUNIT_ASSERT_MEMEQ_MSG(test, tv->ctext, out, tv->data_len,
				       "Wrong ciphertext for %s", tv->name);
		if (tv->next_iv)
			KUNIT_ASSERT_MEMEQ_MSG(
				test, tv->next_iv, iv, SKCIPHER_IV_LEN,
				"Wrong next IV after encryption for %s",
				tv->name);

		skcipher_copy_iv(iv, tv->iv);
		SKCIPHER_DECRYPT(out, tv->ctext, tv->data_len, iv, key, false);
		KUNIT_ASSERT_MEMEQ_MSG(test, tv->ptext, out, tv->data_len,
				       "Wrong plaintext for %s", tv->name);
		if (tv->next_iv)
			KUNIT_ASSERT_MEMEQ_MSG(
				test, tv->next_iv, iv, SKCIPHER_IV_LEN,
				"Wrong next IV after decryption for %s",
				tv->name);
	}
}

/*
 * Given an expected-valid key_len, verify that preparing a key with that length
 * succeeds and that encryption and decryption round-trip with it.  Use guarded
 * buffers for the key struct, the raw key, and the IV state to detect any
 * buffer overruns.
 */
static void skcipher_verify_valid_key_len(struct kunit *test,
					  struct SKCIPHER_KEY *key,
					  const u8 *raw_key_buf_end,
					  size_t key_len, u8 *iv,
					  const u8 *orig_iv)
{
	const u8 *raw_key = raw_key_buf_end - key_len;
	u8 pt[64], ct[64], decrypted[64];
	int err;

	static_assert(sizeof(pt) >= SKCIPHER_MIN_DATA_LEN);
	static_assert(sizeof(pt) % SKCIPHER_DATA_LEN_ALIGN == 0);
	rand_bytes(pt, sizeof(pt));

	err = SKCIPHER_PREPAREKEY(key, raw_key, key_len);
	KUNIT_ASSERT_EQ_MSG(test, 0, err, "key_len=%zu wasn't accepted",
			    key_len);

	skcipher_copy_iv(iv, orig_iv);
	SKCIPHER_ENCRYPT(ct, pt, sizeof(pt), iv, key, false);
	skcipher_copy_iv(iv, orig_iv);
	SKCIPHER_DECRYPT(decrypted, ct, sizeof(pt), iv, key, false);
	KUNIT_ASSERT_MEMEQ_MSG(
		test, pt, decrypted, sizeof(pt),
		"Decryption didn't invert encryption with key_len=%zu",
		key_len);
}

/* Verify that the given expected-invalid key_len is actually rejected. */
static void skcipher_verify_invalid_key_len(struct kunit *test,
					    struct SKCIPHER_KEY *key,
					    const u8 *unmapped_ptr,
					    size_t key_len)
{
	int err;

	/*
	 * The preparekey function should reject the key_len without
	 * dereferencing the raw key pointer, and it should leave the key struct
	 * zeroed.  (It may either not write to it at all or zeroize it.)
	 */
	memset(key, 0, sizeof(*key));
	err = SKCIPHER_PREPAREKEY(key, unmapped_ptr, key_len);
	KUNIT_ASSERT_EQ_MSG(test, -EINVAL, err,
			    "key_len=%zu wasn't rejected with -EINVAL",
			    key_len);
	KUNIT_ASSERT_TRUE_MSG(
		test, mem_is_zero(key, sizeof(*key)),
		"Key struct wasn't left zeroed on invalid key_len=%zu",
		key_len);
}

/*
 * Test that every valid key length is accepted and works, and test that invalid
 * key lengths are rejected.
 */
static void test_skcipher_all_key_lens(struct kunit *test)
{
	struct SKCIPHER_KEY *key = alloc_guarded_buf(test, sizeof(*key));
	/*
	 * raw_key_buf_end points to the unmapped guard page immediately
	 * following the guarded buffer.  Passing it when testing invalid key
	 * lengths ensures that any dereference of the raw key pointer faults.
	 */
	const u8 *raw_key_buf_end =
		alloc_guarded_rand_buf(test, SKCIPHER_MAX_KEY_LEN) +
		SKCIPHER_MAX_KEY_LEN;
	u8 *iv = skcipher_alloc_guarded_iv(test);
	u8 orig_iv[SKCIPHER_IV_BUF_SIZE];

	rand_bytes(orig_iv, sizeof(orig_iv));

	for (size_t i = 0; i < ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS); i++)
		KUNIT_ASSERT_LE(test, SKCIPHER_VALID_KEY_LENS[i],
				SKCIPHER_MAX_KEY_LEN);

	for (size_t key_len = 0; key_len <= SKCIPHER_MAX_KEY_LEN; key_len++) {
		if (skcipher_is_key_len_expected_valid(key_len))
			skcipher_verify_valid_key_len(test, key,
						      raw_key_buf_end, key_len,
						      iv, orig_iv);
		else
			skcipher_verify_invalid_key_len(
				test, key, raw_key_buf_end, key_len);
	}
	skcipher_verify_invalid_key_len(test, key, raw_key_buf_end,
					SKCIPHER_MAX_KEY_LEN + 1);
	skcipher_verify_invalid_key_len(test, key, raw_key_buf_end,
					SKCIPHER_MAX_KEY_LEN * 2);
	skcipher_verify_invalid_key_len(test, key, raw_key_buf_end, U32_MAX);
	skcipher_verify_invalid_key_len(test, key, raw_key_buf_end, SIZE_MAX);
#ifdef CONFIG_64BIT
	/* Check for 64-to-32-bit truncation of key_len. */
	for (size_t i = 0; i < ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS); i++)
		skcipher_verify_invalid_key_len(
			test, key, raw_key_buf_end,
			((size_t)U32_MAX + 1) + SKCIPHER_VALID_KEY_LENS[i]);
#endif
}

/*
 * Monte-Carlo test.  This deterministically generates random inputs for every
 * valid data length up to 1024 bytes, encrypts them, verifies decryption, and
 * computes and verifies the checksum of all the computed ciphertexts.  The
 * expected checksum was computed using an independent implementation of the
 * algorithm (see scripts/crypto/gen-skcipher-testvecs.py), so this test
 * provides known-answer test coverage for many inputs at once.
 */
static void test_skcipher_monte_carlo(struct kunit *test)
{
	const size_t max_data_len = 1024;
	u8 raw_key[SKCIPHER_MAX_KEY_LEN];
	u8 orig_iv[SKCIPHER_IV_BUF_SIZE];
	u8 iv[SKCIPHER_IV_BUF_SIZE];
	u8 *pt = alloc_buf(test, max_data_len);
	u8 *ct = alloc_buf(test, max_data_len);
	u8 *decrypted = alloc_buf(test, max_data_len);
	struct SKCIPHER_KEY *key = alloc_buf(test, sizeof(*key));
	struct blake2s_ctx checksum_ctx;
	u8 actual_checksum[BLAKE2S_HASH_SIZE];
	int err;

	for (size_t i = 0; i < ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS); i++) {
		/*
		 * The expected checksum covers all the valid key lengths, so
		 * this test isn't applicable if any of them is disallowed.
		 */
		if (!SKCIPHER_IS_KEY_LEN_ALLOWED(SKCIPHER_VALID_KEY_LENS[i]))
			kunit_skip(
				test,
				"not applicable, since key_len=%zu is disallowed (FIPS mode)",
				SKCIPHER_VALID_KEY_LENS[i]);
	}

	blake2s_init(&checksum_ctx, BLAKE2S_HASH_SIZE);

	for (size_t data_len = 0; data_len <= max_data_len; data_len++) {
		size_t key_len;

		if (!skcipher_is_data_len_valid(data_len))
			continue;

		key_len = SKCIPHER_VALID_KEY_LENS
			[(data_len / SKCIPHER_DATA_LEN_ALIGN) %
			 ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS)];

		random_seed = data_len;
		rand_bytes(raw_key, key_len);
		rand_bytes(orig_iv, SKCIPHER_IV_LEN);
		rand_bytes(pt, data_len);

		err = SKCIPHER_PREPAREKEY(key, raw_key, key_len);
		KUNIT_ASSERT_EQ(test, 0, err);

		skcipher_copy_iv(iv, orig_iv);
		SKCIPHER_ENCRYPT(ct, pt, data_len, iv, key, false);
		skcipher_copy_iv(iv, orig_iv);
		SKCIPHER_DECRYPT(decrypted, ct, data_len, iv, key, false);
		KUNIT_ASSERT_MEMEQ_MSG(
			test, pt, decrypted, data_len,
			"Decryption didn't invert encryption; data_len=%zu",
			data_len);

		blake2s_update(&checksum_ctx, ct, data_len);
	}

	blake2s_final(&checksum_ctx, actual_checksum);
	KUNIT_EXPECT_MEMEQ_MSG(test, actual_checksum,
			       SKCIPHER_MONTE_CARLO_CHECKSUM, BLAKE2S_HASH_SIZE,
			       "Monte-Carlo checksum mismatch");
}

#ifdef SKCIPHER_INCREMENTAL
/*
 * En/decrypt a message using a random incremental strategy.  The length of each
 * part will be at least SKCIPHER_MIN_DATA_LEN (assuming @len >=
 * SKCIPHER_MIN_DATA_LEN), and if it's a non-final part the length will also be
 * a multiple of SKCIPHER_NONFINAL_DATA_LEN_ALIGN.  Return the number of parts.
 */
static size_t skcipher_crypt_incrementally(u8 *dst, const u8 *src, size_t len,
					   u8 *iv,
					   const struct SKCIPHER_KEY *key,
					   bool enc)
{
	size_t num_parts = 0;
	size_t pos = 0;

	while (rand_bool() && len - pos >= 2 * SKCIPHER_MIN_DATA_LEN) {
		size_t part_len = round_down(
			rand_length(len - pos - SKCIPHER_MIN_DATA_LEN),
			SKCIPHER_NONFINAL_DATA_LEN_ALIGN);

		part_len = max(part_len, SKCIPHER_MIN_DATA_LEN);
		skcipher_crypt(&dst[pos], &src[pos], part_len, iv, key,
			       num_parts != 0, enc);
		pos += part_len;
		num_parts++;
	}
	if (pos < len || rand_bool()) {
		skcipher_crypt(&dst[pos], &src[pos], len - pos, iv, key,
			       num_parts != 0, enc);
		num_parts++;
	}
	return num_parts;
}

/*
 * Test that one-shot encryption and decryption are consistent with incremental
 * encryption and decryption using random split points.
 */
static void test_skcipher_incremental(struct kunit *test)
{
	const size_t max_data_len = 4096;
	const struct skcipher_test_keys *keys = skcipher_alloc_test_keys(test);
	const u8 *pt = alloc_rand_buf(test, max_data_len);
	u8 *ct = alloc_buf(test, max_data_len);
	u8 *ct2 = alloc_buf(test, max_data_len);
	u8 *decrypted = alloc_buf(test, max_data_len);
	u8 orig_iv[SKCIPHER_IV_BUF_SIZE];
	u8 iv[SKCIPHER_IV_BUF_SIZE];
	u8 iv2[SKCIPHER_IV_BUF_SIZE];

	for (int i = 0; i < 500; i++) {
		const struct SKCIPHER_KEY *key = skcipher_pick_key(keys, i);
		size_t data_len = skcipher_rand_data_len(max_data_len);
		bool check_iv = skcipher_is_next_iv_defined(data_len);
		size_t num_parts;

		rand_bytes(orig_iv, sizeof(orig_iv));

		/* Encrypt one-shot, then incrementally. */
		memset(ct, 0, data_len);
		skcipher_copy_iv(iv, orig_iv);
		SKCIPHER_ENCRYPT(ct, pt, data_len, iv, key, false);
		memset(ct2, 0, data_len);
		skcipher_copy_iv(iv2, orig_iv);
		num_parts = skcipher_crypt_incrementally(ct2, pt, data_len, iv2,
							 key, true);
		KUNIT_ASSERT_MEMEQ_MSG(
			test, ct, ct2, data_len,
			"One-shot and incremental encryption differ; data_len=%zu num_parts=%zu",
			data_len, num_parts);
		if (check_iv)
			KUNIT_ASSERT_MEMEQ_MSG(
				test, iv, iv2, SKCIPHER_IV_LEN,
				"One-shot and incremental encryption gave different next IV; data_len=%zu num_parts=%zu",
				data_len, num_parts);

		/* Decrypt one-shot, then incrementally. */
		memset(decrypted, 0, data_len);
		skcipher_copy_iv(iv, orig_iv);
		SKCIPHER_DECRYPT(decrypted, ct, data_len, iv, key, false);
		KUNIT_ASSERT_MEMEQ_MSG(
			test, pt, decrypted, data_len,
			"Decryption didn't invert encryption; data_len=%zu",
			data_len);
		memset(decrypted, 0, data_len);
		skcipher_copy_iv(iv2, orig_iv);
		num_parts = skcipher_crypt_incrementally(
			decrypted, ct, data_len, iv2, key, false);
		KUNIT_ASSERT_MEMEQ_MSG(
			test, pt, decrypted, data_len,
			"Incremental decryption gave wrong plaintext; data_len=%zu num_parts=%zu",
			data_len, num_parts);
		if (check_iv)
			KUNIT_ASSERT_MEMEQ_MSG(
				test, iv, iv2, SKCIPHER_IV_LEN,
				"One-shot and incremental decryption gave different next IV; data_len=%zu num_parts=%zu",
				data_len, num_parts);
	}
}

static void skcipher_check_all_splits(struct kunit *test,
				      const struct SKCIPHER_KEY *key,
				      const u8 *pt, u8 *ct, u8 *out,
				      size_t max_data_len)
{
	u8 orig_iv[SKCIPHER_IV_BUF_SIZE];
	u8 next_iv_enc[SKCIPHER_IV_BUF_SIZE];
	u8 next_iv_dec[SKCIPHER_IV_BUF_SIZE];
	u8 iv[SKCIPHER_IV_BUF_SIZE];

	rand_bytes(orig_iv, sizeof(orig_iv));

	for (size_t data_len = 0; data_len <= max_data_len; data_len++) {
		bool check_iv = skcipher_is_next_iv_defined(data_len);

		if (!skcipher_is_data_len_valid(data_len))
			continue;

		/* Compute the expected results using one-shot en/decryption. */
		skcipher_copy_iv(next_iv_enc, orig_iv);
		SKCIPHER_ENCRYPT(ct, pt, data_len, next_iv_enc, key, false);
		skcipher_copy_iv(next_iv_dec, orig_iv);
		SKCIPHER_DECRYPT(out, ct, data_len, next_iv_dec, key, false);
		KUNIT_ASSERT_MEMEQ(test, pt, out, data_len);

		for (size_t split = SKCIPHER_MIN_DATA_LEN;
		     split + SKCIPHER_MIN_DATA_LEN <= data_len;
		     split += SKCIPHER_NONFINAL_DATA_LEN_ALIGN) {
			skcipher_copy_iv(iv, orig_iv);
			SKCIPHER_ENCRYPT(out, pt, split, iv, key, false);
			SKCIPHER_ENCRYPT(&out[split], &pt[split],
					 data_len - split, iv, key, true);
			KUNIT_ASSERT_MEMEQ_MSG(
				test, ct, out, data_len,
				"Wrong ciphertext with data_len=%zu split=%zu",
				data_len, split);
			if (check_iv)
				KUNIT_ASSERT_MEMEQ_MSG(
					test, next_iv_enc, iv, SKCIPHER_IV_LEN,
					"Wrong next IV after encryption with data_len=%zu split=%zu",
					data_len, split);

			skcipher_copy_iv(iv, orig_iv);
			SKCIPHER_DECRYPT(out, ct, split, iv, key, false);
			SKCIPHER_DECRYPT(&out[split], &ct[split],
					 data_len - split, iv, key, true);
			KUNIT_ASSERT_MEMEQ_MSG(
				test, pt, out, data_len,
				"Wrong plaintext with data_len=%zu split=%zu",
				data_len, split);
			if (check_iv)
				KUNIT_ASSERT_MEMEQ_MSG(
					test, next_iv_dec, iv, SKCIPHER_IV_LEN,
					"Wrong next IV after decryption with data_len=%zu split=%zu",
					data_len, split);
		}
	}
}

/*
 * For every valid data length up to a small maximum, try every possible way of
 * splitting the message into two parts, and verify that the result matches
 * one-shot en/decryption.  This deterministically covers the edge cases in the
 * handling of the end of the message, e.g. partial blocks and ciphertext
 * stealing, in combination with continuing a message.
 */
static void test_skcipher_incremental_all_splits(struct kunit *test)
{
	const size_t max_data_len = 96;
	const struct skcipher_test_keys *keys = skcipher_alloc_test_keys(test);
	const u8 *pt = alloc_rand_buf(test, max_data_len);
	u8 *ct = alloc_buf(test, max_data_len);
	u8 *out = alloc_buf(test, max_data_len);

	for (size_t i = 0; i < keys->num_keys; i++)
		skcipher_check_all_splits(test, &keys->keys[i], pt, ct, out,
					  max_data_len);
}
#endif /* SKCIPHER_INCREMENTAL */

#define SKCIPHER_POISON 0xa5
#define SKCIPHER_POISON_LEN 64

static void skcipher_check_buffer_overruns(struct kunit *test,
					   const struct SKCIPHER_KEY *key,
					   size_t data_len, const u8 *pt_orig,
					   u8 *src_end, u8 *dst_end, u8 *ct,
					   u8 *iv)
{
	/* Set up exact-size guarded buffers. */
	u8 *src = src_end - data_len;
	u8 *dst = dst_end - data_len;
	u8 orig_iv[SKCIPHER_IV_BUF_SIZE];

	rand_bytes(orig_iv, sizeof(orig_iv));

	for (int enc = 1; enc >= 0; enc--) {
		const u8 *expected_src = enc ? pt_orig : ct;

		memcpy(src, expected_src, data_len);
		memset(dst - SKCIPHER_POISON_LEN, SKCIPHER_POISON,
		       SKCIPHER_POISON_LEN + data_len);
		memset(iv - SKCIPHER_POISON_LEN, SKCIPHER_POISON,
		       SKCIPHER_POISON_LEN);
		skcipher_copy_iv(iv, orig_iv);

		skcipher_crypt(dst, src, data_len, iv, key, false, enc);

		KUNIT_ASSERT_MEMEQ_MSG(test, src, expected_src, data_len,
				       "Source modified; data_len=%zu enc=%d",
				       data_len, enc);
		KUNIT_ASSERT_NULL_MSG(
			test,
			memchr_inv(dst - SKCIPHER_POISON_LEN, SKCIPHER_POISON,
				   SKCIPHER_POISON_LEN),
			"Write before dst; data_len=%zu enc=%d", data_len, enc);
		KUNIT_ASSERT_NULL_MSG(
			test,
			memchr_inv(iv - SKCIPHER_POISON_LEN, SKCIPHER_POISON,
				   SKCIPHER_POISON_LEN),
			"Write before IV state; data_len=%zu enc=%d", data_len,
			enc);
		if (data_len == 0 && SKCIPHER_IV_LEN != 0)
			KUNIT_ASSERT_MEMEQ_MSG(
				test, iv, orig_iv, SKCIPHER_IV_LEN,
				"IV state modified with data_len=0; enc=%d",
				enc);
		if (enc)
			memcpy(ct, dst, data_len);
		else
			KUNIT_ASSERT_MEMEQ_MSG(
				test, dst, pt_orig, data_len,
				"Decryption didn't invert encryption; data_len=%zu",
				data_len);
	}
}

/*
 * Test using guarded buffers for the source, destination, and IV state.  This
 * detects out-of-bounds accesses past the end of the buffers, even in assembly
 * code.  Also check for writes before the beginning of the destination and IV
 * state buffers, check that the source buffer isn't modified, and check that
 * the IV state isn't modified when the data length is 0.
 *
 * Note: test_skcipher_all_key_lens() covers overrun of the raw key and key
 * struct.
 */
static void test_skcipher_buffer_overruns(struct kunit *test)
{
	const size_t max_data_len = 4096;
	const size_t buf_len = max_data_len + SKCIPHER_POISON_LEN;
	const size_t iv_buf_len = SKCIPHER_POISON_LEN + SKCIPHER_IV_LEN;
	const struct skcipher_test_keys *keys = skcipher_alloc_test_keys(test);
	const u8 *pt_orig = alloc_rand_buf(test, max_data_len);
	u8 *src_end = alloc_guarded_buf(test, max_data_len) + max_data_len;
	u8 *dst_end = alloc_guarded_buf(test, buf_len) + buf_len;
	u8 *ct = alloc_buf(test, max_data_len);
	/*
	 * The IV state is immediately followed by an unmapped page and is
	 * preceded by SKCIPHER_POISON_LEN bytes of poison.  If
	 * SKCIPHER_IV_LEN == 0, 'iv' points to the unmapped page itself.
	 */
	u8 *iv = alloc_guarded_buf(test, iv_buf_len) + iv_buf_len -
		 SKCIPHER_IV_LEN;

	/* Deterministically test all valid short lengths with every key. */
	for (size_t i = 0; i < keys->num_keys; i++) {
		for (size_t data_len = SKCIPHER_MIN_DATA_LEN; data_len <= 256;
		     data_len += SKCIPHER_DATA_LEN_ALIGN)
			skcipher_check_buffer_overruns(test, &keys->keys[i],
						       data_len, pt_orig,
						       src_end, dst_end, ct,
						       iv);
	}

	/* Also test random lengths up to max_data_len. */
	for (int i = 0; i < 200; i++)
		skcipher_check_buffer_overruns(
			test, skcipher_pick_key(keys, i),
			skcipher_rand_data_len(max_data_len), pt_orig, src_end,
			dst_end, ct, iv);
}

/*
 * Test that encryption and decryption produce the same results regardless of
 * how the buffers and key structs are aligned in memory.
 */
static void test_skcipher_alignment_consistency(struct kunit *test)
{
	const size_t max_data_len = 4096;
	const size_t max_offset = 128;
	const size_t key_align = __alignof__(struct SKCIPHER_KEY);
	const size_t key_buf_len =
		sizeof(struct SKCIPHER_KEY) + max_offset + key_align - 1;
	u8 *key1_buf = alloc_buf(test, key_buf_len);
	u8 *key2_buf = alloc_buf(test, key_buf_len);
	u8 *raw_key1_buf = alloc_buf(test, SKCIPHER_MAX_KEY_LEN + max_offset);
	u8 *raw_key2_buf = alloc_buf(test, SKCIPHER_MAX_KEY_LEN + max_offset);
	u8 *iv1_buf = alloc_buf(test, SKCIPHER_IV_BUF_SIZE + max_offset);
	u8 *iv2_buf = alloc_buf(test, SKCIPHER_IV_BUF_SIZE + max_offset);
	u8 *pt1_buf = alloc_buf(test, max_data_len);
	u8 *pt2_buf = alloc_buf(test, max_data_len);
	u8 *ct1_buf = alloc_buf(test, max_data_len);
	u8 *ct2_buf = alloc_buf(test, max_data_len);
	u8 *pt_orig = alloc_buf(test, max_data_len);
	u8 orig_iv[SKCIPHER_IV_BUF_SIZE];
	int err;

	for (int i = 0; i < 100; i++) {
		/* Generate lengths. */
		const size_t data_len = skcipher_rand_data_len(max_data_len);
		const size_t key_len = skcipher_rand_key_len();
		const bool check_iv = skcipher_is_next_iv_defined(data_len);

		/* Generate two sets of alignments. */
		struct SKCIPHER_KEY *key1 = (void *)PTR_ALIGN(
			key1_buf + rand_offset(max_offset), key_align);
		struct SKCIPHER_KEY *key2 = (void *)PTR_ALIGN(
			key2_buf + rand_offset(max_offset), key_align);
		u8 *raw_key1 = raw_key1_buf + rand_offset(max_offset);
		u8 *raw_key2 = raw_key2_buf + rand_offset(max_offset);
		u8 *iv1 = iv1_buf + rand_offset(max_offset);
		u8 *iv2 = iv2_buf + rand_offset(max_offset);
		u8 *pt1 = pt1_buf + rand_offset(max_data_len - data_len);
		u8 *pt2 = pt2_buf + rand_offset(max_data_len - data_len);
		u8 *ct1 = ct1_buf + rand_offset(max_data_len - data_len);
		u8 *ct2 = ct2_buf + rand_offset(max_data_len - data_len);

		/* Generate inputs and copy them to both sets of buffers. */
		rand_bytes(raw_key1, key_len);
		rand_bytes(orig_iv, sizeof(orig_iv));
		rand_bytes(pt1, data_len);
		memcpy(raw_key2, raw_key1, key_len);
		memcpy(pt2, pt1, data_len);

		/* Verify encryption consistency. */

		err = SKCIPHER_PREPAREKEY(key1, raw_key1, key_len);
		KUNIT_ASSERT_EQ(test, 0, err);
		skcipher_copy_iv(iv1, orig_iv);
		SKCIPHER_ENCRYPT(ct1, pt1, data_len, iv1, key1, false);

		err = SKCIPHER_PREPAREKEY(key2, raw_key2, key_len);
		KUNIT_ASSERT_EQ(test, 0, err);
		skcipher_copy_iv(iv2, orig_iv);
		SKCIPHER_ENCRYPT(ct2, pt2, data_len, iv2, key2, false);

		KUNIT_ASSERT_MEMEQ(test, ct1, ct2, data_len);
		if (check_iv)
			KUNIT_ASSERT_MEMEQ(test, iv1, iv2, SKCIPHER_IV_LEN);

		/* Verify decryption consistency. */

		/*
		 * Decryption overwrites pt1 and pt2, so save the original
		 * plaintext for the round-trip check, and clear pt1 and pt2 so
		 * that a decryption that doesn't write to dst gets detected.
		 */
		memcpy(pt_orig, pt1, data_len);
		memset(pt1, 0, data_len);
		memset(pt2, 0, data_len);

		skcipher_copy_iv(iv1, orig_iv);
		SKCIPHER_DECRYPT(pt1, ct1, data_len, iv1, key1, false);

		skcipher_copy_iv(iv2, orig_iv);
		SKCIPHER_DECRYPT(pt2, ct2, data_len, iv2, key2, false);

		KUNIT_ASSERT_MEMEQ_MSG(
			test, pt_orig, pt1, data_len,
			"Decryption didn't invert encryption; data_len=%zu",
			data_len);
		KUNIT_ASSERT_MEMEQ(test, pt1, pt2, data_len);
		if (check_iv)
			KUNIT_ASSERT_MEMEQ(test, iv1, iv2, SKCIPHER_IV_LEN);
	}
}

static void skcipher_check_inplace(struct kunit *test,
				   const struct SKCIPHER_KEY *key,
				   size_t data_len, u8 *buf1, u8 *buf2,
				   size_t max_offset)
{
	const bool check_iv = skcipher_is_next_iv_defined(data_len);
	const size_t offset = rand_offset(max_offset);
	u8 *data = buf1 + offset;
	u8 orig_iv[SKCIPHER_IV_BUF_SIZE];
	u8 iv[SKCIPHER_IV_BUF_SIZE];
	u8 iv2[SKCIPHER_IV_BUF_SIZE];

	rand_bytes(orig_iv, sizeof(orig_iv));

	for (int enc = 1; enc >= 0; enc--) {
		/* En/decrypt out-of-place. */
		skcipher_copy_iv(iv, orig_iv);
		skcipher_crypt(buf2, data, data_len, iv, key, false, enc);

		/* En/decrypt in-place. */
		skcipher_copy_iv(iv2, orig_iv);
		skcipher_crypt(data, data, data_len, iv2, key, false, enc);

		/* Compare the results. */
		KUNIT_ASSERT_MEMEQ_MSG(
			test, buf2, data, data_len,
			"In-place and out-of-place results differ; data_len=%zu offset=%zu enc=%d",
			data_len, offset, enc);
		if (check_iv)
			KUNIT_ASSERT_MEMEQ(test, iv, iv2, SKCIPHER_IV_LEN);
	}
}

/* Test that in-place en/decryption gives the same results as out-of-place. */
static void test_skcipher_inplace(struct kunit *test)
{
	const size_t max_data_len = 4096;
	const size_t max_offset = 128;
	const struct skcipher_test_keys *keys = skcipher_alloc_test_keys(test);
	u8 *buf1 = alloc_rand_buf(test, max_data_len + max_offset);
	u8 *buf2 = alloc_buf(test, max_data_len);

	/* Deterministically test all valid short lengths with every key. */
	for (size_t i = 0; i < keys->num_keys; i++) {
		for (size_t data_len = SKCIPHER_MIN_DATA_LEN; data_len <= 256;
		     data_len += SKCIPHER_DATA_LEN_ALIGN)
			skcipher_check_inplace(test, &keys->keys[i], data_len,
					       buf1, buf2, max_offset);
	}

	/* Also test random lengths up to max_data_len. */
	for (int i = 0; i < 100; i++)
		skcipher_check_inplace(test, skcipher_pick_key(keys, i),
				       skcipher_rand_data_len(max_data_len),
				       buf1, buf2, max_offset);
}

#ifdef SKCIPHER_ENCKEY
/*
 * Verify that the given expected-invalid key_len is rejected by
 * SKCIPHER_PREPAREENCKEY().
 */
static void skcipher_verify_invalid_enckey_len(struct kunit *test,
					       struct SKCIPHER_ENCKEY *enckey,
					       const u8 *unmapped_ptr,
					       size_t key_len)
{
	int err;

	memset(enckey, 0, sizeof(*enckey));
	err = SKCIPHER_PREPAREENCKEY(enckey, unmapped_ptr, key_len);
	KUNIT_ASSERT_EQ_MSG(test, -EINVAL, err,
			    "key_len=%zu wasn't rejected with -EINVAL",
			    key_len);
	KUNIT_ASSERT_TRUE_MSG(
		test, mem_is_zero(enckey, sizeof(*enckey)),
		"Key struct wasn't left zeroed on invalid key_len=%zu",
		key_len);
}

/*
 * Test that encryption using a key prepared for encryption only
 * (SKCIPHER_ENCKEY) gives the same results as encryption using SKCIPHER_KEY.
 * Also test that SKCIPHER_PREPAREENCKEY verifies the key length properly.
 */
static void test_skcipher_enckey(struct kunit *test)
{
	const size_t max_data_len = 4096;
	struct SKCIPHER_KEY *key = alloc_buf(test, sizeof(*key));
	struct SKCIPHER_ENCKEY *enckey =
		alloc_guarded_buf(test, sizeof(*enckey));
	const u8 *pt = alloc_rand_buf(test, max_data_len);
	u8 *ct = alloc_buf(test, max_data_len);
	u8 *ct2 = alloc_buf(test, max_data_len);
	u8 *raw_key_buf_end = alloc_guarded_buf(test, SKCIPHER_MAX_KEY_LEN) +
			      SKCIPHER_MAX_KEY_LEN;
	u8 orig_iv[SKCIPHER_IV_BUF_SIZE];
	u8 iv[SKCIPHER_IV_BUF_SIZE];
	u8 iv2[SKCIPHER_IV_BUF_SIZE];
	int err;

	for (size_t key_len = 0; key_len <= SKCIPHER_MAX_KEY_LEN; key_len++) {
		if (!skcipher_is_key_len_expected_valid(key_len))
			skcipher_verify_invalid_enckey_len(
				test, enckey, raw_key_buf_end, key_len);
	}
	skcipher_verify_invalid_enckey_len(test, enckey, raw_key_buf_end,
					   SKCIPHER_MAX_KEY_LEN + 1);
	skcipher_verify_invalid_enckey_len(test, enckey, raw_key_buf_end,
					   SKCIPHER_MAX_KEY_LEN * 2);
	skcipher_verify_invalid_enckey_len(test, enckey, raw_key_buf_end,
					   U32_MAX);
	skcipher_verify_invalid_enckey_len(test, enckey, raw_key_buf_end,
					   SIZE_MAX);
#ifdef CONFIG_64BIT
	/* Check for 64-to-32-bit truncation of key_len. */
	for (size_t i = 0; i < ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS); i++)
		skcipher_verify_invalid_enckey_len(
			test, enckey, raw_key_buf_end,
			((size_t)U32_MAX + 1) + SKCIPHER_VALID_KEY_LENS[i]);
#endif

	for (int i = 0; i < 100; i++) {
		const size_t data_len = skcipher_rand_data_len(max_data_len);
		const size_t key_len = skcipher_rand_key_len();
		u8 *raw_key = raw_key_buf_end - key_len;

		rand_bytes(raw_key, key_len);
		rand_bytes(orig_iv, sizeof(orig_iv));
		err = SKCIPHER_PREPAREKEY(key, raw_key, key_len);
		KUNIT_ASSERT_EQ(test, 0, err);
		err = SKCIPHER_PREPAREENCKEY(enckey, raw_key, key_len);
		KUNIT_ASSERT_EQ(test, 0, err);

		skcipher_copy_iv(iv, orig_iv);
		SKCIPHER_ENCRYPT(ct, pt, data_len, iv, key, false);
		skcipher_copy_iv(iv2, orig_iv);
		SKCIPHER_ENCRYPT(ct2, pt, data_len, iv2, enckey, false);
		KUNIT_ASSERT_MEMEQ_MSG(
			test, ct, ct2, data_len,
			"Encryption with enckey differs; data_len=%zu key_len=%zu",
			data_len, key_len);
		if (skcipher_is_next_iv_defined(data_len))
			KUNIT_ASSERT_MEMEQ(test, iv, iv2, SKCIPHER_IV_LEN);
	}
}
#endif /* SKCIPHER_ENCKEY */

/*
 * The data length used by the interrupt context test.  When the algorithm
 * allows it, this isn't a multiple of the block size, so that the fallback code
 * for handling partial blocks (or ciphertext stealing) gets tested too.
 */
#define IRQ_TEST_DATA_LEN round_down(263, SKCIPHER_DATA_LEN_ALIGN)
static_assert(IRQ_TEST_DATA_LEN >= SKCIPHER_MIN_DATA_LEN);
static_assert(IRQ_TEST_DATA_LEN > 0);
#define IRQ_TEST_NUM_BUFFERS 3 /* matches max concurrency level */

struct skcipher_irq_test_slot {
	/* Fields written only at test case initialization time */
	u8 raw_key[SKCIPHER_MAX_KEY_LEN];
	size_t key_len;
	u8 iv[SKCIPHER_IV_BUF_SIZE];
	u8 next_iv_enc[SKCIPHER_IV_BUF_SIZE];
	u8 next_iv_dec[SKCIPHER_IV_BUF_SIZE];
	u8 pt[IRQ_TEST_DATA_LEN];
	u8 ct[IRQ_TEST_DATA_LEN];

	/* Fields written throughout the test case */
	struct SKCIPHER_KEY key;
	u8 scratch_iv[SKCIPHER_IV_BUF_SIZE];
	u8 scratch_buf[IRQ_TEST_DATA_LEN];
	int phase;
	atomic_t in_use;
};

struct skcipher_irq_test_state {
	struct skcipher_irq_test_slot slots[IRQ_TEST_NUM_BUFFERS];
};

static bool skcipher_irq_test_func(void *state_)
{
	struct skcipher_irq_test_state *state = state_;
	struct skcipher_irq_test_slot *slot;
	bool ok = true;

	/*
	 * Find a free slot.  This should always succeed, since the number of
	 * slots is equal to the max concurrency level of kunit_run_irq_test().
	 */
	for (slot = &state->slots[0];
	     slot < &state->slots[ARRAY_SIZE(state->slots)]; slot++) {
		if (atomic_cmpxchg(&slot->in_use, 0, 1) == 0)
			break;
	}
	if (WARN_ON_ONCE(slot == &state->slots[ARRAY_SIZE(state->slots)]))
		return false;
	/*
	 * This execution context now has exclusive access to 'slot'.
	 * Next, execute the next operation that the slot is set to perform.
	 */

	if (slot->phase == 0) {
		/* Phase 0: Prepare slot's key in current context. */
		ok = SKCIPHER_PREPAREKEY(&slot->key, slot->raw_key,
					 slot->key_len) == 0;
	} else if (slot->phase == 1) {
		/*
		 * Phase 1: Encrypt plaintext using key that may have been
		 * prepared in a different context.
		 */
		skcipher_copy_iv(slot->scratch_iv, slot->iv);
		SKCIPHER_ENCRYPT(slot->scratch_buf, slot->pt, IRQ_TEST_DATA_LEN,
				 slot->scratch_iv, &slot->key, false);
		ok = memcmp(slot->scratch_buf, slot->ct, IRQ_TEST_DATA_LEN) ==
		     0;
		if (skcipher_is_next_iv_defined(IRQ_TEST_DATA_LEN))
			ok = ok && memcmp(slot->scratch_iv, slot->next_iv_enc,
					  SKCIPHER_IV_LEN) == 0;
	} else {
		/*
		 * Phase 2: Decrypt ciphertext using key that may have been
		 * prepared in a different context.
		 */
		skcipher_copy_iv(slot->scratch_iv, slot->iv);
		SKCIPHER_DECRYPT(slot->scratch_buf, slot->ct, IRQ_TEST_DATA_LEN,
				 slot->scratch_iv, &slot->key, false);
		ok = memcmp(slot->scratch_buf, slot->pt, IRQ_TEST_DATA_LEN) ==
		     0;
		if (skcipher_is_next_iv_defined(IRQ_TEST_DATA_LEN))
			ok = ok && memcmp(slot->scratch_iv, slot->next_iv_dec,
					  SKCIPHER_IV_LEN) == 0;
	}
	slot->phase = (slot->phase + 1) % 3;
	atomic_set_release(&slot->in_use, 0);
	return ok;
}

/*
 * Test that encryption and decryption produce the correct results in task,
 * softirq, and hardirq contexts running concurrently -- including with keys
 * prepared in other contexts.  This is needed to cover fallback code paths that
 * execute in contexts where FPU or vector registers cannot be used.
 */
static void test_skcipher_interrupt_context(struct kunit *test)
{
	struct skcipher_irq_test_state *state = alloc_buf(test, sizeof(*state));
	size_t allowed_key_lens[ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS)];
	size_t num_allowed_key_lens = 0;

	memset(state, 0, sizeof(*state));

	for (size_t i = 0; i < ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS); i++) {
		size_t key_len = SKCIPHER_VALID_KEY_LENS[i];

		if (SKCIPHER_IS_KEY_LEN_ALLOWED(key_len))
			allowed_key_lens[num_allowed_key_lens++] = key_len;
	}
	KUNIT_ASSERT_GT(test, num_allowed_key_lens, 0);

	/*
	 * For each slot, generate a key, an IV state, and a plaintext.  Then
	 * generate the corresponding ciphertext and expected final IV states.
	 */
	for (int i = 0; i < IRQ_TEST_NUM_BUFFERS; i++) {
		struct skcipher_irq_test_slot *slot = &state->slots[i];
		int err;

		slot->key_len = allowed_key_lens[i % num_allowed_key_lens];
		rand_bytes(slot->raw_key, slot->key_len);
		rand_bytes(slot->iv, sizeof(slot->iv));
		rand_bytes(slot->pt, sizeof(slot->pt));
		err = SKCIPHER_PREPAREKEY(&slot->key, slot->raw_key,
					  slot->key_len);
		KUNIT_ASSERT_EQ(test, 0, err);
		skcipher_copy_iv(slot->next_iv_enc, slot->iv);
		SKCIPHER_ENCRYPT(slot->ct, slot->pt, IRQ_TEST_DATA_LEN,
				 slot->next_iv_enc, &slot->key, false);
		skcipher_copy_iv(slot->next_iv_dec, slot->iv);
		SKCIPHER_DECRYPT(slot->scratch_buf, slot->ct, IRQ_TEST_DATA_LEN,
				 slot->next_iv_dec, &slot->key, false);
		KUNIT_ASSERT_MEMEQ(test, slot->pt, slot->scratch_buf,
				   IRQ_TEST_DATA_LEN);
	}

	kunit_run_irq_test(test, skcipher_irq_test_func, 100000, state);
}

/* Benchmark encryption and decryption on various data lengths. */
static void benchmark_skcipher(struct kunit *test)
{
	static const size_t data_lens_to_test[] = {
		16, 64, 128, 256, 512, 1024, 1420, 4096, 16384,
	};
	const bool enc_is_dec = (void *)SKCIPHER_ENCRYPT ==
				(void *)SKCIPHER_DECRYPT;
	const size_t max_data_len = 16384;
	size_t key_len = 0;
	u8 iv[SKCIPHER_IV_BUF_SIZE] = {};
	const u8 *raw_key;
	struct SKCIPHER_KEY *key;
	u8 *data;
	int err;

	if (!IS_ENABLED(CONFIG_CRYPTO_LIB_BENCHMARK))
		kunit_skip(test, "not enabled");

	for (size_t i = 0; i < ARRAY_SIZE(SKCIPHER_VALID_KEY_LENS); i++) {
		if (SKCIPHER_IS_KEY_LEN_ALLOWED(SKCIPHER_VALID_KEY_LENS[i]))
			key_len = max(key_len, SKCIPHER_VALID_KEY_LENS[i]);
	}
	KUNIT_ASSERT_GT(test, key_len, 0);

	raw_key = alloc_rand_buf(test, key_len);
	data = alloc_rand_buf(test, max_data_len);
	key = alloc_buf(test, sizeof(*key));
	err = SKCIPHER_PREPAREKEY(key, raw_key, key_len);
	KUNIT_ASSERT_EQ(test, 0, err);

	/* Warm-up */
	for (size_t i = 0; i < 10000000; i += max_data_len) {
		SKCIPHER_ENCRYPT(data, data, max_data_len, iv, key, false);
		if (!enc_is_dec)
			SKCIPHER_DECRYPT(data, data, max_data_len, iv, key,
					 false);
	}

	for (size_t i = 0; i < ARRAY_SIZE(data_lens_to_test); i++) {
		size_t data_len = round_down(data_lens_to_test[i],
					     SKCIPHER_DATA_LEN_ALIGN);
		size_t num_iters = 10000000 / (data_len + 128);
		u64 t_enc, t_dec = 0;

		if (data_len < SKCIPHER_MIN_DATA_LEN)
			continue;

		KUNIT_ASSERT_LE(test, data_len, max_data_len);
		KUNIT_ASSERT_TRUE(test, skcipher_is_data_len_valid(data_len));

		preempt_disable();

		t_enc = ktime_get_ns();
		for (size_t j = 0; j < num_iters; j++)
			SKCIPHER_ENCRYPT(data, data, data_len, iv, key, false);
		t_enc = ktime_get_ns() - t_enc;

		if (!enc_is_dec) {
			t_dec = ktime_get_ns();
			for (size_t j = 0; j < num_iters; j++)
				SKCIPHER_DECRYPT(data, data, data_len, iv, key,
						 false);
			t_dec = ktime_get_ns() - t_dec;
		}

		preempt_enable();

		if (enc_is_dec)
			kunit_info(test, "data_len=%zu: %llu MB/s", data_len,
				   div64_u64((u64)data_len * num_iters * 1000,
					     t_enc ?: 1));
		else
			kunit_info(test,
				   "data_len=%zu: enc %llu MB/s, dec %llu MB/s",
				   data_len,
				   div64_u64((u64)data_len * num_iters * 1000,
					     t_enc ?: 1),
				   div64_u64((u64)data_len * num_iters * 1000,
					     t_dec ?: 1));
	}
}

/* clang-format off */
#ifdef SKCIPHER_INCREMENTAL
#define SKCIPHER_INCREMENTAL_KUNIT_CASES			\
	KUNIT_CASE(test_skcipher_incremental),			\
	KUNIT_CASE(test_skcipher_incremental_all_splits),
#else
#define SKCIPHER_INCREMENTAL_KUNIT_CASES
#endif

#ifdef SKCIPHER_ENCKEY
#define SKCIPHER_ENCKEY_KUNIT_CASES KUNIT_CASE(test_skcipher_enckey),
#else
#define SKCIPHER_ENCKEY_KUNIT_CASES
#endif

#define SKCIPHER_KUNIT_CASES					\
	KUNIT_CASE(test_skcipher_all_key_lens),			\
	KUNIT_CASE(test_skcipher_monte_carlo),			\
	SKCIPHER_INCREMENTAL_KUNIT_CASES			\
	KUNIT_CASE(test_skcipher_buffer_overruns),		\
	KUNIT_CASE(test_skcipher_alignment_consistency),	\
	KUNIT_CASE(test_skcipher_inplace),			\
	SKCIPHER_ENCKEY_KUNIT_CASES				\
	KUNIT_CASE(test_skcipher_interrupt_context),		\
	KUNIT_CASE(benchmark_skcipher)
/* clang-format on */
