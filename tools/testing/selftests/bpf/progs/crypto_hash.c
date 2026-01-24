// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"
#include "crypto_common.h"

unsigned char test_input[3] = "abc";

/* Expected SHA-256 hash of "abc" */
/* ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad */
unsigned char expected_sha256[32] = {
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
	0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
	0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

/* Output buffers for test results */
unsigned char sha256_output[32] = {};
unsigned char sha384_output[48] = {};
unsigned char sha512_output[64] = {};
unsigned char small_output[16] = {}; /* Intentionally small for output_too_small test */

int sha256_status = -1;
int sha384_status = -1;
int sha512_status = -1;
int hash_with_key_status = -1;
int hash_output_too_small_status = -1;
int hash_on_skcipher_status = -1;

SEC("syscall")
int test_sha256(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;
	struct bpf_crypto_ctx *hash_ctx;
	struct bpf_crypto_params params = {
		.type = "hash",
		.algo = "sha256",
		.key_len = 0,
	};
	int err = 0;

	hash_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!hash_ctx) {
		sha256_status = err;
		return 0;
	}

	bpf_dynptr_from_mem(test_input, sizeof(test_input), 0, &input_ptr);
	bpf_dynptr_from_mem(sha256_output, sizeof(sha256_output), 0, &output_ptr);

	sha256_status = bpf_crypto_hash(hash_ctx, &input_ptr, &output_ptr);
	bpf_crypto_ctx_release(hash_ctx);
	return 0;
}

SEC("syscall")
int test_sha384(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;
	struct bpf_crypto_ctx *hash_ctx;
	struct bpf_crypto_params params = {
		.type = "hash",
		.algo = "sha384",
		.key_len = 0,
	};
	int err = 0;

	hash_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!hash_ctx) {
		sha384_status = err;
		return 0;
	}

	bpf_dynptr_from_mem(test_input, sizeof(test_input), 0, &input_ptr);
	bpf_dynptr_from_mem(sha384_output, sizeof(sha384_output), 0, &output_ptr);

	sha384_status = bpf_crypto_hash(hash_ctx, &input_ptr, &output_ptr);
	bpf_crypto_ctx_release(hash_ctx);
	return 0;
}

SEC("syscall")
int test_sha512(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;
	struct bpf_crypto_ctx *hash_ctx;
	struct bpf_crypto_params params = {
		.type = "hash",
		.algo = "sha512",
		.key_len = 0,
	};
	int err = 0;

	hash_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!hash_ctx) {
		sha512_status = err;
		return 0;
	}

	bpf_dynptr_from_mem(test_input, sizeof(test_input), 0, &input_ptr);
	bpf_dynptr_from_mem(sha512_output, sizeof(sha512_output), 0, &output_ptr);

	sha512_status = bpf_crypto_hash(hash_ctx, &input_ptr, &output_ptr);
	bpf_crypto_ctx_release(hash_ctx);
	return 0;
}

SEC("syscall")
int test_sha256_zero_len(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;
	struct bpf_crypto_ctx *hash_ctx;
	struct bpf_crypto_params params = {
		.type = "hash",
		.algo = "sha256",
		.key_len = 0,
	};
	int err = 0;
	int ret;

	hash_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!hash_ctx) {
		sha256_status = err;
		return 0;
	}

	bpf_dynptr_from_mem(test_input, 0, 0, &input_ptr);
	bpf_dynptr_from_mem(sha256_output, sizeof(sha256_output), 0, &output_ptr);

	ret = bpf_crypto_hash(hash_ctx, &input_ptr, &output_ptr);
	sha256_status = (ret == -22) ? 0 : ret;
	bpf_crypto_ctx_release(hash_ctx);
	return 0;
}

SEC("syscall")
int test_hash_with_key_rejected(void *ctx)
{
	struct bpf_crypto_ctx *hash_ctx;
	struct bpf_crypto_params params = {
		.type = "hash",
		.algo = "sha256",
		.key_len = 16, /* Hash algorithms don't support keys */
	};
	int err = 0;

	/* Set some dummy key data */
	params.key[0] = 0x01;
	params.key[1] = 0x02;

	hash_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!hash_ctx) {
		/* Expected: should fail with -EINVAL (-22) */
		hash_with_key_status = (err == -22) ? 0 : err;
		return 0;
	}

	/* Should not reach here - context creation should have failed */
	hash_with_key_status = -1;
	bpf_crypto_ctx_release(hash_ctx);
	return 0;
}

SEC("syscall")
int test_hash_output_too_small(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;
	struct bpf_crypto_ctx *hash_ctx;
	struct bpf_crypto_params params = {
		.type = "hash",
		.algo = "sha256",
		.key_len = 0,
	};
	int err = 0;
	int ret;

	hash_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!hash_ctx) {
		hash_output_too_small_status = err;
		return 0;
	}

	bpf_dynptr_from_mem(test_input, sizeof(test_input), 0, &input_ptr);
	bpf_dynptr_from_mem(small_output, sizeof(small_output), 0, &output_ptr);

	ret = bpf_crypto_hash(hash_ctx, &input_ptr, &output_ptr);
	/* Expected: should fail with -EINVAL (-22) */
	hash_output_too_small_status = (ret == -22) ? 0 : ret;
	bpf_crypto_ctx_release(hash_ctx);
	return 0;
}

SEC("syscall")
int test_hash_on_skcipher_ctx(void *ctx)
{
	struct bpf_dynptr input_ptr, output_ptr;
	struct bpf_crypto_ctx *cipher_ctx;
	struct bpf_crypto_params params = {
		.type = "skcipher",
		.algo = "ecb(aes)",
		.key_len = 16,
	};
	int err = 0;
	int ret;

	params.key[0] = 0x00; params.key[1] = 0x01; params.key[2] = 0x02; params.key[3] = 0x03;
	params.key[4] = 0x04; params.key[5] = 0x05; params.key[6] = 0x06; params.key[7] = 0x07;
	params.key[8] = 0x08; params.key[9] = 0x09; params.key[10] = 0x0a; params.key[11] = 0x0b;
	params.key[12] = 0x0c; params.key[13] = 0x0d; params.key[14] = 0x0e; params.key[15] = 0x0f;

	cipher_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!cipher_ctx) {
		hash_on_skcipher_status = err;
		return 0;
	}

	bpf_dynptr_from_mem(test_input, sizeof(test_input), 0, &input_ptr);
	bpf_dynptr_from_mem(sha256_output, sizeof(sha256_output), 0, &output_ptr);

	ret = bpf_crypto_hash(cipher_ctx, &input_ptr, &output_ptr);
	/* Expected: should fail with -EINVAL (-22) due to type_id mismatch */
	hash_on_skcipher_status = (ret == -22) ? 0 : ret;
	bpf_crypto_ctx_release(cipher_ctx);
	return 0;
}

char __license[] SEC("license") = "GPL";
