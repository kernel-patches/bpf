// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"

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

int sha256_status = -1;
int sha384_status = -1;
int sha512_status = -1;

/* Declare the crypto kfuncs */
extern struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params,
						     u32 params__sz, int *err) __ksym;
extern void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;
extern int bpf_crypto_hash(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *data,
			   const struct bpf_dynptr *out) __ksym;

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

char __license[] SEC("license") = "GPL";
