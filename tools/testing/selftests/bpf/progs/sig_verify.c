// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "crypto_common.h"

/* NIST P-256 test vector
 * This is a known valid ECDSA signature for testing purposes
 */

/* Public key in uncompressed format: 0x04 || x || y (65 bytes) */
unsigned char pubkey_p256[65] = {
	0x04, /* Uncompressed point indicator */
	/* X coordinate (32 bytes) */
	0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31,
	0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
	0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c,
	0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
	/* Y coordinate (32 bytes) */
	0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99,
	0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
	0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51,
	0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99
};

/* Message hash (32 bytes) - SHA-256 of "sample" */
unsigned char message_hash[32] = {
	0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1,
	0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4, 0x1f, 0xc7,
	0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15,
	0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf
};

/* Valid signature r || s (64 bytes) */
unsigned char valid_signature[64] = {
	/* r component (32 bytes) */
	0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd,
	0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
	0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91,
	0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
	/* s component (32 bytes) */
	0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41,
	0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
	0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06,
	0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8
};

/* Invalid signature (modified r component) for negative test */
unsigned char invalid_signature[64] = {
	/* r component (32 bytes) - first byte modified */
	0xff, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd,
	0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
	0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91,
	0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
	/* s component (32 bytes) */
	0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41,
	0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
	0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06,
	0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8
};

/* Test results */
int verify_result = -1;
int verify_invalid_result = -1;
int ctx_create_status = -1;
int keysize_result = -1;
int digestsize_result = -1;
int maxsize_result = -1;
int ecdsa_on_hash_ctx_status = -1;
int ecdsa_keysize_on_hash_status = -1;
int ecdsa_zero_msg_status = -1;
int ecdsa_zero_sig_status = -1;

SEC("syscall")
int test_ecdsa_verify_valid(void *ctx)
{
	struct bpf_crypto_ctx *ecdsa_ctx;
	struct bpf_crypto_params params = {
		.type = "sig",
		.algo = "p1363(ecdsa-nist-p256)",
		.key_len = sizeof(pubkey_p256),
	};
	struct bpf_dynptr msg_ptr, sig_ptr;
	int err = 0;

	__builtin_memcpy(params.key, pubkey_p256, sizeof(pubkey_p256));

	ecdsa_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!ecdsa_ctx) {
		ctx_create_status = err;
		return 0;
	}
	ctx_create_status = 0;

	bpf_dynptr_from_mem(message_hash, sizeof(message_hash), 0, &msg_ptr);
	bpf_dynptr_from_mem(valid_signature, sizeof(valid_signature), 0, &sig_ptr);

	verify_result = bpf_sig_verify(ecdsa_ctx, &msg_ptr, &sig_ptr);

	bpf_crypto_ctx_release(ecdsa_ctx);

	return 0;
}

SEC("syscall")
int test_ecdsa_verify_invalid(void *ctx)
{
	struct bpf_crypto_ctx *ecdsa_ctx;
	struct bpf_crypto_params params = {
		.type = "sig",
		.algo = "p1363(ecdsa-nist-p256)",
		.key_len = sizeof(pubkey_p256),
	};
	struct bpf_dynptr msg_ptr, sig_ptr;
	int err = 0;

	__builtin_memcpy(params.key, pubkey_p256, sizeof(pubkey_p256));

	ecdsa_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!ecdsa_ctx)
		return 0;

	bpf_dynptr_from_mem(message_hash, sizeof(message_hash), 0, &msg_ptr);
	bpf_dynptr_from_mem(invalid_signature, sizeof(invalid_signature), 0, &sig_ptr);

	verify_invalid_result = bpf_sig_verify(ecdsa_ctx, &msg_ptr, &sig_ptr);

	bpf_crypto_ctx_release(ecdsa_ctx);

	return 0;
}

SEC("syscall")
int test_ecdsa_size_queries(void *ctx)
{
	struct bpf_crypto_ctx *ecdsa_ctx;
	struct bpf_crypto_params params = {
		.type = "sig",
		.algo = "p1363(ecdsa-nist-p256)",
		.key_len = sizeof(pubkey_p256),
	};
	int err = 0;

	__builtin_memcpy(params.key, pubkey_p256, sizeof(pubkey_p256));

	ecdsa_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!ecdsa_ctx) {
		ctx_create_status = err;
		return 0;
	}
	ctx_create_status = 0;

	keysize_result = bpf_sig_keysize(ecdsa_ctx);
	digestsize_result = bpf_sig_digestsize(ecdsa_ctx);
	maxsize_result = bpf_sig_maxsize(ecdsa_ctx);

	bpf_crypto_ctx_release(ecdsa_ctx);

	return 0;
}

/* Test that calling bpf_sig_verify on hash context fails with type mismatch */
SEC("syscall")
int test_ecdsa_on_hash_ctx(void *ctx)
{
	struct bpf_crypto_ctx *hash_ctx;
	struct bpf_crypto_params params = {
		.type = "hash",
		.algo = "sha256",
		.key_len = 0,
	};
	struct bpf_dynptr msg_ptr, sig_ptr;
	int err = 0;
	int ret;

	hash_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!hash_ctx) {
		ecdsa_on_hash_ctx_status = err;
		return 0;
	}

	bpf_dynptr_from_mem(message_hash, sizeof(message_hash), 0, &msg_ptr);
	bpf_dynptr_from_mem(valid_signature, sizeof(valid_signature), 0, &sig_ptr);

	ret = bpf_sig_verify(hash_ctx, &msg_ptr, &sig_ptr);
	/* Expected: should fail with -EINVAL (-22) due to type_id mismatch */
	ecdsa_on_hash_ctx_status = (ret == -22) ? 0 : ret;
	bpf_crypto_ctx_release(hash_ctx);
	return 0;
}

/* Test that calling bpf_sig_keysize on hash context fails with type mismatch */
SEC("syscall")
int test_ecdsa_keysize_on_hash_ctx(void *ctx)
{
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
		ecdsa_keysize_on_hash_status = err;
		return 0;
	}

	ret = bpf_sig_keysize(hash_ctx);
	/* Expected: should fail with -EINVAL (-22) due to type_id mismatch */
	ecdsa_keysize_on_hash_status = (ret == -22) ? 0 : ret;
	bpf_crypto_ctx_release(hash_ctx);
	return 0;
}

/* Test that bpf_sig_verify with zero-length message fails */
SEC("syscall")
int test_ecdsa_zero_len_msg(void *ctx)
{
	struct bpf_crypto_ctx *ecdsa_ctx;
	struct bpf_crypto_params params = {
		.type = "sig",
		.algo = "p1363(ecdsa-nist-p256)",
		.key_len = sizeof(pubkey_p256),
	};
	struct bpf_dynptr msg_ptr, sig_ptr;
	int err = 0;
	int ret;

	__builtin_memcpy(params.key, pubkey_p256, sizeof(pubkey_p256));

	ecdsa_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!ecdsa_ctx) {
		ecdsa_zero_msg_status = err;
		return 0;
	}

	/* Zero-length message */
	bpf_dynptr_from_mem(message_hash, 0, 0, &msg_ptr);
	bpf_dynptr_from_mem(valid_signature, sizeof(valid_signature), 0, &sig_ptr);

	ret = bpf_sig_verify(ecdsa_ctx, &msg_ptr, &sig_ptr);
	/* Expected: should fail with -EINVAL (-22) */
	ecdsa_zero_msg_status = (ret == -22) ? 0 : ret;
	bpf_crypto_ctx_release(ecdsa_ctx);
	return 0;
}

/* Test that bpf_sig_verify with zero-length signature fails */
SEC("syscall")
int test_ecdsa_zero_len_sig(void *ctx)
{
	struct bpf_crypto_ctx *ecdsa_ctx;
	struct bpf_crypto_params params = {
		.type = "sig",
		.algo = "p1363(ecdsa-nist-p256)",
		.key_len = sizeof(pubkey_p256),
	};
	struct bpf_dynptr msg_ptr, sig_ptr;
	int err = 0;
	int ret;

	__builtin_memcpy(params.key, pubkey_p256, sizeof(pubkey_p256));

	ecdsa_ctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);
	if (!ecdsa_ctx) {
		ecdsa_zero_sig_status = err;
		return 0;
	}

	bpf_dynptr_from_mem(message_hash, sizeof(message_hash), 0, &msg_ptr);
	/* Zero-length signature */
	bpf_dynptr_from_mem(valid_signature, 0, 0, &sig_ptr);

	ret = bpf_sig_verify(ecdsa_ctx, &msg_ptr, &sig_ptr);
	/* Expected: should fail with -EINVAL (-22) */
	ecdsa_zero_sig_status = (ret == -22) ? 0 : ret;
	bpf_crypto_ctx_release(ecdsa_ctx);
	return 0;
}

char __license[] SEC("license") = "GPL";
