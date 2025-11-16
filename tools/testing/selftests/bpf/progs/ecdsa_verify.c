// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct bpf_ecdsa_ctx;
extern struct bpf_ecdsa_ctx *
bpf_ecdsa_ctx_create(const struct bpf_dynptr *algo_name,
		     const struct bpf_dynptr *public_key, int *err) __ksym;
extern struct bpf_ecdsa_ctx *
bpf_ecdsa_ctx_create_with_privkey(const struct bpf_dynptr *algo_name,
				   const struct bpf_dynptr *private_key, int *err) __ksym;
extern int bpf_ecdsa_verify(struct bpf_ecdsa_ctx *ctx,
			    const struct bpf_dynptr *message,
			    const struct bpf_dynptr *signature) __ksym;
extern int bpf_ecdsa_sign(struct bpf_ecdsa_ctx *ctx,
			  const struct bpf_dynptr *message,
			  const struct bpf_dynptr *signature) __ksym;
extern int bpf_ecdsa_keysize(struct bpf_ecdsa_ctx *ctx) __ksym;
extern int bpf_ecdsa_digestsize(struct bpf_ecdsa_ctx *ctx) __ksym;
extern int bpf_ecdsa_maxsize(struct bpf_ecdsa_ctx *ctx) __ksym;
extern void bpf_ecdsa_ctx_release(struct bpf_ecdsa_ctx *ctx) __ksym;

/* NIST P-256 test vector
 * This is a known valid ECDSA signature for testing purposes
 */

/* Algorithm name for P-256 with p1363 format (standard r||s signature) */
char algo_p256[] = "p1363(ecdsa-nist-p256)";

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

/* Private key for signing (32 bytes) - matches the public key above */
unsigned char privkey_p256[32] = {
	0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16,
	0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
	0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
	0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21
};

/* Test results */
int verify_result = -1;
int verify_invalid_result = -1;
int ctx_create_status = -1;
int sign_result = -1;
int sign_verify_result = -1;
int keysize_result = -1;
int digestsize_result = -1;
int maxsize_result = -1;
unsigned char generated_signature[64] = {0};

SEC("syscall")
int test_ecdsa_verify_valid(void *ctx)
{
	struct bpf_ecdsa_ctx *ecdsa_ctx;
	struct bpf_dynptr algo_ptr, key_ptr, msg_ptr, sig_ptr;
	int err = 0;

	bpf_dynptr_from_mem(algo_p256, sizeof(algo_p256) - 1, 0, &algo_ptr);
	bpf_dynptr_from_mem(pubkey_p256, sizeof(pubkey_p256), 0, &key_ptr);

	ecdsa_ctx = bpf_ecdsa_ctx_create(&algo_ptr, &key_ptr, &err);
	if (!ecdsa_ctx) {
		ctx_create_status = err;
		return 0;
	}
	ctx_create_status = 0;

	bpf_dynptr_from_mem(message_hash, sizeof(message_hash), 0, &msg_ptr);
	bpf_dynptr_from_mem(valid_signature, sizeof(valid_signature), 0, &sig_ptr);

	verify_result = bpf_ecdsa_verify(ecdsa_ctx, &msg_ptr, &sig_ptr);

	bpf_ecdsa_ctx_release(ecdsa_ctx);

	return 0;
}

SEC("syscall")
int test_ecdsa_verify_invalid(void *ctx)
{
	struct bpf_ecdsa_ctx *ecdsa_ctx;
	struct bpf_dynptr algo_ptr, key_ptr, msg_ptr, sig_ptr;
	int err = 0;

	bpf_dynptr_from_mem(algo_p256, sizeof(algo_p256) - 1, 0, &algo_ptr);
	bpf_dynptr_from_mem(pubkey_p256, sizeof(pubkey_p256), 0, &key_ptr);

	ecdsa_ctx = bpf_ecdsa_ctx_create(&algo_ptr, &key_ptr, &err);
	if (!ecdsa_ctx)
		return 0;

	bpf_dynptr_from_mem(message_hash, sizeof(message_hash), 0, &msg_ptr);
	bpf_dynptr_from_mem(invalid_signature, sizeof(invalid_signature), 0, &sig_ptr);

	verify_invalid_result = bpf_ecdsa_verify(ecdsa_ctx, &msg_ptr, &sig_ptr);

	bpf_ecdsa_ctx_release(ecdsa_ctx);

	return 0;
}

SEC("syscall")
int test_ecdsa_sign_verify(void *ctx)
{
	struct bpf_ecdsa_ctx *sign_ctx, *verify_ctx;
	struct bpf_dynptr algo_ptr, privkey_ptr, pubkey_ptr, msg_ptr, sig_ptr;
	int err = 0;

	/* Create signing context with private key */
	bpf_dynptr_from_mem(algo_p256, sizeof(algo_p256) - 1, 0, &algo_ptr);
	bpf_dynptr_from_mem(privkey_p256, sizeof(privkey_p256), 0, &privkey_ptr);

	sign_ctx = bpf_ecdsa_ctx_create_with_privkey(&algo_ptr, &privkey_ptr, &err);
	if (!sign_ctx) {
		sign_result = err;
		return 0;
	}

	/* Sign the message */
	bpf_dynptr_from_mem(message_hash, sizeof(message_hash), 0, &msg_ptr);
	bpf_dynptr_from_mem(generated_signature, sizeof(generated_signature), 0, &sig_ptr);

	sign_result = bpf_ecdsa_sign(sign_ctx, &msg_ptr, &sig_ptr);

	bpf_ecdsa_ctx_release(sign_ctx);

	/* If signing succeeded, verify the generated signature */
	if (sign_result > 0 && sign_result <= (int)sizeof(generated_signature)) {
		unsigned int sig_size;

		/* Explicitly bound the value for the verifier */
		sig_size = sign_result & 0x3F; /* Max 64 bytes */

		bpf_dynptr_from_mem(algo_p256, sizeof(algo_p256) - 1, 0, &algo_ptr);
		bpf_dynptr_from_mem(pubkey_p256, sizeof(pubkey_p256), 0, &pubkey_ptr);

		verify_ctx = bpf_ecdsa_ctx_create(&algo_ptr, &pubkey_ptr, &err);
		if (!verify_ctx) {
			sign_verify_result = err;
			return 0;
		}

		bpf_dynptr_from_mem(message_hash, sizeof(message_hash), 0, &msg_ptr);
		bpf_dynptr_from_mem(generated_signature, sig_size, 0, &sig_ptr);

		sign_verify_result = bpf_ecdsa_verify(verify_ctx, &msg_ptr, &sig_ptr);

		bpf_ecdsa_ctx_release(verify_ctx);
	}

	return 0;
}

SEC("syscall")
int test_ecdsa_size_queries(void *ctx)
{
	struct bpf_ecdsa_ctx *ecdsa_ctx;
	struct bpf_dynptr algo_ptr, key_ptr;
	int err = 0;

	bpf_dynptr_from_mem(algo_p256, sizeof(algo_p256) - 1, 0, &algo_ptr);
	bpf_dynptr_from_mem(pubkey_p256, sizeof(pubkey_p256), 0, &key_ptr);

	ecdsa_ctx = bpf_ecdsa_ctx_create(&algo_ptr, &key_ptr, &err);
	if (!ecdsa_ctx)
		return 0;

	keysize_result = bpf_ecdsa_keysize(ecdsa_ctx);
	digestsize_result = bpf_ecdsa_digestsize(ecdsa_ctx);
	maxsize_result = bpf_ecdsa_maxsize(ecdsa_ctx);

	bpf_ecdsa_ctx_release(ecdsa_ctx);

	return 0;
}

char __license[] SEC("license") = "GPL";
