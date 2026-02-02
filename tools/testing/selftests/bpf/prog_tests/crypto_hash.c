// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <errno.h>
#include "crypto_hash.skel.h"

/* NIST test vectors for SHA-256("abc") */
static const unsigned char expected_sha256[32] = {
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
	0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
	0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

/* NIST test vectors for SHA-384("abc") */
static const unsigned char expected_sha384[48] = {
	0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
	0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
	0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
	0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
	0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
	0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
};

/* NIST test vectors for SHA-512("abc") */
static const unsigned char expected_sha512[64] = {
	0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
	0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
	0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
	0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
	0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
	0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
	0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
	0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
};

static struct crypto_hash *setup_skel(void)
{
	struct crypto_hash *skel;

	skel = crypto_hash__open_and_load();
	if (!skel) {
		/* Skip if kfuncs not available (CONFIG_CRYPTO_HASH2 not set) */
		if (errno == ENOENT || errno == EINVAL) {
			test__skip();
			return NULL;
		}
		ASSERT_OK_PTR(skel, "crypto_hash__open_and_load");
		return NULL;
	}

	return skel;
}

static void test_sha256_basic(void)
{
	struct crypto_hash *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = setup_skel();
	if (!skel)
		return;

	prog_fd = bpf_program__fd(skel->progs.test_sha256);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_sha256");
	ASSERT_EQ(skel->data->sha256_status, 0, "sha256_status");
	ASSERT_EQ(memcmp(skel->bss->sha256_output, expected_sha256, 32), 0,
		  "sha256_output_match");

	crypto_hash__destroy(skel);
}

static void test_sha384_basic(void)
{
	struct crypto_hash *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = setup_skel();
	if (!skel)
		return;
	prog_fd = bpf_program__fd(skel->progs.test_sha384);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_sha384");
	ASSERT_EQ(skel->data->sha384_status, 0, "sha384_status");
	ASSERT_EQ(memcmp(skel->bss->sha384_output, expected_sha384, 48), 0,
		  "sha384_output_match");

	crypto_hash__destroy(skel);
}

static void test_sha512_basic(void)
{
	struct crypto_hash *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = setup_skel();
	if (!skel)
		return;

	prog_fd = bpf_program__fd(skel->progs.test_sha512);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_sha512");
	ASSERT_EQ(skel->data->sha512_status, 0, "sha512_status");
	ASSERT_EQ(memcmp(skel->bss->sha512_output, expected_sha512, 64), 0,
		  "sha512_output_match");

	crypto_hash__destroy(skel);
}

static void test_sha256_invalid_params(void)
{
	struct crypto_hash *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = setup_skel();
	if (!skel)
		return;

	prog_fd = bpf_program__fd(skel->progs.test_sha256_zero_len);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_zero_len");
	ASSERT_EQ(skel->data->sha256_status, 0, "zero_len_rejected");

	crypto_hash__destroy(skel);
}

static void test_hash_with_key_rejected(void)
{
	struct crypto_hash *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = setup_skel();
	if (!skel)
		return;

	prog_fd = bpf_program__fd(skel->progs.test_hash_with_key_rejected);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_hash_with_key_rejected");
	ASSERT_EQ(skel->data->hash_with_key_status, 0, "hash_with_key_rejected");

	crypto_hash__destroy(skel);
}

static void test_hash_output_too_small(void)
{
	struct crypto_hash *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = setup_skel();
	if (!skel)
		return;

	prog_fd = bpf_program__fd(skel->progs.test_hash_output_too_small);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_hash_output_too_small");
	ASSERT_EQ(skel->data->hash_output_too_small_status, 0, "hash_output_too_small");

	crypto_hash__destroy(skel);
}

static void test_hash_on_skcipher_ctx(void)
{
	struct crypto_hash *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = setup_skel();
	if (!skel)
		return;

	prog_fd = bpf_program__fd(skel->progs.test_hash_on_skcipher_ctx);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_hash_on_skcipher_ctx");
	ASSERT_EQ(skel->data->hash_on_skcipher_status, 0, "hash_on_skcipher_rejected");

	crypto_hash__destroy(skel);
}

void test_crypto_hash(void)
{
	if (test__start_subtest("sha256_basic"))
		test_sha256_basic();
	if (test__start_subtest("sha384_basic"))
		test_sha384_basic();
	if (test__start_subtest("sha512_basic"))
		test_sha512_basic();
	if (test__start_subtest("sha256_invalid_params"))
		test_sha256_invalid_params();
	if (test__start_subtest("hash_with_key_rejected"))
		test_hash_with_key_rejected();
	if (test__start_subtest("hash_output_too_small"))
		test_hash_output_too_small();
	if (test__start_subtest("hash_on_skcipher_ctx"))
		test_hash_on_skcipher_ctx();
}
