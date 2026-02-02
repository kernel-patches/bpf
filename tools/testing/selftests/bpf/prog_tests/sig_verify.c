// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "sig_verify.skel.h"

static void test_ecdsa_verify_valid_signature(void)
{
	struct sig_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = sig_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "sig_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_verify_valid);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_verify_valid");
	ASSERT_EQ(skel->data->ctx_create_status, 0, "ctx_create_status");
	ASSERT_EQ(skel->data->verify_result, 0, "verify_valid_signature");

	sig_verify__destroy(skel);
}

static void test_ecdsa_verify_invalid_signature(void)
{
	struct sig_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = sig_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "sig_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_verify_invalid);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_verify_invalid");
	ASSERT_NEQ(skel->data->verify_invalid_result, 0, "verify_invalid_signature_rejected");

	sig_verify__destroy(skel);
}

static void test_ecdsa_size_queries(void)
{
	struct sig_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = sig_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "sig_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_size_queries);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_size_queries");
	ASSERT_EQ(skel->data->ctx_create_status, 0, "ctx_create_status");
	/* P-256 key size is 256 bits = 32 bytes */
	ASSERT_GT(skel->data->keysize_result, 0, "keysize_positive");
	/* P-256 digest size is 32 bytes (SHA-256) */
	ASSERT_GT(skel->data->digestsize_result, 0, "digestsize_positive");
	/* P-256 max signature size is 64 bytes (r||s format) */
	ASSERT_GT(skel->data->maxsize_result, 0, "maxsize_positive");

	sig_verify__destroy(skel);
}

static void test_ecdsa_on_hash_ctx(void)
{
	struct sig_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = sig_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "sig_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_on_hash_ctx);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_on_hash_ctx");
	ASSERT_EQ(skel->data->ecdsa_on_hash_ctx_status, 0, "ecdsa_on_hash_ctx_rejected");

	sig_verify__destroy(skel);
}

static void test_ecdsa_keysize_on_hash_ctx(void)
{
	struct sig_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = sig_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "sig_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_keysize_on_hash_ctx);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_keysize_on_hash_ctx");
	ASSERT_EQ(skel->data->ecdsa_keysize_on_hash_status, 0, "ecdsa_keysize_on_hash_rejected");

	sig_verify__destroy(skel);
}

static void test_ecdsa_zero_len_msg(void)
{
	struct sig_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = sig_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "sig_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_zero_len_msg);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_zero_len_msg");
	ASSERT_EQ(skel->data->ecdsa_zero_msg_status, 0, "zero_len_msg_rejected");

	sig_verify__destroy(skel);
}

static void test_ecdsa_zero_len_sig(void)
{
	struct sig_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = sig_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "sig_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_zero_len_sig);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_zero_len_sig");
	ASSERT_EQ(skel->data->ecdsa_zero_sig_status, 0, "zero_len_sig_rejected");

	sig_verify__destroy(skel);
}

void test_sig_verify(void)
{
	if (test__start_subtest("verify_valid_signature"))
		test_ecdsa_verify_valid_signature();
	if (test__start_subtest("verify_invalid_signature"))
		test_ecdsa_verify_invalid_signature();
	if (test__start_subtest("size_queries"))
		test_ecdsa_size_queries();
	if (test__start_subtest("ecdsa_on_hash_ctx"))
		test_ecdsa_on_hash_ctx();
	if (test__start_subtest("ecdsa_keysize_on_hash_ctx"))
		test_ecdsa_keysize_on_hash_ctx();
	if (test__start_subtest("zero_len_msg"))
		test_ecdsa_zero_len_msg();
	if (test__start_subtest("zero_len_sig"))
		test_ecdsa_zero_len_sig();
}
