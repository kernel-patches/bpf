// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "ecdsa_verify.skel.h"

static void test_ecdsa_verify_valid_signature(void)
{
	struct ecdsa_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = ecdsa_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "ecdsa_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_verify_valid);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_verify_valid");
	ASSERT_EQ(skel->data->ctx_create_status, 0, "ctx_create_status");
	ASSERT_EQ(skel->data->verify_result, 0, "verify_valid_signature");

	ecdsa_verify__destroy(skel);
}

static void test_ecdsa_verify_invalid_signature(void)
{
	struct ecdsa_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = ecdsa_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "ecdsa_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_verify_invalid);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_verify_invalid");
	ASSERT_NEQ(skel->data->verify_invalid_result, 0, "verify_invalid_signature_rejected");

	ecdsa_verify__destroy(skel);
}

static void test_ecdsa_sign_and_verify(void)
{
	struct ecdsa_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = ecdsa_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "ecdsa_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_sign_verify);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_sign_verify");
	ASSERT_GT(skel->data->sign_result, 0, "sign_returns_signature_size");
	ASSERT_EQ(skel->data->sign_verify_result, 0, "verify_generated_signature");

	ecdsa_verify__destroy(skel);
}

static void test_ecdsa_size_queries(void)
{
	struct ecdsa_verify *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = ecdsa_verify__open_and_load();
	if (!ASSERT_OK_PTR(skel, "ecdsa_verify__open_and_load"))
		return;

	prog_fd = bpf_program__fd(skel->progs.test_ecdsa_size_queries);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_ecdsa_size_queries");
	ASSERT_EQ(skel->data->keysize_result, 256, "keysize_p256");
	ASSERT_EQ(skel->data->digestsize_result, 64, "digestsize_p256");
	ASSERT_EQ(skel->data->maxsize_result, 64, "maxsize_p256");

	ecdsa_verify__destroy(skel);
}

void test_ecdsa_verify(void)
{
	if (test__start_subtest("verify_valid_signature"))
		test_ecdsa_verify_valid_signature();
	if (test__start_subtest("verify_invalid_signature"))
		test_ecdsa_verify_invalid_signature();
	if (test__start_subtest("sign_and_verify"))
		test_ecdsa_sign_and_verify();
	if (test__start_subtest("size_queries"))
		test_ecdsa_size_queries();
}
