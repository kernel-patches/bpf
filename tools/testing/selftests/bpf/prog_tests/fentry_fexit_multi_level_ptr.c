// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 CrowdStrike, Inc. */
#include <test_progs.h>
#include "fentry_fexit_pptr_nullable_test.skel.h"
#include "fentry_fexit_pptr_test.skel.h"
#include "fentry_fexit_void_pptr_test.skel.h"
#include "fentry_fexit_void_ppptr_test.skel.h"

static void test_fentry_fexit_pptr_nullable(void)
{
	struct fentry_fexit_pptr_nullable_test *skel = NULL;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = fentry_fexit_pptr_nullable_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_fexit_pptr_nullable_test__open_and_load"))
		return;

	err = fentry_fexit_pptr_nullable_test__attach(skel);
	if (!ASSERT_OK(err, "fentry_fexit_pptr_nullable_test__attach"))
		goto cleanup;

	/* Trigger fentry/fexit programs. */
	prog_fd = bpf_program__fd(skel->progs.test_fentry_pptr_nullable);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run retval");

	/* Verify fentry was called and captured the correct value. */
	ASSERT_EQ(skel->bss->fentry_called, 1, "fentry_called");
	ASSERT_EQ(skel->bss->fentry_ptr_field_value1, 1979, "fentry_ptr_field_value1");
	ASSERT_EQ(skel->bss->fentry_ptr_field_value2, 2026, "fentry_ptr_field_value2");

	/* Verify fexit captured correct values and return code. */
	ASSERT_EQ(skel->bss->fexit_called, 1, "fexit_called");
	ASSERT_EQ(skel->bss->fexit_ptr_field_value1, 1979, "fexit_ptr_field_value1");
	ASSERT_EQ(skel->bss->fexit_ptr_field_value2, 2026, "fexit_ptr_field_value2");
	ASSERT_EQ(skel->bss->fexit_retval, 1979, "fexit_retval");

cleanup:
	fentry_fexit_pptr_nullable_test__destroy(skel);
}

static void test_fentry_fexit_pptr(void)
{
	struct fentry_fexit_pptr_test *skel = NULL;
	int err, prog_fd, i;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = fentry_fexit_pptr_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_fexit_pptr_test__open_and_load"))
		return;

	/* Poison some values which should be modified by BPF programs. */
	for (i = 0; i < ARRAY_SIZE(skel->bss->telemetry); ++i) {
		skel->bss->telemetry[i].id = 30;
		skel->bss->telemetry[i].fentry_pptr = 31;
		skel->bss->telemetry[i].fentry_ptr = 32;
		skel->bss->telemetry[i].fexit_pptr = 33;
		skel->bss->telemetry[i].fexit_ptr = 34;
		skel->bss->telemetry[i].fexit_ret_pptr = 35;
		skel->bss->telemetry[i].fexit_ret_ptr = 36;
	}

	err = fentry_fexit_pptr_test__attach(skel);
	if (!ASSERT_OK(err, "fentry_fexit_pptr_test__attach"))
		goto cleanup;

	/* Trigger fentry/fexit programs */
	prog_fd = bpf_program__fd(skel->progs.test_fentry_pptr);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run retval");

	for (i = 0; i < ARRAY_SIZE(skel->bss->telemetry); ++i) {
		ASSERT_TRUE(skel->bss->telemetry[i].id == 0 ||
			skel->bss->telemetry[i].id == 1, "id");
		if (skel->bss->telemetry[i].id == 0) {
			/* Verify fentry captured the correct value. */
			ASSERT_EQ(skel->bss->telemetry[i].fentry_called, 1, "fentry_called");
			ASSERT_EQ(skel->bss->telemetry[i].fentry_ptr, (u64)29, "fentry_ptr");

			/* Verify fexit captured correct values and return address. */
			ASSERT_EQ(skel->bss->telemetry[i].fexit_called, 1, "fexit_called");
			ASSERT_EQ(skel->bss->telemetry[i].fexit_pptr,
				skel->bss->telemetry[i].fentry_pptr, "fexit_pptr");
			ASSERT_EQ(skel->bss->telemetry[i].fexit_ptr, (u64)29, "fexit_ptr");
			ASSERT_EQ(skel->bss->telemetry[i].fexit_ret_pptr,
				skel->bss->telemetry[i].fentry_pptr, "fexit_ret_pptr");
			ASSERT_EQ(skel->bss->telemetry[i].fexit_ret_ptr, (u64)29, "fexit_ret_ptr");
		} else if (skel->bss->telemetry[i].id == 1) {
			/* Verify fentry captured the correct value */
			ASSERT_EQ(skel->bss->telemetry[i].fentry_called, 1, "fentry_called");
			ASSERT_EQ(skel->bss->telemetry[i].fentry_pptr, 17, "fentry_pptr");

			/*
			 * Verify fexit captured correct values and return address,
			 * fentry_ptr value depends on kernel address space layout
			 * and a mapped page presence at NULL.
			 */
			ASSERT_EQ(skel->bss->telemetry[i].fexit_called, 1, "fexit_called");
			ASSERT_EQ(skel->bss->telemetry[i].fexit_pptr, 17, "fexit_pptr");
			ASSERT_EQ(skel->bss->telemetry[i].fexit_ptr,
				skel->bss->telemetry[i].fentry_ptr, "fexit_ptr");
			ASSERT_EQ(skel->bss->telemetry[i].fexit_ret_pptr, 17, "fexit_ret_pptr");
			ASSERT_EQ(skel->bss->telemetry[i].fexit_ret_ptr,
				skel->bss->telemetry[i].fentry_ptr, "fexit_ret_ptr");
		}
	}

cleanup:
	fentry_fexit_pptr_test__destroy(skel);
}

static void test_fentry_fexit_void_pptr(void)
{
	struct fentry_fexit_void_pptr_test *skel = NULL;
	int err, prog_fd, i;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = fentry_fexit_void_pptr_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_fexit_void_pptr_test__open_and_load"))
		return;

	/* Poison some values which should be modified by BPF programs. */
	for (i = 0; i < ARRAY_SIZE(skel->bss->telemetry); ++i) {
		skel->bss->telemetry[i].fentry_pptr = 30;
		skel->bss->telemetry[i].fentry_ptr = 31;
		skel->bss->telemetry[i].fexit_pptr = 32;
		skel->bss->telemetry[i].fexit_ptr = 33;
	}

	err = fentry_fexit_void_pptr_test__attach(skel);
	if (!ASSERT_OK(err, "fentry_fexit_void_pptr_test__attach"))
		goto cleanup;

	/* Trigger fentry/fexit programs. */
	prog_fd = bpf_program__fd(skel->progs.test_fentry_void_pptr);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run retval");
	for (i = 0; i < ARRAY_SIZE(skel->bss->telemetry); ++i) {
		ASSERT_EQ(skel->bss->telemetry[i].fentry_called, 1, "fentry_called");
		ASSERT_EQ(skel->bss->telemetry[i].fexit_called, 1, "fexit_called");
		ASSERT_EQ(skel->bss->telemetry[i].fentry_pptr, skel->bss->telemetry[i].fexit_pptr,
			"fentry_pptr == fexit_pptr");
		ASSERT_EQ(skel->bss->telemetry[i].fexit_ptr, skel->bss->telemetry[i].fentry_ptr,
			"fexit_ptr");
		ASSERT_EQ(skel->bss->telemetry[i].fentry_pptr_addr_valid,
			skel->bss->telemetry[i].fexit_pptr_addr_valid, "fexit_pptr_addr_valid");
		if (!skel->bss->telemetry[i].fentry_pptr_addr_valid) {
			/* Should be set to 0 by kernel address boundaries check or an exception handler. */
			ASSERT_EQ(skel->bss->telemetry[i].fentry_ptr, 0, "fentry_ptr");
			ASSERT_EQ(skel->bss->telemetry[i].fexit_ptr, 0, "fexit_ptr");
		}
	}
cleanup:
	fentry_fexit_void_pptr_test__destroy(skel);
}

static void test_fentry_fexit_void_ppptr(void)
{
	struct fentry_fexit_void_ppptr_test *skel = NULL;
	int err, prog_fd;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = fentry_fexit_void_ppptr_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_fexit_void_ppptr_test__open_and_load"))
		return;

	/* Poison some values which should be modified by BPF programs */
	skel->bss->fentry_pptr = 31;

	err = fentry_fexit_void_ppptr_test__attach(skel);
	if (!ASSERT_OK(err, "fentry_fexit_void_ppptr_test__attach"))
		goto cleanup;

	/* Trigger fentry/fexit programs */
	prog_fd = bpf_program__fd(skel->progs.test_fentry_void_ppptr);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run retval");

	/* Verify invalid memory access results in zeroed register */
	ASSERT_EQ(skel->bss->fentry_called, 1, "fentry_called");
	ASSERT_EQ(skel->bss->fentry_pptr, 0, "fentry_pptr");

	/* Verify fexit captured correct values and return value */
	ASSERT_EQ(skel->bss->fexit_called, 1, "fexit_called");
	ASSERT_EQ(skel->bss->fexit_retval, (u64)ERR_PTR(-ENOMEM), "fexit_retval");

cleanup:
	fentry_fexit_void_ppptr_test__destroy(skel);
}

void test_fentry_fexit_multi_level_ptr(void)
{
	if (test__start_subtest("pptr_nullable"))
		test_fentry_fexit_pptr_nullable();
	if (test__start_subtest("pptr"))
		test_fentry_fexit_pptr();
	if (test__start_subtest("void_pptr"))
		test_fentry_fexit_void_pptr();
	if (test__start_subtest("void_ppptr"))
		test_fentry_fexit_void_ppptr();
}
