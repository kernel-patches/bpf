// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include "tracing_failure.skel.h"
#include "tailcall_bpf2bpf1.skel.h"
#include "freplace_global_func.skel.h"

static void test_bpf_spin_lock(bool is_spin_lock)
{
	struct tracing_failure *skel;
	int err;

	skel = tracing_failure__open();
	if (!ASSERT_OK_PTR(skel, "tracing_failure__open"))
		return;

	if (is_spin_lock)
		bpf_program__set_autoload(skel->progs.test_spin_lock, true);
	else
		bpf_program__set_autoload(skel->progs.test_spin_unlock, true);

	err = tracing_failure__load(skel);
	if (!ASSERT_OK(err, "tracing_failure__load"))
		goto out;

	err = tracing_failure__attach(skel);
	ASSERT_ERR(err, "tracing_failure__attach");

out:
	tracing_failure__destroy(skel);
}

static void test_freplace_attach_log(void)
{
	struct freplace_global_func *freplace_skel = NULL;
	struct tailcall_bpf2bpf1 *tailcall_skel = NULL;
	struct bpf_link *freplace_link = NULL;
	struct bpf_program *prog;
	char log_buf[64];
	int err, prog_fd;

	tailcall_skel = tailcall_bpf2bpf1__open_and_load();
	if (!ASSERT_OK_PTR(tailcall_skel, "tailcall_bpf2bpf1__open_and_load"))
		return;

	freplace_skel = freplace_global_func__open();
	if (!ASSERT_OK_PTR(freplace_skel, "freplace_global_func__open"))
		goto out;

	prog = freplace_skel->progs.new_test_pkt_access;
	prog_fd = bpf_program__fd(tailcall_skel->progs.entry);
	err = bpf_program__set_attach_target(prog, prog_fd, "entry");
	if (!ASSERT_OK(err, "bpf_program__set_attach_target"))
		goto out;

	err = freplace_global_func__load(freplace_skel);
	if (!ASSERT_OK(err, "freplace_global_func__load"))
		goto out;

	log_buf[0] = '\0';
	freplace_link = bpf_program__attach_freplace_log(prog, prog_fd, "subprog_tail", log_buf,
							 sizeof(log_buf));
	ASSERT_ERR_PTR(freplace_link, "bpf_program__attach_freplace_log");
	ASSERT_STREQ(log_buf, "subprog_tail() is not a global function\n", "log_buf");

out:
	bpf_link__destroy(freplace_link);
	freplace_global_func__destroy(freplace_skel);
	tailcall_bpf2bpf1__destroy(tailcall_skel);
}

void test_tracing_failure(void)
{
	if (test__start_subtest("bpf_spin_lock"))
		test_bpf_spin_lock(true);
	if (test__start_subtest("bpf_spin_unlock"))
		test_bpf_spin_lock(false);
	if (test__start_subtest("freplace_attach_log"))
		test_freplace_attach_log();
}
