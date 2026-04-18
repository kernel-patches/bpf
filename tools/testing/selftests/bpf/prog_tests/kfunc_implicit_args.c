// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "kfunc_implicit_args.skel.h"

#define TEST_BPF_LOG_LEVEL_WARN	(1U << 4)

static size_t libbpf_log_pos;
static char libbpf_log_buf[4096];
static bool libbpf_log_error;

static int libbpf_print_cb(enum libbpf_print_level level, const char *fmt, va_list args)
{
	int emitted_cnt;
	size_t left_cnt;

	(void)level;

	left_cnt = sizeof(libbpf_log_buf) - libbpf_log_pos;
	emitted_cnt = vsnprintf(libbpf_log_buf + libbpf_log_pos, left_cnt, fmt, args);
	if (emitted_cnt < 0 || emitted_cnt + 1 > left_cnt) {
		libbpf_log_error = true;
		return 0;
	}

	libbpf_log_pos += emitted_cnt;
	return 0;
}

static void select_legacy_impl_prog(struct kfunc_implicit_args *skel)
{
	struct bpf_program *prog;

	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog,
					  prog == skel->progs.test_kfunc_implicit_arg_legacy_impl);
}

static void test_warn_bit(void)
{
	struct kfunc_implicit_args *skel;
	char log_buf[4096] = {};
	int err;

	skel = kfunc_implicit_args__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	select_legacy_impl_prog(skel);
	bpf_program__set_log_buf(skel->progs.test_kfunc_implicit_arg_legacy_impl,
				 log_buf, sizeof(log_buf));
	bpf_program__set_log_level(skel->progs.test_kfunc_implicit_arg_legacy_impl,
				   TEST_BPF_LOG_LEVEL_WARN);

	err = kfunc_implicit_args__load(skel);
	ASSERT_OK(err, "skel_load");
	ASSERT_OK_PTR(strstr(log_buf, "uses deprecated kfunc bpf_kfunc_implicit_arg_legacy_impl()"),
		      "warning_msg");
	ASSERT_NULL(strstr(log_buf, "processed "), "no_verbose_log");

	kfunc_implicit_args__destroy(skel);
}

static void test_default_warning_flush(void)
{
	libbpf_print_fn_t old_print_cb = libbpf_set_print(libbpf_print_cb);
	struct kfunc_implicit_args *skel = NULL;
	int err;

	libbpf_log_pos = 0;
	libbpf_log_buf[0] = '\0';
	libbpf_log_error = false;

	skel = kfunc_implicit_args__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	select_legacy_impl_prog(skel);

	err = kfunc_implicit_args__load(skel);
	ASSERT_OK(err, "skel_load");
	ASSERT_FALSE(libbpf_log_error, "libbpf_log_error");
	ASSERT_OK_PTR(strstr(libbpf_log_buf, "-- BEGIN PROG LOAD WARNINGS --"), "warn_banner");
	ASSERT_OK_PTR(strstr(libbpf_log_buf,
			     "uses deprecated kfunc bpf_kfunc_implicit_arg_legacy_impl()"),
		      "warn_msg");
	ASSERT_NULL(strstr(libbpf_log_buf, "-- BEGIN PROG LOAD LOG --"), "no_verbose_log");

cleanup:
	kfunc_implicit_args__destroy(skel);
	libbpf_set_print(old_print_cb);
}

void test_kfunc_implicit_args(void)
{
	RUN_TESTS(kfunc_implicit_args);
	if (test__start_subtest("warn_bit"))
		test_warn_bit();
	if (test__start_subtest("default_warning_flush"))
		test_default_warning_flush();
}
