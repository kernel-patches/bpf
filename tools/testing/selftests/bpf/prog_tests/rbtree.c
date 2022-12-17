// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <network_helpers.h>

#include "rbtree.skel.h"
#include "rbtree_fail.skel.h"
#include "rbtree_btf_fail__wrong_node_type.skel.h"
#include "rbtree_btf_fail__add_wrong_type.skel.h"

static char log_buf[1024 * 1024];

static struct {
	const char *prog_name;
	const char *err_msg;
} rbtree_fail_tests[] = {
	{"rbtree_api_nolock_add", "bpf_spin_lock at off=16 must be held for bpf_rb_root"},
	{"rbtree_api_nolock_remove", "bpf_spin_lock at off=16 must be held for bpf_rb_root"},
	{"rbtree_api_nolock_first", "bpf_spin_lock at off=16 must be held for bpf_rb_root"},

	/* Specific failure string for these three isn't very important, but it shouldn't be
	 * possible to call rbtree api func from within add() callback
	 */
	{"rbtree_api_add_bad_cb_bad_fn_call_add",
	 "release kernel function bpf_rbtree_add expects refcounted PTR_TO_BTF_ID"},
	{"rbtree_api_add_bad_cb_bad_fn_call_remove", "rbtree_remove not allowed in rbtree cb"},
	{"rbtree_api_add_bad_cb_bad_fn_call_first_unlock_after",
	 "can't spin_{lock,unlock} in rbtree cb"},

	{"rbtree_api_remove_unadded_node", "rbtree_remove node input must be non-owning ref"},
	{"rbtree_api_add_to_multiple_trees",
	 "function bpf_rbtree_add expects refcounted PTR_TO_BTF_ID"},
	{"rbtree_api_add_release_unlock_escape", "arg#1 expected pointer to allocated object"},
	{"rbtree_api_first_release_unlock_escape", "arg#1 expected pointer to allocated object"},
	{"rbtree_api_remove_no_drop", "Unreleased reference id=2 alloc_insn=11"},
	{"rbtree_api_release_aliasing", "arg#1 expected pointer to allocated object"},
};

static void test_rbtree_fail_prog(const char *prog_name, const char *err_msg)
{
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		    .kernel_log_buf = log_buf,
		    .kernel_log_size = sizeof(log_buf),
		    .kernel_log_level = 1
	);
	struct rbtree_fail *skel;
	struct bpf_program *prog;
	int ret;

	skel = rbtree_fail__open_opts(&opts);
	if (!ASSERT_OK_PTR(skel, "rbtree_fail__open_opts"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto end;

	bpf_program__set_autoload(prog, true);

	ret = rbtree_fail__load(skel);
	if (!ASSERT_ERR(ret, "rbtree_fail__load must fail"))
		goto end;

	if (!ASSERT_OK_PTR(strstr(log_buf, err_msg), "expected error message")) {
		fprintf(stderr, "Expected: %s\n", err_msg);
		fprintf(stderr, "Verifier: %s\n", log_buf);
	}

end:
	rbtree_fail__destroy(skel);
}

static void test_rbtree_add_nodes(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);
	struct rbtree *skel;
	int ret;

	skel = rbtree__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rbtree__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.rbtree_add_nodes), &opts);
	ASSERT_OK(ret, "rbtree_add_nodes run");
	ASSERT_OK(opts.retval, "rbtree_add_nodes retval");
	ASSERT_EQ(skel->data->less_callback_ran, 1, "rbtree_add_nodes less_callback_ran");

	rbtree__destroy(skel);
}

static void test_rbtree_add_and_remove(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);
	struct rbtree *skel;
	int ret;

	skel = rbtree__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rbtree__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.rbtree_add_and_remove), &opts);
	ASSERT_OK(ret, "rbtree_add_and_remove");
	ASSERT_OK(opts.retval, "rbtree_add_and_remove retval");
	ASSERT_EQ(skel->data->removed_key, 5, "rbtree_add_and_remove first removed key");

	rbtree__destroy(skel);
}

static void test_rbtree_first_and_remove(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = &pkt_v4,
		    .data_size_in = sizeof(pkt_v4),
		    .repeat = 1,
	);
	struct rbtree *skel;
	int ret;

	skel = rbtree__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rbtree__open_and_load"))
		return;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.rbtree_first_and_remove), &opts);
	ASSERT_OK(ret, "rbtree_first_and_remove");
	ASSERT_OK(opts.retval, "rbtree_first_and_remove retval");
	ASSERT_EQ(skel->data->first_data[0], 2, "rbtree_first_and_remove first rbtree_first()");
	ASSERT_EQ(skel->data->removed_key, 1, "rbtree_first_and_remove first removed key");
	ASSERT_EQ(skel->data->first_data[1], 4, "rbtree_first_and_remove second rbtree_first()");

	rbtree__destroy(skel);
}

void test_rbtree_success(void)
{
	if (test__start_subtest("rbtree_add_nodes"))
		test_rbtree_add_nodes();
	if (test__start_subtest("rbtree_add_and_remove"))
		test_rbtree_add_and_remove();
	if (test__start_subtest("rbtree_first_and_remove"))
		test_rbtree_first_and_remove();
}

#define BTF_FAIL_TEST(suffix)									\
void test_rbtree_btf_fail__##suffix(void)							\
{												\
	struct rbtree_btf_fail__##suffix *skel;							\
												\
	skel = rbtree_btf_fail__##suffix##__open_and_load();					\
	if (!ASSERT_ERR_PTR(skel,								\
			    "rbtree_btf_fail__" #suffix "__open_and_load unexpected success"))	\
		rbtree_btf_fail__##suffix##__destroy(skel);					\
}

#define RUN_BTF_FAIL_TEST(suffix)				\
	if (test__start_subtest("rbtree_btf_fail__" #suffix))	\
		test_rbtree_btf_fail__##suffix();

BTF_FAIL_TEST(wrong_node_type);
BTF_FAIL_TEST(add_wrong_type);

void test_rbtree_btf_fail(void)
{
	RUN_BTF_FAIL_TEST(wrong_node_type);
	RUN_BTF_FAIL_TEST(add_wrong_type);
}

void test_rbtree_fail(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rbtree_fail_tests); i++) {
		if (!test__start_subtest(rbtree_fail_tests[i].prog_name))
			continue;
		test_rbtree_fail_prog(rbtree_fail_tests[i].prog_name,
				      rbtree_fail_tests[i].err_msg);
	}
}
