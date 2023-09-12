// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <test_progs.h>
#include "cgroup_helpers.h"

#include "iters.skel.h"
#include "iters_state_safety.skel.h"
#include "iters_looping.skel.h"
#include "iters_num.skel.h"
#include "iters_testmod_seq.skel.h"
#include "iters_task.skel.h"

static void subtest_num_iters(void)
{
	struct iters_num *skel;
	int err;

	skel = iters_num__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = iters_num__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	usleep(1);
	iters_num__detach(skel);

#define VALIDATE_CASE(case_name)					\
	ASSERT_EQ(skel->bss->res_##case_name,				\
		  skel->rodata->exp_##case_name,			\
		  #case_name)

	VALIDATE_CASE(empty_zero);
	VALIDATE_CASE(empty_int_min);
	VALIDATE_CASE(empty_int_max);
	VALIDATE_CASE(empty_minus_one);

	VALIDATE_CASE(simple_sum);
	VALIDATE_CASE(neg_sum);
	VALIDATE_CASE(very_neg_sum);
	VALIDATE_CASE(neg_pos_sum);

	VALIDATE_CASE(invalid_range);
	VALIDATE_CASE(max_range);
	VALIDATE_CASE(e2big_range);

	VALIDATE_CASE(succ_elem_cnt);
	VALIDATE_CASE(overfetched_elem_cnt);
	VALIDATE_CASE(fail_elem_cnt);

#undef VALIDATE_CASE

cleanup:
	iters_num__destroy(skel);
}

static void subtest_testmod_seq_iters(void)
{
	struct iters_testmod_seq *skel;
	int err;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	skel = iters_testmod_seq__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = iters_testmod_seq__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	usleep(1);
	iters_testmod_seq__detach(skel);

#define VALIDATE_CASE(case_name)					\
	ASSERT_EQ(skel->bss->res_##case_name,				\
		  skel->rodata->exp_##case_name,			\
		  #case_name)

	VALIDATE_CASE(empty);
	VALIDATE_CASE(full);
	VALIDATE_CASE(truncated);

#undef VALIDATE_CASE

cleanup:
	iters_testmod_seq__destroy(skel);
}

static void subtest_process_iters(void)
{
	struct iters_task *skel;
	int err;

	skel = iters_task__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;
	bpf_program__set_autoload(skel->progs.iter_task_for_each_sleep, true);
	err = iters_task__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;
	skel->bss->target_pid = getpid();
	err = iters_task__attach(skel);
	if (!ASSERT_OK(err, "iters_task__attach"))
		goto cleanup;
	syscall(SYS_getpgid);
	iters_task__detach(skel);
	ASSERT_EQ(skel->bss->process_cnt, 1, "process_cnt");

cleanup:
	iters_task__destroy(skel);
}

extern int stack_mprotect(void);

static void subtest_css_task_iters(void)
{
	struct iters_task *skel;
	int err, cg_fd, cg_id;
	const char *cgrp_path = "/cg1";

	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		goto cleanup;
	cg_fd = create_and_get_cgroup(cgrp_path);
	if (!ASSERT_GE(cg_fd, 0, "cg_create"))
		goto cleanup;
	cg_id = get_cgroup_id(cgrp_path);
	err = join_cgroup(cgrp_path);
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		goto cleanup;

	skel = iters_task__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	bpf_program__set_autoload(skel->progs.iter_css_task_for_each, true);
	err = iters_task__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	skel->bss->target_pid = getpid();
	skel->bss->cg_id = cg_id;
	err = iters_task__attach(skel);

	err = stack_mprotect();
	if (!ASSERT_OK(err, "iters_task__attach"))
		goto cleanup;

	iters_task__detach(skel);
	ASSERT_EQ(skel->bss->css_task_cnt, 1, "css_task_cnt");

cleanup:
	cleanup_cgroup_environment();
	iters_task__destroy(skel);
}

static void subtest_css_dec_iters(void)
{
	struct iters_task *skel;
	struct {
		const char *path;
		int fd;
	} cgs[] = {
		{ "/cg1" },
		{ "/cg1/cg2" },
		{ "/cg1/cg2/cg3" },
		{ "/cg1/cg2/cg3/cg4" },
	};
	int err, cg_nr = ARRAY_SIZE(cgs);
	int i;

	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		goto cleanup;
	for (i = 0; i < cg_nr; i++) {
		cgs[i].fd = create_and_get_cgroup(cgs[i].path);
		if (!ASSERT_GE(cgs[i].fd, 0, "cg_create"))
			goto cleanup;
	}

	skel = iters_task__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;
	bpf_program__set_autoload(skel->progs.iter_css_dec_for_each, true);
	err = iters_task__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	skel->bss->target_pid = getpid();
	skel->bss->cg_id = get_cgroup_id(cgs[0].path);

	err = iters_task__attach(skel);

	if (!ASSERT_OK(err, "iters_task__attach"))
		goto cleanup;

	syscall(SYS_getpgid);
	ASSERT_EQ(skel->bss->css_dec_cnt, cg_nr, "pre order search dec count");
	ASSERT_EQ(skel->bss->first_cg_id, get_cgroup_id(cgs[0].path),
				"pre order search first cgroup id");
	skel->bss->css_dec_cnt = 0;
	skel->bss->is_post_order = 1;
	syscall(SYS_getpgid);
	ASSERT_EQ(skel->bss->css_dec_cnt, cg_nr, "post order search dec count");
	ASSERT_EQ(skel->bss->last_cg_id, get_cgroup_id(cgs[0].path),
				"post order search last cgroup id");
	iters_task__detach(skel);
cleanup:
	cleanup_cgroup_environment();
	iters_task__destroy(skel);
}

void test_iters(void)
{
	RUN_TESTS(iters_state_safety);
	RUN_TESTS(iters_looping);
	RUN_TESTS(iters);

	if (env.has_testmod)
		RUN_TESTS(iters_testmod_seq);

	if (test__start_subtest("num"))
		subtest_num_iters();
	if (test__start_subtest("testmod_seq"))
		subtest_testmod_seq_iters();
	if (test__start_subtest("process"))
		subtest_process_iters();
	if (test__start_subtest("css_task"))
		subtest_css_task_iters();
	if (test__start_subtest("css_dec"))
		subtest_css_dec_iters();
}
