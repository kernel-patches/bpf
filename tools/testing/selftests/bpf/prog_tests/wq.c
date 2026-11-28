// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Benjamin Tissoires */
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <test_progs.h>
#include "wq.skel.h"
#include "wq_failures.skel.h"

#define CALLBACK_WAIT_RETRIES 10000
#define CALLBACK_WAIT_US 1000
#define WQ_USERCNT_MAX_ATTEMPTS 256
#define WQ_USERCNT_RETRY EAGAIN

static int pin_to_first_cpu(cpu_set_t *old_mask)
{
	cpu_set_t new_mask;
	int cpu;

	if (sched_getaffinity(0, sizeof(*old_mask), old_mask))
		return -errno;

	for (cpu = 0; cpu < CPU_SETSIZE; cpu++)
		if (CPU_ISSET(cpu, old_mask))
			break;
	if (cpu == CPU_SETSIZE)
		return -EINVAL;

	CPU_ZERO(&new_mask);
	CPU_SET(cpu, &new_mask);
	if (sched_setaffinity(0, sizeof(new_mask), &new_mask))
		return -errno;
	return 0;
}

/* Check callback setup after reusing an idle object with no map uref. */
static void test_wq_usercnt_reuse(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct bpf_program *prog;
	struct wq *skel = NULL;
	cpu_set_t old_mask;
	int err, attempt, inner_fd, outer_fd;
	int prepare_fd, reuse_fd;

	if (!ASSERT_OK(pin_to_first_cpu(&old_mask), "pin"))
		return;

	skel = wq__open();
	if (!ASSERT_OK_PTR(skel, "wq__open"))
		goto restore;

	bpf_object__for_each_program(prog, skel->obj) {
		if (prog != skel->progs.prepare_wq_usercnt_reuse &&
		    prog != skel->progs.test_wq_usercnt_reuse)
			bpf_program__set_autoload(prog, false);
	}
	err = wq__load(skel);
	if (!ASSERT_OK(err, "wq__load"))
		goto destroy;

	outer_fd = bpf_map__fd(skel->maps.outer_wq);
	prepare_fd = bpf_program__fd(skel->progs.prepare_wq_usercnt_reuse);
	reuse_fd = bpf_program__fd(skel->progs.test_wq_usercnt_reuse);

	opts.btf_fd = bpf_object__btf_fd(skel->obj);
	opts.btf_key_type_id = bpf_map__btf_key_type_id(skel->maps.hmap_malloc);
	opts.btf_value_type_id = bpf_map__btf_value_type_id(skel->maps.hmap_malloc);
	opts.map_flags = BPF_F_NO_PREALLOC;

	for (attempt = 0; attempt < WQ_USERCNT_MAX_ATTEMPTS; attempt++) {
		LIBBPF_OPTS(bpf_test_run_opts, run_opts);
		bool have_reuse_retval = false;
		int key = 0;
		__s32 retval;

		/* Only key 0 is used; a single bucket suffices. */
		inner_fd = bpf_map_create(BPF_MAP_TYPE_HASH, "wq_usercnt",
					  sizeof(int),
					  bpf_map__value_size(skel->maps.hmap_malloc),
					  1, &opts);
		if (!ASSERT_GE(inner_fd, 0, "inner_create"))
			break;

		err = bpf_map_update_elem(outer_fd, &key, &inner_fd, 0);
		if (!ASSERT_OK(err, "inner_install")) {
			close(inner_fd);
			break;
		}

		err = bpf_prog_test_run_opts(prepare_fd, &run_opts);
		/* The outer slot keeps the inner map alive after its last user FD closes. */
		close(inner_fd);
		if (ASSERT_OK(err, "usercnt_prepare_run") &&
		    ASSERT_OK((__s32)run_opts.retval, "usercnt_prepare_ret")) {
			err = bpf_prog_test_run_opts(reuse_fd, &run_opts);
			have_reuse_retval = ASSERT_OK(err, "usercnt_reuse_run");
		}

		/* Drop the outer reference even if a callback retains the program. */
		err = bpf_map_delete_elem(outer_fd, &key);
		if (!ASSERT_OK(err, "outer_slot_clear") || !have_reuse_retval)
			break;

		retval = (__s32)run_opts.retval;
		if (retval == WQ_USERCNT_RETRY)
			continue;
		ASSERT_EQ(retval, (__s32)-EPERM, "usercnt_setter_ret");
		break;
	}

	ASSERT_LT(attempt, WQ_USERCNT_MAX_ATTEMPTS, "usercnt_reuse_hit");
destroy:
	wq__destroy(skel);
restore:
	err = sched_setaffinity(0, sizeof(old_mask), &old_mask);
	ASSERT_OK(err, "restore_affinity");
}

void serial_test_wq(void)
{
	struct wq *wq_skel = NULL;
	int err, prog_fd, i;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	RUN_TESTS(wq);

	/* re-run the success test to check if the timer was actually executed */

	wq_skel = wq__open_and_load();
	if (!ASSERT_OK_PTR(wq_skel, "wq__open_and_load"))
		goto clean_up;

	err = wq__attach(wq_skel);
	if (!ASSERT_OK(err, "wq_attach"))
		goto clean_up;

	prog_fd = bpf_program__fd(wq_skel->progs.test_syscall_array_sleepable);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "test_run") || !ASSERT_EQ(topts.retval, 0, "test_run"))
		goto clean_up;

	/* wait for wq callback to finish and fail instead of hanging if it never runs */
	for (i = 0; i < CALLBACK_WAIT_RETRIES && !READ_ONCE(wq_skel->bss->ok_sleepable); i++)
		usleep(CALLBACK_WAIT_US);
	ASSERT_EQ(wq_skel->bss->ok_sleepable, (1 << 1), "ok_sleepable");
clean_up:
	wq__destroy(wq_skel);

	if (test__start_subtest("usercnt_reuse"))
		test_wq_usercnt_reuse();
}

void serial_test_failures_wq(void)
{
	RUN_TESTS(wq_failures);
}

static void test_failure_map_no_btf(void)
{
	struct wq *skel = NULL;
	char log[8192];
	const struct bpf_insn *insns;
	size_t insn_cnt;
	int ret, err, map_fd;
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .log_size = sizeof(log), .log_buf = log,
		    .log_level = 2);

	skel = wq__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	err = bpf_object__prepare(skel->obj);
	if (!ASSERT_OK(err, "skel__prepare"))
		goto out;

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "map_no_btf", sizeof(__u32), sizeof(__u64), 100,
				NULL);
	if (!ASSERT_GT(map_fd, -1, "map create"))
		goto out;

	err = bpf_map__reuse_fd(skel->maps.array, map_fd);
	close(map_fd);
	if (!ASSERT_OK(err, "map reuse fd"))
		goto out;

	insns = bpf_program__insns(skel->progs.test_map_no_btf);
	if (!ASSERT_OK_PTR(insns, "insns ptr"))
		goto out;

	insn_cnt = bpf_program__insn_cnt(skel->progs.test_map_no_btf);
	if (!ASSERT_GT(insn_cnt, 0u, "insn cnt"))
		goto out;

	ret = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, NULL, "GPL", insns, insn_cnt, &opts);
	if (!ASSERT_LT(ret, 0, "prog load failed")) {
		if (ret > 0)
			close(ret);
		goto out;
	}

	ASSERT_HAS_SUBSTR(log, "map 'map_no_btf' has to have BTF in order to use bpf_wq",
			  "log complains no map BTF");
out:
	wq__destroy(skel);
}

void test_wq_custom(void)
{
	if (test__start_subtest("test_failure_map_no_btf"))
		test_failure_map_no_btf();
}
