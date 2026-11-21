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

static int run_wq_prog(int prog_fd, __s32 *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (err)
		return err;
	*retval = (__s32)opts.retval;
	return 0;
}

/* Check callback setup after reusing an idle object with no map uref. */
static void test_wq_usercnt_reuse(void)
{
	struct wq *skel = NULL;
	cpu_set_t old_mask;
	__s32 retval = 0;
	int stage_b_fd = -1;
	int err, attempt;

	if (!ASSERT_OK(pin_to_first_cpu(&old_mask), "pin"))
		return;

	for (attempt = 0; attempt < WQ_USERCNT_MAX_ATTEMPTS; attempt++) {
		skel = wq__open_and_load();
		if (!ASSERT_OK_PTR(skel, "wq__open_and_load"))
			break;

		err = run_wq_prog(bpf_program__fd(skel->progs.test_deleted_wq),
				  &retval);
		if (!ASSERT_OK(err, "test_deleted_wq_run") ||
		    !ASSERT_EQ(retval, (__s32)-ENOENT, "test_deleted_wq_ret"))
			break;

		stage_b_fd = dup(bpf_program__fd(skel->progs.test_wq_usercnt_reuse));
		if (!ASSERT_GE(stage_b_fd, 0, "dup_stage_b"))
			break;

		/* Drop all target-map user FDs; the retained program FD keeps
		 * the map alive through used_maps, but usercnt becomes zero.
		 */
		wq__destroy(skel);
		skel = NULL;

		err = run_wq_prog(stage_b_fd, &retval);
		close(stage_b_fd);
		if (!ASSERT_OK(err, "stage_b_run"))
			break;

		if (retval == WQ_USERCNT_RETRY) {
			/* The cached element was not reused; try again. */
			continue;
		}
		if (retval > 0) {
			ASSERT_FAIL("usercnt stage error %d", retval);
			break;
		}

		ASSERT_EQ(retval, (__s32)-EPERM, "usercnt_setter_ret");
		break;
	}

	if (attempt == WQ_USERCNT_MAX_ATTEMPTS)
		ASSERT_FAIL("usercnt reuse not hit after %d attempts",
			    WQ_USERCNT_MAX_ATTEMPTS);

	if (skel)
		wq__destroy(skel);
	sched_setaffinity(0, sizeof(old_mask), &old_mask);
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
