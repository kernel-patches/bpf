// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <sched.h>

#include <test_progs.h>
#include "rhash_timer.skel.h"

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

static int update_timer_map(int map_fd, __u64 key)
{
	__u64 value[3] = {};

	return bpf_map_update_elem(map_fd, &key, value, BPF_NOEXIST);
}

static int run_prog(int prog_fd, struct bpf_test_run_opts *opts)
{
	int err;

	err = bpf_prog_test_run_opts(prog_fd, opts);
	if (err)
		return err;
	return opts->retval;
}

void test_rhash_timer(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct rhash_timer *skel = NULL;
	cpu_set_t old_mask;
	int map_fd = -1, arm_del_fd, arm_live_fd, cancel_live_fd;
	bool affinity_set = false;
	__u64 key = 0, deadline;
	int err;

	err = pin_to_first_cpu(&old_mask);
	if (!ASSERT_OK(err, "pin_to_first_cpu"))
		return;
	affinity_set = true;

	skel = rhash_timer__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	map_fd = bpf_map__fd(skel->maps.timer_map);
	if (!ASSERT_GE(map_fd, 0, "timer_map fd"))
		goto out;
	arm_del_fd = bpf_program__fd(skel->progs.arm_deleted_timer);
	if (!ASSERT_GE(arm_del_fd, 0, "arm_deleted_timer fd"))
		goto out;
	arm_live_fd = bpf_program__fd(skel->progs.live_arm_timer);
	if (!ASSERT_GE(arm_live_fd, 0, "live_arm_timer fd"))
		goto out;
	cancel_live_fd = bpf_program__fd(skel->progs.cancel_live_timer);
	if (!ASSERT_GE(cancel_live_fd, 0, "cancel_live_timer fd"))
		goto out;

	if (test__start_subtest("deleted_init_rejected")) {
		err = update_timer_map(map_fd, key);
		if (!ASSERT_OK(err, "seed_deleted"))
			goto out;
		err = run_prog(arm_del_fd, &opts);
		if (!ASSERT_OK(err, "arm_deleted_timer"))
			goto out;
		ASSERT_EQ(skel->bss->timer_init_err, -ENOENT, "deleted_init_errno");
	}

	if (test__start_subtest("live_timer_roundtrip")) {
		err = update_timer_map(map_fd, key);
		if (!ASSERT_OK(err, "seed_live"))
			goto out;
		err = run_prog(arm_live_fd, &opts);
		if (!ASSERT_OK(err, "live_arm_timer"))
			goto out;
		ASSERT_EQ(skel->bss->live_armed, 1, "live_armed");
		ASSERT_EQ(skel->bss->live_init_err, 0, "live_init_err");
		ASSERT_EQ(skel->bss->live_set_callback_err, 0,
			  "live_set_callback_err");
		ASSERT_EQ(skel->bss->live_start_err, 0, "live_start_err");

		deadline = get_time_ns() + 2000000000ULL;
		while (!__atomic_load_n(&skel->bss->live_cb_cnt, __ATOMIC_ACQUIRE) &&
		       get_time_ns() < deadline)
			usleep(1000);
		ASSERT_GT(__atomic_load_n(&skel->bss->live_cb_cnt, __ATOMIC_ACQUIRE),
			  0, "live_callback");

		err = run_prog(cancel_live_fd, &opts);
		if (!ASSERT_OK(err, "cancel_live_timer"))
			goto out;
		ASSERT_EQ(skel->bss->live_cancel_err, 0, "live_cancel_err");
		ASSERT_GT(skel->bss->live_cancelled, 0, "live_cancelled");
	}
out:
	if (map_fd >= 0)
		bpf_map_delete_elem(map_fd, &key);
	rhash_timer__destroy(skel);
	if (affinity_set)
		sched_setaffinity(0, sizeof(old_mask), &old_mask);
}
