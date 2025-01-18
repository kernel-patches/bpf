// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <network_helpers.h>

struct qspinlock { int val; };

#include "arena_spin_lock.skel.h"

static long cpu;
int *counter;

static void *spin_lock_thread(void *arg)
{
	int err, prog_fd = *(u32 *) arg;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(__sync_fetch_and_add(&cpu, 1), &cpuset);
	ASSERT_OK(pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset), "cpu affinity");

	while (*READ_ONCE(counter) <= 50) {
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "test_run err");
		ASSERT_EQ(topts.retval, 1, "test_run retval");
	}
	pthread_exit(arg);
}

void test_arena_spin_lock(void)
{
	struct arena_spin_lock *skel;
	pthread_t thread_id[16];
	int prog_fd, i, err;
	void *ret;

	skel = arena_spin_lock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_spin_lock__open_and_load"))
		return;
	if (skel->data->test_skip == 2) {
		test__skip();
		goto end;
	}

	counter = &skel->bss->counter;

	prog_fd = bpf_program__fd(skel->progs.prog);
	for (i = 0; i < 16; i++) {
		err = pthread_create(&thread_id[i], NULL, &spin_lock_thread, &prog_fd);
		if (!ASSERT_OK(err, "pthread_create"))
			goto end;
	}

	for (i = 0; i < 16; i++) {
		if (!ASSERT_OK(pthread_join(thread_id[i], &ret), "pthread_join"))
			goto end;
		if (!ASSERT_EQ(ret, &prog_fd, "ret == prog_fd"))
			goto end;
	}
end:
	arena_spin_lock__destroy(skel);
	return;
}
