// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <sched.h>
#include <test_progs.h>
#include <pthread.h>
#include <network_helpers.h>
#include "timer_lockup.skel.h"

long cpu;
int *timer1_err;
int *timer2_err;

static void *timer_lockup_thread(void *arg)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 10000,
	);
	int prog_fd = *(int *)arg;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(__sync_fetch_and_add(&cpu, 1), &cpuset);
	ASSERT_OK(pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset), "cpu affinity");

	while (!*timer1_err && !*timer2_err)
		bpf_prog_test_run_opts(prog_fd, &opts);

	return NULL;
}

void test_timer_lockup(void)
{
	struct timer_lockup *skel;
	pthread_t thrds[2];
	void *ret;

	skel = timer_lockup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "timer_lockup__open_and_load"))
		return;

	int timer1_prog = bpf_program__fd(skel->progs.timer1_prog);
	int timer2_prog = bpf_program__fd(skel->progs.timer2_prog);

	timer1_err = &skel->bss->timer1_err;
	timer2_err = &skel->bss->timer2_err;

	if (!ASSERT_OK(pthread_create(&thrds[0], NULL, timer_lockup_thread, &timer1_prog), "pthread_create thread1"))
		return;
	if (!ASSERT_OK(pthread_create(&thrds[1], NULL, timer_lockup_thread, &timer2_prog), "pthread_create thread2")) {
		pthread_exit(&thrds[0]);
		return;
	}

	pthread_join(thrds[1], &ret);
	pthread_join(thrds[0], &ret);

	if (*timer1_err != -EDEADLK && *timer1_err != 0)
		ASSERT_FAIL("timer1_err bad value");
	if (*timer2_err != -EDEADLK && *timer2_err != 0)
		ASSERT_FAIL("timer2_err bad value");

	return;
}
