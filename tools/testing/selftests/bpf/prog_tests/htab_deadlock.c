// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 DiDi Global Inc. */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <test_progs.h>

#include "htab_deadlock.skel.h"

static int perf_event_open(void)
{
	struct perf_event_attr attr = {0};
	int pfd;

	/* create perf event on CPU 0 */
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.freq = 1;
	attr.sample_freq = 1000;
	pfd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);

	return pfd >= 0 ? pfd : -errno;
}

void test_htab_deadlock(void)
{
	unsigned int val = 0, key = 20;
	struct bpf_link *link = NULL;
	struct htab_deadlock *skel;
	int err, i, pfd;
	cpu_set_t cpus;

	skel = htab_deadlock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = htab_deadlock__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto clean_skel;

	/* NMI events. */
	pfd = perf_event_open();
	if (pfd < 0) {
		if (pfd == -ENOENT || pfd == -EOPNOTSUPP) {
			printf("%s:SKIP:no PERF_COUNT_HW_CPU_CYCLES\n", __func__);
			test__skip();
			goto clean_skel;
		}
		if (!ASSERT_GE(pfd, 0, "perf_event_open"))
			goto clean_skel;
	}

	link = bpf_program__attach_perf_event(skel->progs.bpf_empty, pfd);
	if (!ASSERT_OK_PTR(link, "attach_perf_event"))
		goto clean_pfd;

	/* Pinned on CPU 0 */
	CPU_ZERO(&cpus);
	CPU_SET(0, &cpus);
	pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus);

	/* update bpf map concurrently on CPU0 in NMI and Task context.
	 * there should be no kernel deadlock.
	 */
	for (i = 0; i < 100000; i++)
		bpf_map_update_elem(bpf_map__fd(skel->maps.htab),
				    &key, &val, BPF_ANY);

	bpf_link__destroy(link);
clean_pfd:
	close(pfd);
clean_skel:
	htab_deadlock__destroy(skel);
}
