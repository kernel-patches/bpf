// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

/*
 * Stress test for timer ctx leak on non-preallocated hash maps.
 *
 * The race:
 *   cancel_and_free:                  concurrent BPF program:
 *     xchg(&cb, NULL)
 *     free old cb
 *                                     __bpf_async_init: READ_ONCE(cb) == NULL
 *                                     allocates NEW cb
 *                                     cmpxchg(&cb, NULL, new_cb) succeeds
 *                                     element freed -> cb LEAKED
 *
 * Multiple threads hammer insert+timer_init vs delete on the same
 * non-preallocated hash map.  kmemleak or explicit counters should
 * detect the leaked bpf_async_cb allocations.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <test_progs.h>
#include "timer_leak.skel.h"

struct thread_ctx {
	int prog_fd;
	volatile bool start;
	volatile bool stop;
	int errors;
};

static void *worker(void *arg)
{
	struct thread_ctx *ctx = arg;

	while (!ctx->start && !ctx->stop)
		usleep(1);

	while (!ctx->stop) {
		LIBBPF_OPTS(bpf_test_run_opts, opts);
		int err;

		err = bpf_prog_test_run_opts(ctx->prog_fd, &opts);
		if (err || opts.retval) {
			ctx->errors++;
			break;
		}
	}

	return NULL;
}

void test_timer_leak(void)
{
	int nthreads_init = 10, nthreads_del = 5;
	int total = nthreads_init + nthreads_del;
	pthread_t tids[total];
	struct thread_ctx ctxs[total];
	struct timer_leak *skel;
	int i, err;

	skel = timer_leak__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	for (i = 0; i < total; i++) {
		ctxs[i].start = false;
		ctxs[i].stop = false;
		ctxs[i].errors = 0;

		if (i < nthreads_init)
			ctxs[i].prog_fd = bpf_program__fd(skel->progs.insert_and_init_timer);
		else
			ctxs[i].prog_fd = bpf_program__fd(skel->progs.delete_elem);

		err = pthread_create(&tids[i], NULL, worker, &ctxs[i]);
		if (!ASSERT_OK(err, "pthread_create")) {
			for (int j = 0; j < i; j++) {
				ctxs[j].stop = true;
				pthread_join(tids[j], NULL);
			}
			goto cleanup;
		}
	}

	/* release all threads */
	for (i = 0; i < total; i++)
		ctxs[i].start = true;

	sleep(2);

	for (i = 0; i < total; i++)
		ctxs[i].stop = true;
	for (i = 0; i < total; i++)
		pthread_join(tids[i], NULL);

	for (i = 0; i < total; i++)
		ASSERT_EQ(ctxs[i].errors, 0, "thread_errors");

	ASSERT_GT(skel->bss->init_success, 0, "init_success");
	ASSERT_GT(skel->bss->delete_success, 0, "delete_success");

	/*
	 * If there is a leak, kmemleak scan will catch it, or
	 * check /sys/kernel/debug/kmemleak after running this test.
	 */

cleanup:
	timer_leak__destroy(skel);
}
