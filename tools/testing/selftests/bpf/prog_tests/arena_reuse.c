// SPDX-License-Identifier: GPL-2.0

#include <stdatomic.h>
#include <sys/sysinfo.h>
#include <test_progs.h>

#include "arena_reuse.skel.h"

#define MAX_ALLOCATORS 15
#define ROUNDS 20000

struct reuse_ctx {
	pthread_barrier_t start;
	pthread_barrier_t done;
	pthread_barrier_t next;
	atomic_int err;
	int prime_fd;
};

struct thread_ctx {
	struct reuse_ctx *shared;
	int action_fd;
	int cpu;
	bool allocator;
};

static int run_prog(int fd)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(fd, &opts);
	if (err)
		return err;
	return opts.retval ? -EUCLEAN : 0;
}

static void *reuse_thread(void *arg)
{
	struct thread_ctx *ctx = arg;
	struct reuse_ctx *shared = ctx->shared;
	cpu_set_t cpuset;
	int err, round;

	CPU_ZERO(&cpuset);
	CPU_SET(ctx->cpu, &cpuset);
	err = pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
	if (err) {
		atomic_store(&shared->err, err);
		return NULL;
	}

	for (round = 0; round < ROUNDS; round++) {
		if (ctx->allocator && !atomic_load(&shared->err)) {
			err = run_prog(shared->prime_fd);
			if (err)
				atomic_store(&shared->err, err);
		}
		pthread_barrier_wait(&shared->start);
		if (!atomic_load(&shared->err)) {
			err = run_prog(ctx->action_fd);
			if (err)
				atomic_store(&shared->err, err);
		}
		pthread_barrier_wait(&shared->done);
		pthread_barrier_wait(&shared->next);
	}
	return NULL;
}

static void test_arena_reuse(bool deferred_free)
{
	struct arena_reuse *skel;
	struct reuse_ctx ctx = {};
	struct thread_ctx tctx[MAX_ALLOCATORS + 1];
	pthread_t threads[MAX_ALLOCATORS + 1];
	int nr_allocators, nr_threads;
	int check_fd, init_fd;
	int i, err, round;

	nr_allocators = MIN(get_nprocs() - 1, MAX_ALLOCATORS);
	if (nr_allocators < 1) {
		test__skip();
		return;
	}
	nr_threads = nr_allocators + 1;

	skel = arena_reuse__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	skel->rodata->deferred_free = deferred_free;
	if (!ASSERT_OK(arena_reuse__load(skel), "load")) {
		arena_reuse__destroy(skel);
		return;
	}

	init_fd = bpf_program__fd(skel->progs.init_page);
	check_fd = bpf_program__fd(skel->progs.check_page);
	if (!ASSERT_OK(run_prog(init_fd), "init_page"))
		goto out;

	pthread_barrier_init(&ctx.start, NULL, nr_threads + 1);
	pthread_barrier_init(&ctx.done, NULL, nr_threads + 1);
	pthread_barrier_init(&ctx.next, NULL, nr_threads + 1);
	ctx.prime_fd = bpf_program__fd(skel->progs.prime_tlb);
	atomic_init(&ctx.err, 0);

	for (i = 0; i < nr_threads; i++) {
		tctx[i].shared = &ctx;
		tctx[i].cpu = i;
		tctx[i].allocator = i != nr_allocators;
		tctx[i].action_fd = bpf_program__fd(tctx[i].allocator ?
						   skel->progs.alloc_page :
						   skel->progs.free_page);
		err = pthread_create(&threads[i], NULL, reuse_thread, &tctx[i]);
		if (!ASSERT_OK(err, "pthread_create"))
			goto join;
	}

	for (round = 0; round < ROUNDS; round++) {
		skel->bss->alloc_wins = 0;
		pthread_barrier_wait(&ctx.start);
		pthread_barrier_wait(&ctx.done);

		if (atomic_load(&ctx.err))
			goto next;
		if (skel->bss->alloc_wins > 1) {
			atomic_store(&ctx.err, -EUCLEAN);
			goto next;
		}
		if (!skel->bss->alloc_wins) {
			for (i = 0; i < 1000 && run_prog(init_fd); i++)
				usleep(10);
			if (i == 1000)
				atomic_store(&ctx.err, -EIO);
			goto next;
		}
		err = run_prog(check_fd);
		if (err) {
			fprintf(stderr, "arena reuse corruption at round %d\n", round);
			atomic_store(&ctx.err, err);
		}
next:
		pthread_barrier_wait(&ctx.next);
	}

join:
	for (i = 0; i < nr_threads; i++)
		pthread_join(threads[i], NULL);

	ASSERT_OK(atomic_load(&ctx.err), "concurrent arena reuse");
	pthread_barrier_destroy(&ctx.next);
	pthread_barrier_destroy(&ctx.done);
	pthread_barrier_destroy(&ctx.start);
out:
	arena_reuse__destroy(skel);
}

void serial_test_arena_reuse(void)
{
	if (test__start_subtest("sleepable"))
		test_arena_reuse(false);
	if (test__start_subtest("deferred"))
		test_arena_reuse(true);
}
