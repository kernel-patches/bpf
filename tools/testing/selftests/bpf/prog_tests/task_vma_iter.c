// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/libbpf.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include "task_vma_iter.skel.h"

struct map_ctx {
	struct task_vma_iter *skel;
	void *addr;
	int err;
};

static void *map_new_vma(void *arg)
{
	struct map_ctx *ctx = arg;
	struct task_vma_iter *skel = ctx->skel;
	void *addr;

	while (!__atomic_load_n(&skel->bss->drain_done, __ATOMIC_RELAXED))
		sched_yield();

	if (!skel->bss->new_ret) {
		addr = (void *)(unsigned long)skel->bss->last_end;
		ctx->addr = mmap(addr, getpagesize(), PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
				 -1, 0);
		if (ctx->addr == MAP_FAILED)
			ctx->err = errno;
	}

	__atomic_store_n(&skel->bss->go, 1, __ATOMIC_RELEASE);
	return NULL;
}

static void test_task_vma_iter_next_after_drain(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct task_vma_iter *skel;
	struct map_ctx ctx;
	pthread_t thread;
	int err, fd;

	skel = task_vma_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "task_vma_iter__open_and_load"))
		return;

	ctx.skel = skel;
	ctx.addr = NULL;
	ctx.err = 0;

	if (!ASSERT_OK(pthread_create(&thread, NULL, map_new_vma, &ctx),
		       "pthread_create"))
		goto out;

	fd = bpf_program__fd(skel->progs.iter_task_vma_next_after_drain);
	err = bpf_prog_test_run_opts(fd, &topts);
	if (err) {
		/* Release the mapper if the program never ran. */
		skel->bss->new_ret = -1;
		__atomic_store_n(&skel->bss->drain_done, 1, __ATOMIC_RELEASE);
		__atomic_store_n(&skel->bss->go, 1, __ATOMIC_RELEASE);
	}
	pthread_join(thread, NULL);

	if (!ASSERT_OK(err, "test_run_opts err"))
		goto out;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		goto out;

	ASSERT_OK(ctx.err, "mmap new VMA");
	ASSERT_OK(skel->bss->new_ret, "new_ret");
	ASSERT_GT(skel->bss->vma_count, 0, "vma_count");
	ASSERT_EQ(skel->bss->go_seen, 1, "go_seen");
	/* last_end is set, so a restarted walk would find the new VMA */
	ASSERT_EQ(skel->data->next_after_drain, 0, "next_after_drain");

out:
	if (ctx.addr && ctx.addr != MAP_FAILED)
		munmap(ctx.addr, getpagesize());
	task_vma_iter__destroy(skel);
}

void test_task_vma_iter(void)
{
	if (test__start_subtest("next_after_drain"))
		test_task_vma_iter_next_after_drain();
}
