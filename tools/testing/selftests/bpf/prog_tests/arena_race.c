// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <sys/syscall.h>
#include <test_progs.h>

#include "arena_race.skel.h"

struct free_thread_ctx {
	struct arena_race *skel;
	int err;
	__u32 retval;
};

struct fault_thread_ctx {
	__u64 *addr;
	int stop;
};

static int run_prog(struct bpf_program *prog, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	return ASSERT_OK(err, name) && ASSERT_OK(opts.retval, name) ? 0 : -1;
}

/* Trigger the sleepable free page path. */
static void *run_free_thread(void *arg)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct free_thread_ctx *ctx = arg;

	ctx->skel->bss->target_tid = sys_gettid();
	ctx->err = bpf_prog_test_run_opts(
		bpf_program__fd(ctx->skel->progs.free_page), &opts);
	ctx->retval = opts.retval;
	return NULL;
}

/* Continuously fault in the address. */
static void *fault_reader_thread(void *arg)
{
	struct fault_thread_ctx *ctx = arg;

	while (!READ_ONCE(ctx->stop))
		(void)READ_ONCE(*ctx->addr);
	return NULL;
}

static int wait_for(int *p)
{
	__u64 deadline = get_time_ns() + 5ULL * 1000 * 1000 * 1000;

	while (!READ_ONCE(*p)) {
		if (get_time_ns() > deadline)
			return -ETIMEDOUT;
	}
	return 0;
}

static struct arena_race *setup_arena(__u64 **addr)
{
	struct arena_race *skel;
	size_t arena_sz;
	char *base;
	int err;

	skel = arena_race__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return NULL;

	err = arena_race__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto err_out;
	err = arena_race__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto err_out;

	if (run_prog(skel->progs.alloc_old, "alloc_old"))
		goto err_out;
	if (skel->bss->skip) {
		test__skip();
		goto err_out;
	}

	base = bpf_map__initial_value(skel->maps.arena, &arena_sz);
	if (!ASSERT_OK_PTR(base, "arena_base"))
		goto err_out;
	*addr = (__u64 *)(base + getpagesize());
	if (!ASSERT_EQ((unsigned long)skel->bss->ptr, (unsigned long)*addr,
		       "arena_ptr"))
		goto err_out;
	return skel;

err_out:
	arena_race__destroy(skel);
	return NULL;
}

static void test_free_before_flush(bool deferred)
{
	struct free_thread_ctx ctx = {};
	struct arena_race *skel;
	pthread_t thread;
	__u64 *addr;
	bool thread_created = false, flush_seen = false, completed = false;
	int err;

	skel = setup_arena(&addr);
	if (!skel)
		return;

	/* Pause during a TLB flush to widen the race window. */
	skel->bss->pause_on_flush = 1;

	if (deferred) {
		/*
		 * Test the nonsleepable free path that gets
		 * deferred to a worker in the kernel. We do
		 * so by triggering the arena operation from
		 * a nonsleepable tracepoint context.
		 */
		skel->bss->trigger_pid_tgid =
			((__u64)getpid() << 32) | (__u32)sys_gettid();
		skel->bss->trigger_syscall = SYS_getpgid;
		skel->bss->deferred_free = 1;
		if (!ASSERT_GE(syscall(SYS_getpgid, 0), 0, "deferred_free"))
			goto release;
	} else {
		/*
		 * Test the sleepable arena free path through a
		 * syscall test prog.
		 */
		ctx.skel = skel;
		err = pthread_create(&thread, NULL, run_free_thread, &ctx);
		if (!ASSERT_OK(err, "pthread_create")) {
			skel->bss->release = 1;
			goto out;
		}
		thread_created = true;
	}

	/* Wait until the worker thread triggers a flush. */
	err = wait_for(&skel->bss->flush_entered);
	if (!ASSERT_OK(err, "flush_entered"))
		goto release;

	flush_seen = true;

	/* Force a reallocation during the flush. */
	run_prog(skel->progs.try_realloc, "realloc_before_flush");
	ASSERT_NULL(skel->bss->realloc_ptr, "realloc_before_flush");

release:
	skel->bss->release = 1;
	if (thread_created) {
		ASSERT_OK(pthread_join(thread, NULL), "pthread_join");
		thread_created = false;
		completed = ASSERT_OK(ctx.err, "free_run") &&
			    ASSERT_OK(ctx.retval, "free_retval");
	} else if (skel->bss->target_tid) {
		err = wait_for(&skel->bss->worker_exited);
		completed = ASSERT_OK(err, "worker_exited");
	}
	ASSERT_FALSE(skel->bss->timed_out, "flush_timed_out");

	if (flush_seen && completed &&
	    !run_prog(skel->progs.try_realloc, "realloc_after_flush")) {
		ASSERT_EQ((unsigned long)skel->bss->realloc_ptr,
			  (unsigned long)addr, "realloc_after_flush");
		ASSERT_EQ(*addr, skel->rodata->new_marker, "new_marker");
	}
out:

	if (thread_created)
		pthread_join(thread, NULL);

	arena_race__destroy(skel);
}

/*
 * Force a race between a faulting thread in userspace and a
 * free operation on the arena.
 */
static void test_fault_free_realloc(void)
{
	struct fault_thread_ctx fault = {};
	struct arena_race *skel;
	pthread_t fault_thread;
	bool fault_created = false;
	__u64 *addr;
	__u64 expected, value;
	int err, i;

	skel = setup_arena(&addr);
	if (!skel)
		return;

	skel->bss->realloc_after_free = 1;

	fault.addr = addr;
	err = pthread_create(&fault_thread, NULL, fault_reader_thread, &fault);
	if (!ASSERT_OK(err, "pthread_create_fault"))
		goto out;
	fault_created = true;

	for (i = 0; i < 1000 && !READ_ONCE(fault.stop); i++) {
		LIBBPF_OPTS(bpf_test_run_opts, opts);

		err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.free_page),
					     &opts);
		if (err) {
			ASSERT_OK(err, "free_realloc");
			break;
		}
		if (opts.retval) {
			ASSERT_OK(opts.retval, "free_realloc");
			break;
		}
		value = *addr;
		expected = skel->bss->current_marker;
		if (value != expected) {
			ASSERT_EQ(value, expected, "marker_after_realloc");
			break;
		}
	}

	WRITE_ONCE(fault.stop, 1);
	if (fault_created) {
		ASSERT_OK(pthread_join(fault_thread, NULL), "pthread_join_fault");
		fault_created = false;
	}
	ASSERT_GE(i, 1, "race_iterations");
out:
	WRITE_ONCE(fault.stop, 1);
	if (fault_created)
		pthread_join(fault_thread, NULL);
	arena_race__destroy(skel);
}

void serial_test_arena_race(void)
{
	if (test__start_subtest("free_before_flush"))
		test_free_before_flush(false);
	if (test__start_subtest("deferred_free_before_flush"))
		test_free_before_flush(true);
	if (test__start_subtest("fault_free_realloc"))
		test_fault_free_realloc();
}
