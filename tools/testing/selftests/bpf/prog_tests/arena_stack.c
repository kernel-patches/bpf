// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <test_progs.h>
#include <pthread.h>
#include <sched.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include "arena_stack.skel.h"
#include "arena_stack_nomem.skel.h"
#include "arena_stack_fentry.skel.h"
#include "arena_stack_loop.skel.h"

static int run_prog(int fd)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);

	if (bpf_prog_test_run_opts(fd, &opts))
		return -1;
	return opts.retval;
}

static int run_tc_prog(int fd)
{
	char pkt[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = pkt, .data_size_in = sizeof(pkt));

	if (bpf_prog_test_run_opts(fd, &opts))
		return -1;
	return opts.retval;
}

static int pin_to_cpu0(cpu_set_t *old)
{
	cpu_set_t set;

	if (sched_getaffinity(0, sizeof(*old), old))
		return -1;
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

#define NR_THREADS 8
#define NR_RUNS 20

static int preempted_fd;

static void *preempted_thread(void *arg)
{
	long bad = 0;
	int i;

	for (i = 0; i < NR_RUNS; i++)
		bad += run_prog(preempted_fd) != 0;
	return (void *)bad;
}

/* Programs on one cpu preempt each other. They don't exit in the order they started. */
static void test_preemption(struct arena_stack *skel)
{
	pthread_t thread[NR_THREADS];
	long bad = 0;
	cpu_set_t old;
	void *ret;
	int i, n;

	if (!ASSERT_OK(pin_to_cpu0(&old), "pin"))
		return;
	preempted_fd = bpf_program__fd(skel->progs.preempted);
	/* threads inherit the affinity */
	for (n = 0; n < NR_THREADS; n++)
		if (!ASSERT_OK(pthread_create(&thread[n], NULL, preempted_thread, NULL), "thread"))
			break;
	for (i = 0; i < n; i++) {
		pthread_join(thread[i], &ret);
		bad += (long)ret;
	}
	ASSERT_EQ(bad, 0, "runs with a corrupted frame");
	sched_setaffinity(0, sizeof(old), &old);
}

/* A program that runs with preemption disabled is interrupted by a program in the timer interrupt */
static void test_nesting(struct arena_stack *skel)
{
	struct perf_event_attr attr = {
		.size = sizeof(attr),
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
		.sample_period = 50000, /* nsec */
	};
	struct bpf_link *link = NULL;
	int i, pfd, bad = 0;
	cpu_set_t old;

	if (!ASSERT_OK(pin_to_cpu0(&old), "pin"))
		return;
	pfd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
	if (!ASSERT_GE(pfd, 0, "perf_event_open"))
		goto out;
	link = bpf_program__attach_perf_event(skel->progs.in_interrupt, pfd);
	if (!ASSERT_OK_PTR(link, "attach_perf_event")) {
		close(pfd);
		goto out;
	}
	for (i = 0; i < 200; i++)
		bad += run_tc_prog(bpf_program__fd(skel->progs.interrupted)) != 0;
	ASSERT_EQ(bad, 0, "runs with a corrupted frame");
	/* the program was interrupted */
	ASSERT_GT(skel->bss->interrupts, 10, "interrupts");
	bpf_link__destroy(link);
out:
	sched_setaffinity(0, sizeof(old), &old);
}

/* bpf_throw() doesn't return the stack. Programs run when all stacks of the cpu are taken. */
static void test_throw(struct arena_stack *skel)
{
	cpu_set_t old;
	int i;

	if (!ASSERT_OK(pin_to_cpu0(&old), "pin"))
		return;
	for (i = 0; i < 40; i++)
		run_prog(bpf_program__fd(skel->progs.throws));
	for (i = 0; i < 40; i++)
		if (!ASSERT_EQ(run_prog(bpf_program__fd(skel->progs.prog_returns_7)), 7, "returns_7"))
			break;
	/* the same with preemption disabled */
	for (i = 0; i < 200; i++)
		run_tc_prog(bpf_program__fd(skel->progs.throws_nested));
	for (i = 0; i < 40; i++)
		if (!ASSERT_EQ(run_tc_prog(bpf_program__fd(skel->progs.returns_8_nested)), 8,
			       "returns_8_nested"))
			break;
	sched_setaffinity(0, sizeof(old), &old);
}

/* A callback that the kernel calls takes a stack of its own */
static void test_timer(struct arena_stack *skel)
{
	int i, j;

	for (i = 0; i < 100; i++) {
		if (!ASSERT_OK(run_prog(bpf_program__fd(skel->progs.start_timer)), "start_timer"))
			return;
		for (j = 0; j < 1000 && skel->bss->timer_runs <= i; j++)
			usleep(100);
	}
	ASSERT_EQ(skel->bss->timer_runs, 100, "runs of the callback");
	ASSERT_EQ(skel->bss->timer_bad, 0, "runs with a wrong frame");
}

static void test_attach_to_subprog(struct arena_stack *skel)
{
	struct arena_stack_fentry *fentry;
	int tgt_fd = bpf_program__fd(skel->progs.preempted);

	/* the main program is fine */
	fentry = arena_stack_fentry__open();
	if (!ASSERT_OK_PTR(fentry, "open"))
		return;
	ASSERT_OK(bpf_program__set_attach_target(fentry->progs.on_entry, tgt_fd, "preempted"),
		  "set_attach_target");
	ASSERT_OK(arena_stack_fentry__load(fentry), "load for the main program");
	arena_stack_fentry__destroy(fentry);

	fentry = arena_stack_fentry__open();
	if (!ASSERT_OK_PTR(fentry, "open"))
		return;
	ASSERT_OK(bpf_program__set_attach_target(fentry->progs.on_entry, tgt_fd, "spin"),
		  "set_attach_target");
	ASSERT_ERR(arena_stack_fentry__load(fentry), "load for a subprog");
	arena_stack_fentry__destroy(fentry);
}

/* The insns that take the stack are in front of the first insn. A jump to it doesn't run them. */
static void test_jump_to_first_insn(void)
{
	struct arena_stack_loop *skel;
	cpu_set_t old;
	int i;

	skel = arena_stack_loop__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (!ASSERT_OK(pin_to_cpu0(&old), "pin"))
		goto out;
	for (i = 0; i < 1000; i++) {
		if (!ASSERT_EQ(run_tc_prog(bpf_program__fd(skel->progs.loop)), 7, "loop"))
			break;
		if (!ASSERT_EQ(run_tc_prog(bpf_program__fd(skel->progs.nop_loop)), 7, "nop_loop"))
			break;
	}
	sched_setaffinity(0, sizeof(old), &old);
out:
	arena_stack_loop__destroy(skel);
}

static void test_no_memory(void)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct arena_stack_nomem *skel;
	char buf[256] = {};
	int fd;

	skel = arena_stack_nomem__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	fd = bpf_program__fd(skel->progs.returns_1);
	ASSERT_EQ(run_prog(fd), 0, "retval");
	ASSERT_EQ(skel->bss->runs, 0, "runs");
	ASSERT_OK(bpf_prog_get_info_by_fd(fd, &info, &info_len), "info");
	ASSERT_EQ(info.recursion_misses, 1, "misses");
	ASSERT_GT(bpf_prog_stream_read(fd, BPF_STREAM_STDERR, buf, sizeof(buf) - 1, NULL), 0,
		  "stream_read");
	ASSERT_HAS_SUBSTR(buf, "No memory for the stack in arena", "stderr");
	arena_stack_nomem__destroy(skel);
}

void test_arena_stack(void)
{
	struct arena_stack *skel;

#if !defined(__x86_64__) && !defined(__aarch64__)
	/* other JITs don't support r12 */
	test__skip();
	return;
#endif
	skel = arena_stack__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (test__start_subtest("preemption"))
		test_preemption(skel);
	if (test__start_subtest("nesting"))
		test_nesting(skel);
	if (test__start_subtest("attach_to_subprog"))
		test_attach_to_subprog(skel);
	if (test__start_subtest("timer"))
		test_timer(skel);
	if (test__start_subtest("throw"))
		test_throw(skel);
	arena_stack__destroy(skel);
	if (test__start_subtest("jump_to_first_insn"))
		test_jump_to_first_insn();
	if (test__start_subtest("no_memory"))
		test_no_memory();
}
