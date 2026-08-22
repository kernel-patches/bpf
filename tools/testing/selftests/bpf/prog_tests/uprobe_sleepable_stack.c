// SPDX-License-Identifier: GPL-2.0
/*
 * Test that preemptible uprobe programs don't use private stack.
 *
 * Private stack is per-CPU and per-program, so preemption during a program's
 * execution would allow another task to corrupt the stack. The verifier must
 * disable private stack for programs whose invocation can be preempted.
 *
 * This test overlaps two invocations of the same uprobe program on the same
 * CPU and verifies:
 * 1. Both invocations execute
 * 2. No stack corruption occurs (each task has its own stack frame)
 */
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include <test_progs.h>
#include "uprobe_sleepable_stack.skel.h"

static noinline void uprobe_sleepable_stack_trigger(void)
{
	asm volatile("");
}

static void *trigger_uprobe(void *arg)
{
	uprobe_sleepable_stack_trigger();
	return NULL;
}

static void reset_state(struct uprobe_sleepable_stack *skel)
{
	skel->bss->ready = 0;
	skel->bss->release = 0;
	skel->bss->executions = 0;
	skel->bss->corruptions = 0;
	skel->bss->loop_exhausted = 0;
}

static void assert_results(struct uprobe_sleepable_stack *skel)
{
	ASSERT_EQ(skel->bss->loop_exhausted, 0, "loop_exhausted");
	ASSERT_EQ(skel->bss->executions, 2, "executions");
	ASSERT_EQ(skel->bss->corruptions, 0, "corruptions");
}

static void run_test(struct uprobe_sleepable_stack *skel, bool multi,
		     bool large_stack)
{
	LIBBPF_OPTS(bpf_uprobe_opts, opts);
	LIBBPF_OPTS(bpf_uprobe_multi_opts, multi_opts);
	const char *binary = "/proc/self/exe";
	struct bpf_program *prog;
	struct bpf_link *link;
	pthread_t thread;
	long link_err;
	int err, i;

	reset_state(skel);

	if (multi) {
		prog = large_stack ? skel->progs.uprobe_multi_sleepable_large_stack :
					     skel->progs.uprobe_multi_sleepable_small_stack;
		link = bpf_program__attach_uprobe_multi(
			prog, 0, binary, "uprobe_sleepable_stack_trigger",
			&multi_opts);
	} else {
		opts.func_name = "uprobe_sleepable_stack_trigger";
		prog = large_stack ? skel->progs.uprobe_sleepable_large_stack :
					     skel->progs.uprobe_sleepable_small_stack;
		link = bpf_program__attach_uprobe_opts(prog, 0, binary, 0,
						       &opts);
	}

	link_err = libbpf_get_error(link);
	if (link_err == -EOPNOTSUPP) {
		test__skip();
		return;
	}
	if (!ASSERT_OK_PTR(link, "attach_uprobe"))
		return;

	err = pthread_create(&thread, NULL, trigger_uprobe, NULL);
	if (!ASSERT_OK(err, "pthread_create"))
		goto cleanup;

	for (i = 0; i < 10000; i++) {
		if (__atomic_load_n(&skel->bss->ready, __ATOMIC_ACQUIRE))
			break;
		usleep(1000);
	}

	if (ASSERT_LT(i, 10000, "first_uprobe_ready"))
		uprobe_sleepable_stack_trigger();
	__atomic_store_n(&skel->bss->release, 1, __ATOMIC_RELEASE);

	err = pthread_join(thread, NULL);
	if (!ASSERT_OK(err, "pthread_join"))
		goto cleanup;

	assert_results(skel);

cleanup:
	bpf_link__destroy(link);
}

void test_uprobe_sleepable_stack(void)
{
	struct uprobe_sleepable_stack *skel = NULL;
	cpu_set_t old_mask, mask;
	bool affinity_set = false;
	int cpu;

#if !defined(__x86_64__) && !defined(__aarch64__) && !defined(__powerpc64__)
	test__skip();
	return;
#endif
	if (!env.jit_enabled) {
		test__skip();
		return;
	}

	if (!ASSERT_OK(sched_getaffinity(0, sizeof(old_mask), &old_mask),
		       "get_affinity"))
		return;

	CPU_ZERO(&mask);
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &old_mask)) {
			CPU_SET(cpu, &mask);
			break;
		}
	}
	if (!ASSERT_LT(cpu, CPU_SETSIZE, "available_cpu"))
		return;
	/* Both triggers must run on the same CPU to test stack sharing */
	if (!ASSERT_OK(sched_setaffinity(0, sizeof(mask), &mask),
		       "set_affinity"))
		return;
	affinity_set = true;

	skel = uprobe_sleepable_stack__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;
	if (!skel->kconfig->CONFIG_PREEMPTION) {
		test__skip();
		goto cleanup;
	}

	if (test__start_subtest("sleepable_classic_large"))
		run_test(skel, false, true);
	if (test__start_subtest("sleepable_classic_small"))
		run_test(skel, false, false);
	if (test__start_subtest("sleepable_multi_large"))
		run_test(skel, true, true);
	if (test__start_subtest("sleepable_multi_small"))
		run_test(skel, true, false);

cleanup:
	uprobe_sleepable_stack__destroy(skel);
	if (affinity_set)
		ASSERT_OK(sched_setaffinity(0, sizeof(old_mask), &old_mask),
			  "restore_affinity");
}
