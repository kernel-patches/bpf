// SPDX-License-Identifier: GPL-2.0
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#include <test_progs.h>
#include "uprobe_private_stack.skel.h"

static noinline void uprobe_private_stack_trigger(void)
{
	asm volatile("");
}

static void *trigger_uprobe(void *arg)
{
	uprobe_private_stack_trigger();
	return NULL;
}

static void run_private_stack_test(struct uprobe_private_stack *skel, bool multi)
{
	LIBBPF_OPTS(bpf_uprobe_opts, opts);
	LIBBPF_OPTS(bpf_uprobe_multi_opts, multi_opts);
	const char *binary = "/proc/self/exe";
	struct bpf_program *prog;
	struct bpf_link *link;
	pthread_t thread;
	int err, i;

	skel->bss->ready = 0;
	skel->bss->release = 0;
	skel->bss->executions = 0;
	skel->bss->corruptions = 0;
	skel->bss->loop_exhausted = 0;

	if (multi) {
		prog = skel->progs.uprobe_multi_private_stack;
		link = bpf_program__attach_uprobe_multi(prog, 0, binary,
							"uprobe_private_stack_trigger",
							&multi_opts);
	} else {
		opts.func_name = "uprobe_private_stack_trigger";
		prog = skel->progs.uprobe_private_stack;
		link = bpf_program__attach_uprobe_opts(prog, 0, binary, 0, &opts);
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
		uprobe_private_stack_trigger();
	__atomic_store_n(&skel->bss->release, 1, __ATOMIC_RELEASE);

	err = pthread_join(thread, NULL);
	if (!ASSERT_OK(err, "pthread_join"))
		goto cleanup;

	ASSERT_EQ(skel->bss->loop_exhausted, 0, "loop_exhausted");
	ASSERT_EQ(skel->bss->executions, 1, "executions");
	ASSERT_EQ(skel->bss->corruptions, 0, "corruptions");

cleanup:
	bpf_link__destroy(link);
}

void test_uprobe_private_stack(void)
{
#if defined(__x86_64__) || defined(__aarch64__)
	struct uprobe_private_stack *skel = NULL;
	cpu_set_t old_mask, mask;
	bool affinity_set = false;
	int cpu;

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
	/* Both triggers must contend for the same per-CPU private stack. */
	if (!ASSERT_OK(sched_setaffinity(0, sizeof(mask), &mask), "set_affinity"))
		return;
	affinity_set = true;

	skel = uprobe_private_stack__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;

	if (test__start_subtest("classic"))
		run_private_stack_test(skel, false);
	if (test__start_subtest("multi"))
		run_private_stack_test(skel, true);

cleanup:
	uprobe_private_stack__destroy(skel);
	if (affinity_set)
		ASSERT_OK(sched_setaffinity(0, sizeof(old_mask), &old_mask),
			  "restore_affinity");
#else
	test__skip();
#endif
}
