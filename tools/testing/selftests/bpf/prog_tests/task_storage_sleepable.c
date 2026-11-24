// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <test_progs.h>
#include "task_storage_sleepable.skel.h"

static void *run_storage(void *arg)
{
	struct task_storage_sleepable *skel = arg;

	/* A new thread has no task storage from earlier tests. */
	skel->bss->target_pid = syscall(SYS_gettid);
	syscall(SYS_getpgid, 0);
	skel->bss->target_pid = 0;
	return NULL;
}

static void test_alloc(const char *prog_name, int regular_allocs, int nonsleepable_allocs)
{
	struct task_storage_sleepable *skel;
	struct bpf_link *link = NULL;
	struct bpf_program *regular_probe, *prog;
	pthread_t thread;
	int err;

	skel = task_storage_sleepable__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	regular_probe = skel->progs.on_regular_alloc;
	err = bpf_program__set_attach_target(regular_probe, 0, "bpf_map_kzalloc");
	if (err == -ESRCH) {
		printf("%s: bpf_map_kzalloc missing from kernel BTF\n", __func__);
		err = bpf_program__set_autoload(regular_probe, false);
	}
	if (!ASSERT_OK(err, "configure_regular_alloc_probe"))
		goto out;

	/* Task storage uses the nolock allocator until the fallback is added. */
	prog = skel->progs.on_nonsleepable_alloc;
	err = bpf_program__set_attach_target(prog, 0, "bpf_map_kmalloc_maylock");
	if (err == -ESRCH)
		err = bpf_program__set_attach_target(prog, 0, "bpf_map_kmalloc_nolock");
	if (!ASSERT_OK(err, "set_nonsleepable_alloc_target"))
		goto out;

	err = task_storage_sleepable__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto out;

	if (bpf_program__autoload(regular_probe)) {
		skel->links.on_regular_alloc = bpf_program__attach(regular_probe);
		if (!ASSERT_OK_PTR(skel->links.on_regular_alloc, "attach_regular_alloc"))
			goto out;
	}
	skel->links.on_nonsleepable_alloc = bpf_program__attach(skel->progs.on_nonsleepable_alloc);
	if (!ASSERT_OK_PTR(skel->links.on_nonsleepable_alloc, "attach_nonsleepable_alloc"))
		goto out;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "find_program"))
		goto out;
	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "attach_program"))
		goto out;

	err = pthread_create(&thread, NULL, run_storage, skel);
	if (!ASSERT_OK(err, "pthread_create"))
		goto out;
	err = pthread_join(thread, NULL);
	ASSERT_OK(err, "pthread_join");
	ASSERT_EQ(skel->bss->errors, 0, "storage_errors");
	if (skel->links.on_regular_alloc)
		ASSERT_EQ(skel->bss->regular_allocs, regular_allocs, "regular_allocs");
	ASSERT_EQ(skel->bss->nonsleepable_allocs, nonsleepable_allocs, "nonsleepable_allocs");
out:
	bpf_link__destroy(link);
	task_storage_sleepable__destroy(skel);
}

void test_task_storage_sleepable(void)
{
	if (test__start_subtest("sleepable"))
		test_alloc("sleepable", 3, 0);
	if (test__start_subtest("non_sleepable"))
		test_alloc("non_sleepable", 0, 3);
	if (test__start_subtest("sleepable_rcu"))
		test_alloc("sleepable_rcu", 0, 3);
	if (test__start_subtest("mixed_contexts"))
		test_alloc("mixed_contexts", 2, 2);
}
