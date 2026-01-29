// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <string.h>
#include <stdio.h>
#include "rhash.skel.h"
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <network_helpers.h>

static void rhash_run(const char *prog_name)
{
	struct rhash *skel;
	struct bpf_program *prog;
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	skel = rhash__open();
	if (!ASSERT_OK_PTR(skel, "rhash__open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;
	bpf_program__set_autoload(prog, true);

	err = rhash__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, "prog run"))
		goto cleanup;

	if (!ASSERT_OK(skel->bss->err, "bss->err"))
		goto cleanup;

cleanup:
	rhash__destroy(skel);
}

struct lock_thread_args {
	int prog_fd;
	int map_fd;
};

struct lock_elem {
	struct bpf_spin_lock lock;
	int var[16];
};

static void *spin_lock_thread(void *arg)
{
	struct lock_thread_args *args = arg;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 10000,
	);
	int err;

	err = bpf_prog_test_run_opts(args->prog_fd, &topts);
	if (err || topts.retval)
		return (void *)1;

	return (void *)0;
}

static void *parallel_map_access(void *arg)
{
	struct lock_thread_args *args = arg;
	int i, j, key = 0;
	int err;
	struct lock_elem val;

	for (i = 0; i < 10000; i++) {
		err = bpf_map_lookup_elem_flags(args->map_fd, &key, &val, BPF_F_LOCK);
		if (err)
			return (void *)1;
		if (val.lock.val)
			return (void *)1;
		for (j = 1; j < 16; j++) {
			if (val.var[j] != val.var[0])
				return (void *)1;
		}
	}

	return (void *)0;
}

static void rhash_spin_lock_test(void)
{
	struct lock_thread_args args;
	struct rhash *skel;
	struct lock_elem val = {};
	pthread_t thread_id[4];
	int err, key = 0, i;
	void *ret;

	skel = rhash__open_and_load();
	if (!ASSERT_OK_PTR(skel, "rhash__open_and_load"))
		return;

	args.prog_fd = bpf_program__fd(skel->progs.test_rhash_spin_lock);
	args.map_fd = bpf_map__fd(skel->maps.rhmap_lock);

	/* Insert initial element with BPF_F_LOCK */
	err = bpf_map_update_elem(args.map_fd, &key, &val, BPF_F_LOCK);
	if (!ASSERT_OK(err, "initial update"))
		goto cleanup;

	/* Spawn 2 threads running BPF program (uses bpf_spin_lock) */
	for (i = 0; i < 2; i++)
		if (!ASSERT_OK(pthread_create(&thread_id[i], NULL,
					      &spin_lock_thread, &args),
			       "pthread_create spin_lock"))
			goto cleanup;

	/* Spawn 2 threads doing parallel map access with BPF_F_LOCK */
	for (i = 2; i < 4; i++)
		if (!ASSERT_OK(pthread_create(&thread_id[i], NULL,
					      &parallel_map_access, &args),
			       "pthread_create parallel_map_access"))
			goto cleanup;

	/* Wait for all threads */
	for (i = 0; i < 4; i++)
		if (!ASSERT_OK(pthread_join(thread_id[i], &ret), "pthread_join") ||
		    !ASSERT_OK((long)ret, "thread ret"))
			goto cleanup;

cleanup:
	rhash__destroy(skel);
}

void test_rhash(void)
{
	if (test__start_subtest("test_rhash_lookup_update"))
		rhash_run("test_rhash_lookup_update");

	if (test__start_subtest("test_rhash_update_delete"))
		rhash_run("test_rhash_update_delete");

	if (test__start_subtest("test_rhash_update_elements"))
		rhash_run("test_rhash_update_elements");

	if (test__start_subtest("test_rhash_update_exist"))
		rhash_run("test_rhash_update_exist");

	if (test__start_subtest("test_rhash_update_any"))
		rhash_run("test_rhash_update_any");

	if (test__start_subtest("test_rhash_noexist_duplicate"))
		rhash_run("test_rhash_noexist_duplicate");

	if (test__start_subtest("test_rhash_delete_nonexistent"))
		rhash_run("test_rhash_delete_nonexistent");

	if (test__start_subtest("test_rhash_spin_lock"))
		rhash_spin_lock_test();
}

