// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#define _GNU_SOURCE
#include <test_progs.h>
#include <network_helpers.h>
#include <pthread.h>
#include <sched.h>

#include "refcounted_kptr.skel.h"
#include "refcounted_kptr_fail.skel.h"

void test_refcounted_kptr(void)
{
	RUN_TESTS(refcounted_kptr);
}

void test_refcounted_kptr_fail(void)
{
	RUN_TESTS(refcounted_kptr_fail);
}

static void force_cpu(pthread_t thread, int cpunum)
{
	cpu_set_t cpuset;
	int err;

	CPU_ZERO(&cpuset);
	CPU_SET(cpunum, &cpuset);
	err = pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
	if (!ASSERT_OK(err, "pthread_setaffinity_np"))
		return;
}

struct refcounted_kptr *skel;

static void *run_unstash_acq_ref(void *unused)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	long ret, unstash_acq_ref_fd;
	force_cpu(pthread_self(), 1);

	unstash_acq_ref_fd = bpf_program__fd(skel->progs.unstash_add_and_acquire_refcount);

	ret = bpf_prog_test_run_opts(unstash_acq_ref_fd, &opts);
	ASSERT_EQ(opts.retval, 0, "unstash_add_and_acquire_refcount retval");
	ASSERT_EQ(skel->bss->ref_check_3, 2, "ref_check_3");
	ASSERT_EQ(skel->bss->ref_check_4, 1, "ref_check_4");
	ASSERT_EQ(skel->bss->ref_check_5, 0, "ref_check_5");
	pthread_exit((void *)ret);
}

void test_refcounted_kptr_races(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int ref_acq_lock_fd, ref_acq_unlock_fd, rem_node_lock_fd;
	int add_stash_fd, remove_tree_fd;
	pthread_t thread_id;
	int ret;

	force_cpu(pthread_self(), 0);
	skel = refcounted_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "refcounted_kptr__open_and_load"))
		return;

	add_stash_fd = bpf_program__fd(skel->progs.add_refcounted_node_to_tree_and_stash);
	remove_tree_fd = bpf_program__fd(skel->progs.remove_refcounted_node_from_tree);
	ref_acq_lock_fd = bpf_program__fd(skel->progs.unsafe_ref_acq_lock);
	ref_acq_unlock_fd = bpf_program__fd(skel->progs.unsafe_ref_acq_unlock);
	rem_node_lock_fd = bpf_program__fd(skel->progs.unsafe_rem_node_lock);

	ret = bpf_prog_test_run_opts(rem_node_lock_fd, &opts);
	if (!ASSERT_OK(ret, "rem_node_lock"))
		return;

	ret = bpf_prog_test_run_opts(ref_acq_lock_fd, &opts);
	if (!ASSERT_OK(ret, "ref_acq_lock"))
		return;

	ret = bpf_prog_test_run_opts(add_stash_fd, &opts);
	if (!ASSERT_OK(ret, "add_stash"))
		return;
	if (!ASSERT_OK(opts.retval, "add_stash retval"))
		return;

	ret = pthread_create(&thread_id, NULL, &run_unstash_acq_ref, NULL);
	if (!ASSERT_OK(ret, "pthread_create"))
		goto cleanup;

	force_cpu(thread_id, 1);

	/* This program will execute before unstash_acq_ref's refcount_acquire, then
	 * unstash_acq_ref can proceed after unsafe_unlock
	 */
	ret = bpf_prog_test_run_opts(remove_tree_fd, &opts);
	if (!ASSERT_OK(ret, "remove_tree"))
		goto cleanup;

	ret = bpf_prog_test_run_opts(ref_acq_unlock_fd, &opts);
	if (!ASSERT_OK(ret, "ref_acq_unlock"))
		goto cleanup;

	ret = pthread_join(thread_id, NULL);
	if (!ASSERT_OK(ret, "pthread_join"))
		goto cleanup;

	refcounted_kptr__destroy(skel);
	return;
cleanup:
	bpf_prog_test_run_opts(ref_acq_unlock_fd, &opts);
	refcounted_kptr__destroy(skel);
	return;
}
