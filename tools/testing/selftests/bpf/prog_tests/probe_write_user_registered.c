// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023, Google LLC. */

#include <malloc.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <time.h>

#include <test_progs.h>
#include "test_probe_write_user_registered.skel.h"

#define TEST_TAG 0xf23c39ab

/* Encoding of the test access-type in the tv_nsec parameter. */
enum test_access {
	TEST_SUB_REGION,
	TEST_EQ_REGION,
	TEST_ONE_BY_ONE,
	TEST_ANY_TAG,
};

/* This will be written to by the BPF program. */
struct test_data {
	volatile uint64_t padding_start;
	volatile uint64_t nanosleep_arg;
	volatile uint64_t padding_end;
};

static struct test_data test_data;

static void prctl_register_writable(const volatile void *start, size_t size, uint32_t tag)
{
	ASSERT_OK(prctl(PR_BPF_REGISTER_WRITABLE, start, size, tag, 0), __func__);
}

static void prctl_unregister_writable(const volatile void *start, size_t size)
{
	ASSERT_OK(prctl(PR_BPF_UNREGISTER_WRITABLE, start, size, 0, 0), __func__);
}

/* Returns the actual tv_nsec value derived from base and test_access. */
static uint64_t do_nanosleep(uint64_t base, enum test_access test_access)
{
	const uint64_t tv_nsec = base << 8 | test_access;
	struct timespec ts = {};

	ts.tv_sec = 0;
	ts.tv_nsec = tv_nsec;
	syscall(__NR_nanosleep, &ts, NULL);

	return tv_nsec;
}

/*
 * Test that the basic usage works: register, write from BPF program,
 * unregister, after which no more writes can happen.
 */
static void test_register_and_unregister(struct test_probe_write_user_registered *skel)
{
	uint64_t nsec = 1234;
	uint64_t expect;

	prctl_register_writable(&test_data, sizeof(test_data), TEST_TAG);

	/* Check that we see the writes. */
	for (int i = 0; i < 3; ++i) {
		test_data.nanosleep_arg = 0;
		expect = do_nanosleep(++nsec, TEST_SUB_REGION);
		ASSERT_EQ(test_data.nanosleep_arg, expect, __func__);
		ASSERT_EQ(skel->data->found_user_registered, 1, __func__);
	}

	/* Registered the whole region, so this should also work... */
	for (int i = 0; i < 3; ++i) {
		test_data.nanosleep_arg = 0;
		expect = do_nanosleep(++nsec, TEST_EQ_REGION);
		ASSERT_EQ(test_data.nanosleep_arg, expect, __func__);
		ASSERT_EQ(skel->data->found_user_registered, 1, __func__);
	}

	prctl_unregister_writable(&test_data, sizeof(test_data));

	/* No more writes after unregistration. */
	test_data.nanosleep_arg = 0;
	do_nanosleep(++nsec, TEST_SUB_REGION);
	ASSERT_EQ(test_data.nanosleep_arg, 0, __func__);
	ASSERT_EQ(skel->data->found_user_registered, 0, __func__);
}

/*
 * Test that accesses with mismatching tags fail.
 */
static void test_bad_tag(struct test_probe_write_user_registered *skel)
{
	uint64_t expect;

	prctl_register_writable(&test_data, sizeof(test_data), TEST_TAG);
	test_data.nanosleep_arg = 0;
	expect = do_nanosleep(1234, TEST_SUB_REGION);
	ASSERT_EQ(test_data.nanosleep_arg, expect, __func__);
	ASSERT_EQ(skel->data->found_user_registered, 1, __func__);
	do_nanosleep(9999, TEST_ANY_TAG); /* fails */
	ASSERT_EQ(test_data.nanosleep_arg, expect, __func__);
	ASSERT_EQ(skel->data->found_user_registered, 1, __func__);
	prctl_unregister_writable(&test_data, sizeof(test_data));
}

/*
 * Test that the "any" (zero) tag works.
 */
static void test_any_tag(struct test_probe_write_user_registered *skel)
{
	uint64_t nsec = 1234;
	uint64_t expect;

	prctl_register_writable(&test_data, sizeof(test_data), 0);

	for (int i = 0; i < 3; ++i) {
		test_data.nanosleep_arg = 0;
		expect = do_nanosleep(++nsec, TEST_ANY_TAG);
		ASSERT_EQ(test_data.nanosleep_arg, expect, __func__);
		ASSERT_EQ(skel->data->found_user_registered, 0, __func__);
	}

	prctl_unregister_writable(&test_data, sizeof(test_data));

	test_data.nanosleep_arg = 0;
	do_nanosleep(++nsec, TEST_ANY_TAG);
	ASSERT_EQ(test_data.nanosleep_arg, 0, __func__);
	ASSERT_EQ(skel->data->found_user_registered, 0, __func__);
}

/*
 * Test that invalid prctl() fail.
 */
static void test_invalid_prctl(struct test_probe_write_user_registered *skel)
{
	ASSERT_ERR(prctl(PR_BPF_REGISTER_WRITABLE, NULL, 1, 0, 0), __func__);
	ASSERT_ERR(prctl(PR_BPF_REGISTER_WRITABLE, &test_data, 0, 0, 0), __func__);
	prctl_register_writable(&test_data, sizeof(test_data), TEST_TAG);
	ASSERT_ERR(prctl(PR_BPF_REGISTER_WRITABLE, &test_data, sizeof(test_data), 0, 0), __func__);
	ASSERT_ERR(prctl(PR_BPF_REGISTER_WRITABLE, &test_data, 2, 0, 0), __func__);
	prctl_register_writable((void *)&test_data + 1, 1, TEST_TAG);
	prctl_register_writable((void *)&test_data - 1, 1, TEST_TAG);

	ASSERT_ERR(prctl(PR_BPF_UNREGISTER_WRITABLE, &test_data, 1, 0, 0), __func__);
	prctl_unregister_writable((void *)&test_data - 1, 1);
	prctl_unregister_writable(&test_data, sizeof(test_data));
	prctl_unregister_writable((void *)&test_data + 1, 1);
	ASSERT_ERR(prctl(PR_BPF_UNREGISTER_WRITABLE, 0x123456, 1, 0, 0), __func__);
	ASSERT_ERR(prctl(PR_BPF_UNREGISTER_WRITABLE, &test_data, sizeof(test_data), 0, 0), __func__);
}

/*
 * Test that we can register multiple regions and they all work.
 */
static void test_multiple_region(struct test_probe_write_user_registered *skel)
{
	uint64_t expect;

	prctl_register_writable(&test_data.nanosleep_arg, sizeof(uint64_t), TEST_TAG);
	prctl_register_writable(&test_data.padding_end, sizeof(uint64_t), TEST_TAG);
	/* First one last, so the test program knows where to start. */
	prctl_register_writable(&test_data.padding_start, sizeof(uint64_t), TEST_TAG);

	memset(&test_data, 0, sizeof(test_data));
	do_nanosleep(0xf00d, TEST_EQ_REGION); /* fails */
	ASSERT_EQ(test_data.nanosleep_arg, 0, __func__);
	ASSERT_EQ(skel->data->found_user_registered, 1, __func__); /* found first */

	expect = do_nanosleep(0xf33d, TEST_ONE_BY_ONE);
	ASSERT_EQ(test_data.padding_start, expect, __func__);
	ASSERT_EQ(test_data.nanosleep_arg, expect, __func__);
	ASSERT_EQ(test_data.padding_end, expect, __func__);
	ASSERT_EQ(skel->data->found_user_registered, 1, __func__);

	prctl_unregister_writable(&test_data.padding_start, sizeof(uint64_t));
	prctl_unregister_writable(&test_data.nanosleep_arg, sizeof(uint64_t));
	prctl_unregister_writable(&test_data.padding_end, sizeof(uint64_t));
}

static void *test_thread_func(void *arg)
{
	struct test_probe_write_user_registered *skel = arg;

	/* If this fails, the thread didn't inherit the region. */
	ASSERT_ERR(prctl(PR_BPF_UNREGISTER_WRITABLE, &test_data, sizeof(test_data), 0, 0), __func__);
	/* So that the BPF user_writable task storage is filled. */
	prctl_register_writable(&test_data, 1, TEST_TAG);
	prctl_unregister_writable(&test_data, 1);

	/* Test that there really is no way it'll write. */
	test_data.nanosleep_arg = 0;
	do_nanosleep(9999, TEST_SUB_REGION); /* fails */
	ASSERT_EQ(test_data.nanosleep_arg, 0, __func__);
	ASSERT_EQ(skel->data->found_user_registered, 0, __func__);

	return NULL;
}

/*
 * Test that threads (CLONE_VM) do not inherit writable regions.
 */
static void test_thread(struct test_probe_write_user_registered *skel)
{
	uint64_t expect;
	pthread_t tid;

	prctl_register_writable(&test_data, sizeof(test_data), TEST_TAG);

	test_data.nanosleep_arg = 0;
	expect = do_nanosleep(1234, TEST_SUB_REGION);
	ASSERT_EQ(test_data.nanosleep_arg, expect, __func__);
	ASSERT_EQ(skel->data->found_user_registered, 1, __func__);

	ASSERT_OK(pthread_create(&tid, NULL, test_thread_func, skel), "pthread_create");
	ASSERT_OK(pthread_join(tid, NULL), "pthread_join");

	ASSERT_EQ(test_data.nanosleep_arg, 0, __func__);
	prctl_unregister_writable(&test_data, sizeof(test_data));
}

/*
 * Test that fork() does inherit writable regions.
 */
static void test_fork(struct test_probe_write_user_registered *skel)
{
	uint64_t expect;
	int pid, status;

	prctl_register_writable(&test_data, sizeof(test_data), TEST_TAG);

	test_data.nanosleep_arg = 0;
	expect = do_nanosleep(1234, TEST_SUB_REGION);
	ASSERT_EQ(test_data.nanosleep_arg, expect, __func__);
	ASSERT_EQ(skel->data->found_user_registered, 1, __func__);

	pid = fork();
	if (!pid) {
		test_data.nanosleep_arg = 0; /* write prefault */
		expect = do_nanosleep(3333, TEST_SUB_REGION);
		ASSERT_EQ(skel->data->found_user_registered, 1, __func__);
		exit(!ASSERT_EQ(test_data.nanosleep_arg, expect, __func__));
	}

	status = -1;
	waitpid(pid, &status, 0);
	ASSERT_EQ(status, 0, __func__);

	ASSERT_EQ(test_data.nanosleep_arg, expect, __func__);
	prctl_unregister_writable(&test_data, sizeof(test_data));
}

/*
 * Test that the kernel can allocate lots of regions and find them.
 */
static void test_stress_regions(struct test_probe_write_user_registered *skel)
{
	const int STRESS_SIZE = 200;
	struct test_data *large = malloc(STRESS_SIZE * sizeof(*large));
	uint64_t expect;

	ASSERT_NEQ(large, NULL, __func__);

	memset(large, 0, STRESS_SIZE * sizeof(*large));

	for (int i = 0; i < STRESS_SIZE; ++i) {
		prctl_register_writable(&large[i], sizeof(*large), TEST_TAG);
		ASSERT_ERR(prctl(PR_BPF_REGISTER_WRITABLE, &large[i], sizeof(*large), 0, 0), __func__);
		expect = do_nanosleep(777, TEST_SUB_REGION);
		ASSERT_EQ(large[i].nanosleep_arg, expect, __func__);
		ASSERT_EQ(skel->data->found_user_registered, 1, __func__);
	}

	for (int i = 0; i < STRESS_SIZE; ++i) {
		prctl_unregister_writable(&large[i], sizeof(*large));
		ASSERT_ERR(prctl(PR_BPF_UNREGISTER_WRITABLE, &large[i], sizeof(*large), 0, 0), __func__);
		large[i].nanosleep_arg = 0;
		do_nanosleep(1992, TEST_SUB_REGION); /* no more writes */
		ASSERT_EQ(large[i].nanosleep_arg, 0, __func__);
		ASSERT_EQ(skel->data->found_user_registered, i < STRESS_SIZE - 1 ? 1 : 0, __func__);
	}

	for (int i = 0; i < STRESS_SIZE; ++i)
		ASSERT_ERR(prctl(PR_BPF_UNREGISTER_WRITABLE, &large[i], sizeof(*large), 0, 0), __func__);

	free(large);
}

/*
 * Test setup.
 */
void test_probe_write_user_registered(void)
{
	struct test_probe_write_user_registered *skel;

	skel = test_probe_write_user_registered__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load"))
		return;

	if (!ASSERT_OK(test_probe_write_user_registered__attach(skel), "attach"))
		goto cleanup;

	if (test__start_subtest("register_and_unregister"))
		test_register_and_unregister(skel);
	if (test__start_subtest("bad_tag"))
		test_bad_tag(skel);
	if (test__start_subtest("any_tag"))
		test_any_tag(skel);
	if (test__start_subtest("invalid_prctl"))
		test_invalid_prctl(skel);
	if (test__start_subtest("multiple_region"))
		test_multiple_region(skel);
	if (test__start_subtest("thread"))
		test_thread(skel);
	if (test__start_subtest("fork"))
		test_fork(skel);
	if (test__start_subtest("stress_regions"))
		test_stress_regions(skel);

cleanup:
	test_probe_write_user_registered__destroy(skel);
}
