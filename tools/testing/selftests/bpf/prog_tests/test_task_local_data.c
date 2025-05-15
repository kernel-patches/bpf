// SPDX-License-Identifier: GPL-2.0
#include <pthread.h>
#include <bpf/btf.h>
#include <test_progs.h>

struct test_struct {
	__u64 a;
	__u64 b;
	__u64 c;
	__u64 d;
};

#include "test_task_local_data.skel.h"
#include "task_local_data.h"

/*
 * Reset task local data between subtests by clearing metadata. This is only safe
 * in selftests as subtests run sequentially. Users of task local data libraries
 * should not do this.
 */
static void reset_tld(void)
{
	if (tld_metadata_p)
		memset(tld_metadata_p, 0, PAGE_SIZE);
}

/* Serialize access to bpf program's global variables */
static pthread_mutex_t global_mutex;

#define TEST_BASIC_THREAD_NUM 63
static tld_key_t tld_keys[TEST_BASIC_THREAD_NUM];

void *test_task_local_data_basic_thread(void *arg)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct test_task_local_data *skel = (struct test_task_local_data *)arg;
	struct test_struct *value2;
	int fd, err, tid, *value1;

	fd = bpf_map__fd(skel->maps.tld_data_map);

	value1 = tld_get_data(fd, tld_keys[0]);
	if (!ASSERT_OK_PTR(value1, "tld_get_data"))
		goto out;

	value2 = tld_get_data(fd, tld_keys[1]);
	if (!ASSERT_OK_PTR(value1, "tld_get_data"))
		goto out;

	tid = gettid();

	*value1 = tid + 0;
	value2->a = tid + 1;
	value2->b = tid + 2;
	value2->c = tid + 3;
	value2->d = tid + 4;

	pthread_mutex_lock(&global_mutex);
	/*
	 * Run task_init which simulates an initialization bpf prog that runs once
	 * for every new task. The program saves keys for subsequent bpf programs.
	 */
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.task_init), &opts);
	ASSERT_OK(err, "run task_init");
	ASSERT_OK(opts.retval, "task_init retval");
	/* Run task_main that read task local data and save to global variables */
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.task_main), &opts);
	ASSERT_OK(err, "run task_main");
	ASSERT_OK(opts.retval, "task_main retval");

	ASSERT_EQ(skel->bss->test_value1, tid + 0, "tld_get_data value1");
	ASSERT_EQ(skel->bss->test_value2.a, tid + 1, "tld_get_data value2.a");
	ASSERT_EQ(skel->bss->test_value2.b, tid + 2, "tld_get_data value2.b");
	ASSERT_EQ(skel->bss->test_value2.c, tid + 3, "tld_get_data value2.c");
	ASSERT_EQ(skel->bss->test_value2.d, tid + 4, "tld_get_data value2.d");
	pthread_mutex_unlock(&global_mutex);

	/* Make sure valueX are indeed local to threads */
	ASSERT_EQ(*value1, tid + 0, "value1");
	ASSERT_EQ(value2->a, tid + 1, "value2.a");
	ASSERT_EQ(value2->b, tid + 2, "value2.b");
	ASSERT_EQ(value2->c, tid + 3, "value2.c");
	ASSERT_EQ(value2->d, tid + 4, "value2.d");

	*value1 = tid + 4;
	value2->a = tid + 3;
	value2->b = tid + 2;
	value2->c = tid + 1;
	value2->d = tid + 0;

	/* Run task_main again */
	pthread_mutex_lock(&global_mutex);
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.task_main), &opts);
	ASSERT_OK(err, "run task_main");
	ASSERT_OK(opts.retval, "task_main retval");

	ASSERT_EQ(skel->bss->test_value1, tid + 4, "tld_get_data value1");
	ASSERT_EQ(skel->bss->test_value2.a, tid + 3, "tld_get_data value2.a");
	ASSERT_EQ(skel->bss->test_value2.b, tid + 2, "tld_get_data value2.b");
	ASSERT_EQ(skel->bss->test_value2.c, tid + 1, "tld_get_data value2.c");
	ASSERT_EQ(skel->bss->test_value2.d, tid + 0, "tld_get_data value2.d");
	pthread_mutex_unlock(&global_mutex);

	tld_free();
out:
	pthread_exit(NULL);
}

static void test_task_local_data_basic(void)
{
	struct test_task_local_data *skel;
	pthread_t thread[TEST_BASIC_THREAD_NUM];
	char dummy_key_name[TLD_NAME_LEN];
	tld_key_t key;
	int i, fd, err;

	reset_tld();

	ASSERT_OK(pthread_mutex_init(&global_mutex, NULL), "pthread_mutex_init");

	skel = test_task_local_data__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	fd = bpf_map__fd(skel->maps.tld_data_map);

	tld_keys[0] = tld_create_key(fd, "value1", sizeof(int));
	ASSERT_FALSE(tld_key_is_err(tld_keys[0]), "tld_create_key");
	tld_keys[1] = tld_create_key(fd, "value2", sizeof(struct test_struct));
	ASSERT_FALSE(tld_key_is_err(tld_keys[1]), "tld_create_key");

	key = tld_create_key(fd, "value_not_exist",
			     PAGE_SIZE - sizeof(int) - sizeof(struct test_struct) + 1);
	ASSERT_EQ(tld_key_err_or_zero(key), -E2BIG, "tld_create_key");

	key = tld_create_key(fd, "value2", sizeof(struct test_struct));
	ASSERT_EQ(tld_key_err_or_zero(key), -EEXIST, "tld_create_key");

	for (i = 2; i < TLD_DATA_CNT; i++) {
		snprintf(dummy_key_name, TLD_NAME_LEN, "dummy_value%d", i);
		tld_keys[i] = tld_create_key(fd, dummy_key_name, sizeof(int));
		ASSERT_FALSE(tld_key_is_err(tld_keys[i]), "tld_create_key");
	}

	key = tld_create_key(fd, "value_not_exist", sizeof(struct test_struct));
	ASSERT_EQ(tld_key_err_or_zero(key), -ENOSPC, "tld_create_key");

	for (i = 0; i < TEST_BASIC_THREAD_NUM; i++) {
		err = pthread_create(&thread[i], NULL, test_task_local_data_basic_thread, skel);
		if (!ASSERT_OK(err, "pthread_create"))
			goto out;
	}

out:
	for (i = 0; i < TEST_BASIC_THREAD_NUM; i++)
		pthread_join(thread[i], NULL);
}

void test_task_local_data(void)
{
	if (test__start_subtest("task_local_data_basic"))
		test_task_local_data_basic();
}
