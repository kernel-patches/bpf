#include <pthread.h>

#include <test_progs.h>
#include <bpf/btf.h>

#include "task_local_data.h"
#include "test_task_local_data_basic.skel.h"

#define TEST_THREAD_NUM 32

/* Used to declare a large tasl local data below to see if bpf_tld_type_var() prevents
 * a value from crossing the page boundary
 */
struct dummy {
	char data[1000];
};

/* Declare task local data */
bpf_tld_type_var(int, value1);
bpf_tld_type_var(struct test_struct, value2);
bpf_tld_type_var(struct dummy, dummy);
bpf_tld_key_type_var("test_basic_value3", int, value3);
bpf_tld_key_type_var("test_basic_value4", struct test_struct, value4);

/* Serialize access to bpf program's global variables */
static pthread_mutex_t global_mutex;

static void run_prog_init(struct test_task_local_data_basic *skel, int tid)
{
	skel->bss->target_tid = tid;
	(void)syscall(__NR_getuid);
	skel->bss->target_tid = -1;
}

static void run_prog_main(struct test_task_local_data_basic *skel, int tid)
{
	skel->bss->target_tid = tid;
	(void)syscall(__NR_gettid);
	skel->bss->target_tid = -1;
}

void *test_task_local_data_basic_thread(void *arg)
{
	struct test_task_local_data_basic *skel = (struct test_task_local_data_basic *)arg;
	int err, tid;

	tid = gettid();

	err = bpf_tld_thread_init();
	if (!ASSERT_OK(err, "bpf_tld_thread_init"))
		return NULL;

	value1 = tid + 0;
	value2.a = tid + 1;
	value2.b = tid + 2;
	value2.c = tid + 3;
	value2.d = tid + 4;
	value3 = tid + 5;
	value4.a = tid + 6;
	value4.b = tid + 7;
	value4.c = tid + 8;
	value4.d = tid + 9;

	pthread_mutex_lock(&global_mutex);
	/* Simulate an initialization bpf prog that runs once for every new task.
	 * The program caches data offsets for subsequent bpf programs
	 */
	run_prog_init(skel, tid);
	/* Run main prog that lookup task local data and save to global variables */
	run_prog_main(skel, tid);
	ASSERT_EQ(skel->bss->test_value1, tid + 0, "bpf_tld_lookup value1");
	ASSERT_EQ(skel->bss->test_value2.a, tid + 1, "bpf_tld_lookup value2.a");
	ASSERT_EQ(skel->bss->test_value2.b, tid + 2, "bpf_tld_lookup value2.b");
	ASSERT_EQ(skel->bss->test_value2.c, tid + 3, "bpf_tld_lookup value2.c");
	ASSERT_EQ(skel->bss->test_value2.d, tid + 4, "bpf_tld_lookup value2.d");
	ASSERT_EQ(skel->bss->test_value3, tid + 5, "bpf_tld_lookup value3");
	ASSERT_EQ(skel->bss->test_value4.a, tid + 6, "bpf_tld_lookup value4.a");
	ASSERT_EQ(skel->bss->test_value4.b, tid + 7, "bpf_tld_lookup value4.b");
	ASSERT_EQ(skel->bss->test_value4.c, tid + 8, "bpf_tld_lookup value4.c");
	ASSERT_EQ(skel->bss->test_value4.d, tid + 9, "bpf_tld_lookup value4.d");
	pthread_mutex_unlock(&global_mutex);

	/* Make sure valueX are indeed local to threads */
	ASSERT_EQ(value1, tid + 0, "value1");
	ASSERT_EQ(value2.a, tid + 1, "value2.a");
	ASSERT_EQ(value2.b, tid + 2, "value2.b");
	ASSERT_EQ(value2.c, tid + 3, "value2.c");
	ASSERT_EQ(value2.d, tid + 4, "value2.d");
	ASSERT_EQ(value3, tid + 5, "value3");
	ASSERT_EQ(value4.a, tid + 6, "value4.a");
	ASSERT_EQ(value4.b, tid + 7, "value4.b");
	ASSERT_EQ(value4.c, tid + 8, "value4.c");
	ASSERT_EQ(value4.d, tid + 9, "value4.d");

	value1 = tid + 9;
	value2.a = tid + 8;
	value2.b = tid + 7;
	value2.c = tid + 6;
	value2.d = tid + 5;
	value3 = tid + 4;
	value4.a = tid + 3;
	value4.b = tid + 2;
	value4.c = tid + 1;
	value4.d = tid + 0;

	/* Run main prog again */
	pthread_mutex_lock(&global_mutex);
	run_prog_main(skel, tid);
	ASSERT_EQ(skel->bss->test_value1, tid + 9, "bpf_tld_lookup value1");
	ASSERT_EQ(skel->bss->test_value2.a, tid + 8, "bpf_tld_lookup value2.a");
	ASSERT_EQ(skel->bss->test_value2.b, tid + 7, "bpf_tld_lookup value2.b");
	ASSERT_EQ(skel->bss->test_value2.c, tid + 6, "bpf_tld_lookup value2.c");
	ASSERT_EQ(skel->bss->test_value2.d, tid + 5, "bpf_tld_lookup value2.d");
	ASSERT_EQ(skel->bss->test_value3, tid + 4, "bpf_tld_lookup value3");
	ASSERT_EQ(skel->bss->test_value4.a, tid + 3, "bpf_tld_lookup value4.a");
	ASSERT_EQ(skel->bss->test_value4.b, tid + 2, "bpf_tld_lookup value4.b");
	ASSERT_EQ(skel->bss->test_value4.c, tid + 1, "bpf_tld_lookup value4.c");
	ASSERT_EQ(skel->bss->test_value4.d, tid + 0, "bpf_tld_lookup value4.d");
	pthread_mutex_unlock(&global_mutex);

	pthread_exit(NULL);
}

static void test_task_local_data_basic(void)
{
	struct test_task_local_data_basic *skel;
	pthread_t thread[TEST_THREAD_NUM];
	int i, err;

	ASSERT_OK(pthread_mutex_init(&global_mutex, NULL), "pthread_mutex_init");

	skel = test_task_local_data_basic__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	err = test_task_local_data_basic__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;

	for (i = 0; i < TEST_THREAD_NUM; i++) {
		err = pthread_create(&thread[i], NULL, test_task_local_data_basic_thread, skel);
		if (!ASSERT_OK(err, "pthread_create"))
			goto out;
	}

	for (i = 0; i < TEST_THREAD_NUM; i++)
		pthread_join(thread[i], NULL);
out:
	unlink(TASK_LOCAL_DATA_MAP_PIN_PATH);
}

void test_task_local_data(void)
{
	if (test__start_subtest("task_local_data_basic"))
		test_task_local_data_basic();
}
