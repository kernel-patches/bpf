// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <bpf/bpf.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <sys/klog.h>
#include <test_progs.h>
#include <unpriv_helpers.h>
#include "kasan.skel.h"

#define SUBTEST_NAME_MAX_LEN	64
#define SYSLOG_ACTION_READ_ALL	3
#define SYSLOG_ACTION_CLEAR	5

#define MAX_LOG_SIZE		(8*1024)
#define READ_CHUNK_SIZE		128

#define KASAN_PATTERN_SLAB_UAF "BUG: KASAN: slab-use-after-free in bpf_prog_"
#define KASAN_PATTERN_GLOBAL_OOB "BUG: KASAN: global-out-of-bounds in bpf_prog_"

static char klog_buffer[MAX_LOG_SIZE];

static int read_kernel_logs(char *buf, size_t max_len)
{
	return klogctl(SYSLOG_ACTION_READ_ALL, buf, max_len);
}

static int clear_kernel_logs(void)
{
	return klogctl(SYSLOG_ACTION_CLEAR, NULL, 0);
}

static int kernel_logs_have_matching_kasan_report(char *buf, char *pattern,
						  bool is_write, int size)
{
	char *access_desc_start, *access_desc_end, *tmp;
	char access_log[READ_CHUNK_SIZE];
	char *kasan_report_start;
	int hsize, nsize;
	/* Searched kasan report is valid if
	 * - it contains the expected kasan pattern
	 * - the next line is the description of the faulty access
	 * - faulty access properties match the tested type and size
	 */
	kasan_report_start = strstr(buf, pattern);

	if (!kasan_report_start)
		return 1;

	/* Find next line */
	access_desc_start = strchr(kasan_report_start, '\n');
	if (!access_desc_start)
		return 1;
	access_desc_start++;

	access_desc_end = strchr(access_desc_start, '\n');
	if (!access_desc_end)
		return 1;

	nsize = snprintf(access_log, READ_CHUNK_SIZE, "%s of size %d at addr",
		 is_write ? "Write" : "Read", size);

	hsize = access_desc_end - access_desc_start;
	tmp = memmem(access_desc_start, hsize, access_log, nsize);

	if (!tmp)
		return 1;

	return 0;
}

struct test_spec {
	char *prog_name;
	char *expected_report_pattern;
};

static struct test_spec tests[] = {
	{
		.prog_name = "bpf_kasan_uaf",
		.expected_report_pattern = KASAN_PATTERN_SLAB_UAF
	},
	{
		.prog_name = "bpf_kasan_oob",
		.expected_report_pattern = KASAN_PATTERN_GLOBAL_OOB
	}
};

static void run_test_with_type_and_size(struct kasan *skel,
					struct test_spec *test, bool is_write,
					int access_size)
{
	char subtest_name[SUBTEST_NAME_MAX_LEN];
	struct bpf_program *prog;
	uint8_t buf[ETH_HLEN];
	int ret;

	prog = bpf_object__find_program_by_name(skel->obj, test->prog_name);
	if (!ASSERT_OK_PTR(prog, "find test prog"))
		return;

	snprintf(subtest_name, SUBTEST_NAME_MAX_LEN, "%s_%s_%d",
		 test->prog_name, is_write ? "write" : "read", access_size);

	if (!test__start_subtest(subtest_name))
		return;

	ret = clear_kernel_logs();
	if (!ASSERT_OK(ret, "reset log buffer"))
		return;

	LIBBPF_OPTS(bpf_test_run_opts, topts);
	topts.sz = sizeof(struct bpf_test_run_opts);
	topts.data_size_in = ETH_HLEN;
	topts.data_in = buf;
	skel->bss->is_write = is_write;
	skel->bss->access_size = access_size;
	ret = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
	if (!ASSERT_OK(ret, "run prog"))
		return;

	ret = read_kernel_logs(klog_buffer, MAX_LOG_SIZE);
	if (ASSERT_GE(ret, 0, "read kernel logs"))
		ASSERT_OK(kernel_logs_have_matching_kasan_report(
				  klog_buffer, test->expected_report_pattern,
				  is_write, access_size),
			  test->prog_name);
}

static void run_test_with_type(struct kasan *skel, struct test_spec *test,
			       bool is_write)
{
	run_test_with_type_and_size(skel, test, is_write, 1);
	run_test_with_type_and_size(skel, test, is_write, 2);
	run_test_with_type_and_size(skel, test, is_write, 4);
	run_test_with_type_and_size(skel, test, is_write, 8);
}

static void run_test(struct kasan *skel, struct test_spec *test)
{
	run_test_with_type(skel, test, false);
	run_test_with_type(skel, test, true);
}

void test_kasan(void)
{
	struct test_spec *test;
	struct kasan *skel;
	int i;

	if (!is_jit_enabled() || !get_kasan_jit_enabled()) {
		test__skip();
		return;
	}

	skel = kasan__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load prog"))
		return;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		test = &tests[i];

		run_test(skel, test);
	}

	kasan__destroy(skel);
}
