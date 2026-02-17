// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <sys/klog.h>
#include <test_progs.h>
#include <unpriv_helpers.h>
#include "kasan.skel.h"

#define SYSLOG_ACTION_READ_ALL	3
#define SYSLOG_ACTION_CLEAR	5

#define MAX_LOG_SIZE		8*1024
#define READ_CHUNK_SIZE		128

#define KASAN_PATTERN_SLAB_UAF "BUG: KASAN: slab-use-after-free in bpf_prog_"
#define KASAN_PATTERN_SLAB_OOB "BUG: KASAN: slab-out-of-bounds in bpf_prog_"

static char klog_buffer[MAX_LOG_SIZE];

static int read_kernel_logs(char *buf, size_t max_len)
{
	return klogctl(SYSLOG_ACTION_READ_ALL, buf, max_len);
}

static int clear_kernel_logs()
{
	return klogctl(SYSLOG_ACTION_CLEAR, NULL, 0);
}

static int test_pattern_in_logs(char *buf, char *pattern)
{
	return strstr(buf, pattern) != NULL ? 0 : 1;
}

struct subtest {
	char *prog_name;
	char *expected_report_pattern;
};

struct subtest subtests[] = {
	{
		.prog_name = "bpf_kasan_uaf",
		.expected_report_pattern = KASAN_PATTERN_SLAB_UAF
	},
	{
		.prog_name = "bpf_kasan_oob",
		.expected_report_pattern = KASAN_PATTERN_SLAB_OOB
	}
};

void test_kasan() {
	struct bpf_program *prog;
	struct subtest *subtest;
	uint8_t buf[ETH_HLEN];
	struct kasan *skel;
	int ret, i;

	if (!is_jit_enabled() || !get_kasan_jit_enabled()) {
		test__skip();
		return;
	}

	skel = kasan__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load prog"))
		return;

	LIBBPF_OPTS(bpf_test_run_opts, topts);
	memset(&topts, 0, sizeof(struct bpf_test_run_opts));
	topts.sz = sizeof(struct bpf_test_run_opts);
	topts.data_size_in = ETH_HLEN;
	topts.data_in = buf;

	for (i = 0; i < ARRAY_SIZE(subtests); i++) {
		subtest = &subtests[i];
		if (!test__start_subtest(subtest->prog_name))
			continue;
		ret = clear_kernel_logs();
		if (!ASSERT_OK(ret, "reset log buffer"))
			continue;

		prog = bpf_object__find_program_by_name(skel->obj,
							subtest->prog_name);
		if (!ASSERT_OK_PTR(prog, "find subtest prog"))
			continue;

		ret = bpf_prog_test_run_opts( bpf_program__fd(prog), &topts);
		if (!ASSERT_OK(ret, "run prog"))
			continue;

		ret = read_kernel_logs(klog_buffer, MAX_LOG_SIZE);
		if(ASSERT_GE(ret, 0, "read kernel logs"))
			ASSERT_OK(test_pattern_in_logs(
					  klog_buffer,
					  subtests[i].expected_report_pattern),
				  subtests[i].prog_name);
	}

	kasan__destroy(skel);
}
