// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <network_helpers.h>
#include "file_reader.skel.h"
#include "file_reader_fail.skel.h"

__thread int tls_counter;
const char *user_ptr = "hello world";
char file_contents[256000];

enum file_reader_test {
	VALIDATE_LARGE_FILE = 1,
	SEARCH_ELF = 2,
};

static int initialize_file_contents(void)
{
	int fd;
	ssize_t n;
	int err = 0;

	fd = open("/proc/self/exe", O_RDONLY);
	if (!ASSERT_GT(fd, 0, "Open /proc/self/exe\n"))
		return 1;

	n = read(fd, file_contents, sizeof(file_contents));
	if (!ASSERT_EQ(n, sizeof(file_contents), "Read /proc/self/exe\n"))
		err = 1;

	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	close(fd);
	return err;
}

static void run_test(enum file_reader_test test_type)
{
	struct file_reader *skel;
	int err;
	char data[256];
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = &data, .repeat = 1,
		    .data_size_in = sizeof(data));

	skel = file_reader__open();
	if (!ASSERT_OK_PTR(skel, "file_reader__open"))
		return;

	skel->bss->user_ptr = (void *)user_ptr;
	skel->bss->user_buf = file_contents;
	skel->rodata->user_buf_sz = sizeof(file_contents);
	skel->rodata->test_type = test_type;

	err = file_reader__load(skel);
	if (!ASSERT_OK(err, "file_reader__load"))
		return;

	err = initialize_file_contents();
	if (!ASSERT_OK(err, "initialize file contents"))
		goto cleanup;

	err = file_reader__attach(skel);
	if (!ASSERT_OK(err, "file_reader__attach"))
		goto cleanup;

	getpid();

	ASSERT_EQ(skel->bss->err, 0, "err");
cleanup:
	file_reader__destroy(skel);
}

void test_file_reader(void)
{
	if (test__start_subtest("test_large_file"))
		run_test(VALIDATE_LARGE_FILE);
	if (test__start_subtest("test_search_elf"))
		run_test(SEARCH_ELF);

	RUN_TESTS(file_reader_fail);
}
