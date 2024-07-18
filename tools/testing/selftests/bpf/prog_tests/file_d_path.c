// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/syscall.h>

#include "test_file_d_path.skel.h"

/* Compatible with older versions of glibc begin */
#ifndef __NR_close_range
#ifdef __alpha__
#define __NR_close_range 546
#else
#define __NR_close_range 436
#endif
#endif

#define close_fd(fd) syscall(__NR_close_range, fd, fd, 0)
/* Compatible with older versions of glibc end */


#define MAX_PATH_LEN	256
#define TEST_FILES_NUM		2

static int duration;

static struct {
	__u32 cnt;
	char paths[TEST_FILES_NUM][MAX_PATH_LEN];
} record;

static int set_pathname(int fd, pid_t pid)
{
	char buf[MAX_PATH_LEN];

	snprintf(buf, MAX_PATH_LEN, "/proc/%d/fd/%d", pid, fd);
	return readlink(buf, record.paths[record.cnt++], MAX_PATH_LEN);
}

static int trigger_filp_close(pid_t pid)
{
	int ret = -1;
	const char *comm_path = "/proc/self/comm";
	int commfd = -1;
	const char *tmp_path = "/tmp/test_bpf_file_d_path.txt";
	int tmpfd = -1;

	/* open file */
	commfd = open(comm_path, O_RDONLY);
	if (CHECK(commfd < 0, "test_file_d_path", "open %s failed\n", comm_path))
		goto fd_close;

	tmpfd = open(tmp_path, O_CREAT | O_RDONLY, 0644);
	if (CHECK(tmpfd < 0, "test_file_d_path", "open %s failed\n", tmp_path))
		goto fd_close;
	remove(tmp_path);

	/* record file */
	memset(&record, 0, sizeof(record));
	ret = set_pathname(commfd, pid);
	if (CHECK(ret < 0, "test_file_d_path", "set_pathname failed for commfd\n"))
		goto fd_close;
	ret = set_pathname(tmpfd, pid);
	if (CHECK(ret < 0, "test_file_d_path", "set_pathname failed for tmpfd\n"))
		goto fd_close;

	ret = 0;
	/* close file */
fd_close:
	if (commfd != -1)
		close_fd(commfd);
	if (tmpfd != -1)
		close_fd(tmpfd);
	return ret;
}

static void test_base(void)
{
	int err = -1;
	struct test_file_d_path__bss *bss;
	struct test_file_d_path *skel;

	skel = test_file_d_path__open_and_load();
	if (CHECK(!skel, "open_and_load", "load file_d_path skeleton failed\n"))
		goto cleanup;

	err = test_file_d_path__attach(skel);
	if (CHECK(err, "attach", "attach file_d_path failed: %s\n", strerror(errno)))
		goto cleanup;

	bss = skel->bss;
	bss->monitor_pid = getpid();

	err = trigger_filp_close(bss->monitor_pid);
	if (err < 0)
		goto cleanup;

	if (CHECK(bss->bpf_called_cnt != TEST_FILES_NUM,
		"bpf_called_cnt",
		"prog called times diff from with the expectations\n"))
		goto cleanup;

	for (int i = 0; i < TEST_FILES_NUM; i++) {
		CHECK(strncmp(record.paths[i], bss->bpf_paths_close[i], MAX_PATH_LEN),
			"bpf_paths_close",
			"the paths diff from the expectations: id=[%d], path: %s vs %s\n",
			i, record.paths[i], bss->bpf_paths_close[i]);
	}

cleanup:
	test_file_d_path__destroy(skel);
}

void test_file_d_path(void)
{
	test_base();
}
