// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include <sys/stat.h>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define MAX_PATH_LEN		128
#define MAX_FILES		7

#include "test_d_path.skel.h"
#include "test_d_path_check_rdonly_mem.skel.h"
#include "test_d_path_check_types.skel.h"

/* sys_close_range is not around for long time, so let's
 * make sure we can call it on systems with older glibc
 */
#ifndef __NR_close_range
#ifdef __alpha__
#define __NR_close_range 546
#else
#define __NR_close_range 436
#endif
#endif

static struct {
	__u32 cnt;
	char paths[MAX_FILES][MAX_PATH_LEN];
} src;

static int set_pathname(int fd, pid_t pid)
{
	char buf[MAX_PATH_LEN];

	snprintf(buf, MAX_PATH_LEN, "/proc/%d/fd/%d", pid, fd);
	return readlink(buf, src.paths[src.cnt++], MAX_PATH_LEN);
}

static inline long syscall_close(int fd)
{
	return syscall(__NR_close_range,
			(unsigned int)fd,
			(unsigned int)fd,
			0u);
}

static int trigger_fstat_events(pid_t pid)
{
	int sockfd = -1, procfd = -1, devfd = -1;
	int localfd = -1, indicatorfd = -1;
	int pipefd[2] = { -1, -1 };
	struct stat fileStat;
	int ret = -1;

	/* unmountable pseudo-filesystems */
	if (!ASSERT_OK(pipe(pipefd), "pipe"))
		return ret;
	/* unmountable pseudo-filesystems */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_OK_FD(sockfd, "socket"))
		goto out_close;
	/* mountable pseudo-filesystems */
	procfd = open("/proc/self/comm", O_RDONLY);
	if (!ASSERT_OK_FD(procfd, "open /proc/self/comm"))
		goto out_close;
	devfd = open("/dev/urandom", O_RDONLY);
	if (!ASSERT_OK_FD(devfd, "open /dev/urandom"))
		goto out_close;
	localfd = open("/tmp/d_path_loadgen.txt", O_CREAT | O_RDONLY, 0644);
	if (!ASSERT_OK_FD(localfd, "open /tmp/d_path_loadgen.txt"))
		goto out_close;
	/* bpf_d_path will return path with (deleted) */
	remove("/tmp/d_path_loadgen.txt");
	indicatorfd = open("/tmp/", O_PATH);
	if (!ASSERT_OK_FD(indicatorfd, "open /tmp/"))
		goto out_close;

	ret = set_pathname(pipefd[0], pid);
	if (!ASSERT_GE(ret, 0, "set_pathname for pipe[0]"))
		goto out_close;
	ret = set_pathname(pipefd[1], pid);
	if (!ASSERT_GE(ret, 0, "set_pathname for pipe[1]"))
		goto out_close;
	ret = set_pathname(sockfd, pid);
	if (!ASSERT_GE(ret, 0, "set_pathname for socket"))
		goto out_close;
	ret = set_pathname(procfd, pid);
	if (!ASSERT_GE(ret, 0, "set_pathname for proc"))
		goto out_close;
	ret = set_pathname(devfd, pid);
	if (!ASSERT_GE(ret, 0, "set_pathname for dev"))
		goto out_close;
	ret = set_pathname(localfd, pid);
	if (!ASSERT_GE(ret, 0, "set_pathname for file"))
		goto out_close;
	ret = set_pathname(indicatorfd, pid);
	if (!ASSERT_GE(ret, 0, "set_pathname for dir"))
		goto out_close;

	/* triggers vfs_getattr */
	fstat(pipefd[0], &fileStat);
	fstat(pipefd[1], &fileStat);
	fstat(sockfd, &fileStat);
	fstat(procfd, &fileStat);
	fstat(devfd, &fileStat);
	fstat(localfd, &fileStat);
	fstat(indicatorfd, &fileStat);

out_close:
	/*
	 * filp_close_sync() may be inlined into close(2), so use
	 * close_range(2), which calls it directly.
	 */
	syscall_close(pipefd[0]);
	syscall_close(pipefd[1]);
	syscall_close(sockfd);
	syscall_close(procfd);
	syscall_close(devfd);
	syscall_close(localfd);
	syscall_close(indicatorfd);
	return ret;
}

static void attach_and_load(struct test_d_path **skel)
{
	int err;

	*skel = test_d_path__open_and_load();
	if (!ASSERT_OK_PTR(*skel, "d_path skeleton"))
		goto cleanup;

	err = test_d_path__attach(*skel);
	if (!ASSERT_OK(err, "attach"))
		goto cleanup;

	(*skel)->bss->my_pid = getpid();
	return;

cleanup:
	test_d_path__destroy(*skel);
	*skel = NULL;
}

static void test_d_path_basic(void)
{
	struct test_d_path__bss *bss;
	struct test_d_path *skel;
	int err;

	attach_and_load(&skel);
	if (!skel)
		goto cleanup;

	bss = skel->bss;

	err = trigger_fstat_events(bss->my_pid);
	if (err < 0)
		goto cleanup;

	if (!ASSERT_TRUE(bss->called_stat, "called_stat"))
		goto cleanup;

	if (!ASSERT_TRUE(bss->called_close, "called_close"))
		goto cleanup;

	for (int i = 0; i < MAX_FILES; i++) {
		ASSERT_STRNEQ(bss->paths_stat[i], src.paths[i], MAX_PATH_LEN, "stat path");
		ASSERT_STRNEQ(bss->paths_close[i], src.paths[i], MAX_PATH_LEN, "close path");
		/* The d_path helper returns size plus NUL char, hence + 1 */
		ASSERT_EQ(bss->rets_stat[i], strlen(bss->paths_stat[i]) + 1, "stat return");
		ASSERT_EQ(bss->rets_close[i], strlen(bss->paths_stat[i]) + 1, "close return");
	}

cleanup:
	test_d_path__destroy(skel);
}

static void test_d_path_check_rdonly_mem(void)
{
	struct test_d_path_check_rdonly_mem *skel;

	skel = test_d_path_check_rdonly_mem__open_and_load();
	ASSERT_ERR_PTR(skel, "unexpected_load_overwriting_rdonly_mem");

	test_d_path_check_rdonly_mem__destroy(skel);
}

static void test_d_path_check_types(void)
{
	struct test_d_path_check_types *skel;

	skel = test_d_path_check_types__open_and_load();
	ASSERT_ERR_PTR(skel, "unexpected_load_passing_wrong_type");

	test_d_path_check_types__destroy(skel);
}

/* Check if the verifier correctly generates code for
 * accessing the memory modified by d_path helper.
 */
static void test_d_path_mem_access(void)
{
	int localfd = -1;
	struct test_d_path__bss *bss;
	struct test_d_path *skel;

	attach_and_load(&skel);
	if (!skel)
		goto cleanup;

	bss = skel->bss;

	localfd = memfd_create("d_path_loadgen", 0);
	if (!ASSERT_OK_FD(localfd, "memfd_create"))
		goto cleanup;

	if (!ASSERT_OK(fallocate(localfd, 0, 0, 1024), "fallocate"))
		goto cleanup;

	if (!ASSERT_TRUE(bss->path_match_fallocate, "fallocate path"))
		goto cleanup;

cleanup:
	syscall_close(localfd);
	test_d_path__destroy(skel);
}

void test_d_path(void)
{
	if (test__start_subtest("basic"))
		test_d_path_basic();

	if (test__start_subtest("check_rdonly_mem"))
		test_d_path_check_rdonly_mem();

	if (test__start_subtest("check_alloc_mem"))
		test_d_path_check_types();

	if (test__start_subtest("check_mem_access"))
		test_d_path_mem_access();
}
