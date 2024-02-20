// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include <sys/stat.h>
#include <linux/sched.h>
#include <sys/syscall.h>

#define MAX_PATH_LEN		128
#define MAX_FILES		8

#include "test_d_path.skel.h"
#include "test_d_path_check_rdonly_mem.skel.h"
#include "test_d_path_check_types.skel.h"
#include "d_path_kfunc_failure.skel.h"
#include "d_path_kfunc_success.skel.h"

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

static int duration;

struct want {
	bool err;
	long err_code;
	char path[MAX_PATH_LEN];
};

static struct {
	__u32 cnt;
	struct want want[MAX_FILES];
} src;

static int set_pathname(int fd, pid_t pid)
{
	char buf[MAX_PATH_LEN];

	snprintf(buf, MAX_PATH_LEN, "/proc/%d/fd/%d", pid, fd);
	return readlink(buf, src.want[src.cnt++].path, MAX_PATH_LEN);
}

static int trigger_fstat_events(pid_t pid, bool want_error)
{
	int sockfd = -1, procfd = -1, devfd = -1, mntnsfd = -1;
	int localfd = -1, indicatorfd = -1;
	int pipefd[2] = { -1, -1 };
	struct stat fileStat;
	int ret = -1;

	/* unmountable pseudo-filesystems */
	if (CHECK(pipe(pipefd) < 0, "trigger", "pipe failed\n"))
		return ret;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (CHECK(sockfd < 0, "trigger", "socket failed\n"))
		goto out_close;

	mntnsfd = open("/proc/self/ns/mnt", O_RDONLY);
	if (CHECK(mntnsfd < 0, "trigger", "mntnsfd failed"))
		goto out_close;

	/* mountable pseudo-filesystems */
	procfd = open("/proc/self/comm", O_RDONLY);
	if (CHECK(procfd < 0, "trigger", "open /proc/self/comm failed\n"))
		goto out_close;
	devfd = open("/dev/urandom", O_RDONLY);
	if (CHECK(devfd < 0, "trigger", "open /dev/urandom failed\n"))
		goto out_close;
	localfd = open("/tmp/d_path_loadgen.txt", O_CREAT | O_RDONLY, 0644);
	if (CHECK(localfd < 0, "trigger", "open /tmp/d_path_loadgen.txt failed\n"))
		goto out_close;
	/* bpf_d_path will return path with (deleted) */
	remove("/tmp/d_path_loadgen.txt");
	indicatorfd = open("/tmp/", O_PATH);
	if (CHECK(indicatorfd < 0, "trigger", "open /tmp/ failed\n"))
		goto out_close;

	/*
	 * With bpf_d_path() being backed by probe-read semantics, we cannot
	 * safely resolve paths that are comprised of dentries that make use of
	 * dynamic names. We expect to return -EOPNOTSUPP for such paths.
	 */
	src.want[src.cnt].err = want_error;
	src.want[src.cnt].err_code = -EOPNOTSUPP;
	ret = set_pathname(pipefd[0], pid);
	if (CHECK(ret < 0, "trigger", "set_pathname failed for pipe[0]\n"))
		goto out_close;

	src.want[src.cnt].err = want_error;
	src.want[src.cnt].err_code = -EOPNOTSUPP;
	ret = set_pathname(pipefd[1], pid);
	if (CHECK(ret < 0, "trigger", "set_pathname failed for pipe[1]\n"))
		goto out_close;

	src.want[src.cnt].err = want_error;
	src.want[src.cnt].err_code = -EOPNOTSUPP;
	ret = set_pathname(sockfd, pid);
	if (CHECK(ret < 0, "trigger", "set_pathname failed for socket\n"))
		goto out_close;

	src.want[src.cnt].err = want_error;
	src.want[src.cnt].err_code = -EOPNOTSUPP;
	ret = set_pathname(mntnsfd, pid);
	if (CHECK(ret < 0, "trigger", "set_pathname failed for mntnsfd\n"))
		goto out_close;

	ret = set_pathname(procfd, pid);
	if (CHECK(ret < 0, "trigger", "set_pathname failed for proc\n"))
		goto out_close;
	ret = set_pathname(devfd, pid);
	if (CHECK(ret < 0, "trigger", "set_pathname failed for dev\n"))
		goto out_close;
	ret = set_pathname(localfd, pid);
	if (CHECK(ret < 0, "trigger", "set_pathname failed for file\n"))
		goto out_close;
	ret = set_pathname(indicatorfd, pid);
	if (CHECK(ret < 0, "trigger", "set_pathname failed for dir\n"))
		goto out_close;

	/* triggers vfs_getattr */
	fstat(pipefd[0], &fileStat);
	fstat(pipefd[1], &fileStat);
	fstat(sockfd, &fileStat);
	fstat(mntnsfd, &fileStat);
	fstat(procfd, &fileStat);
	fstat(devfd, &fileStat);
	fstat(localfd, &fileStat);
	fstat(indicatorfd, &fileStat);

out_close:
	/* sys_close no longer triggers filp_close, but we can
	 * call sys_close_range instead which still does
	 */
#define close(fd) syscall(__NR_close_range, fd, fd, 0)

	close(pipefd[0]);
	close(pipefd[1]);
	close(sockfd);
	close(mntnsfd);
	close(procfd);
	close(devfd);
	close(localfd);
	close(indicatorfd);

#undef close
	return ret;
}

static void test_bpf_d_path_basic(void)
{
	struct test_d_path__bss *bss;
	struct test_d_path *skel;
	int err;

	/*
	 * Carrying global state across test function invocations is super
	 * gross, but it was late and I was tired and I just wanted to get the
	 * darn test working. Zero'ing this out was a simple no brainer.
	 */
	memset(&src, 0, sizeof(src));

	skel = test_d_path__open_and_load();
	if (CHECK(!skel, "setup", "d_path skeleton failed\n"))
		goto cleanup;

	err = test_d_path__attach(skel);
	if (CHECK(err, "setup", "attach failed: %d\n", err))
		goto cleanup;

	bss = skel->bss;
	bss->my_pid = getpid();

	err = trigger_fstat_events(bss->my_pid, /*want_error=*/true);
	if (err < 0)
		goto cleanup;

	if (CHECK(!bss->called_stat,
		  "stat",
		  "trampoline for security_inode_getattr was not called\n"))
		goto cleanup;

	if (CHECK(!bss->called_close,
		  "close",
		  "trampoline for filp_close was not called\n"))
		goto cleanup;

	for (int i = 0; i < MAX_FILES; i++) {
		struct want want = src.want[i];

		/*
		 * Assert that we get the correct error code from bpf_d_path()
		 * when the underlying path contains a dentry that is backed by
		 * a dynamic name.
		 */
		if (want.err) {
			CHECK(want.err_code != bss->rets_stat[i], "check",
			      "failed to match stat return[%d]: got=%d, want=%ld [%s]\n",
			      i, bss->rets_stat[i], want.err_code,
			      bss->paths_stat[i]);
			CHECK(want.err_code != bss->rets_close[i], "check",
			      "failed to match close return[%d]: got=%d, want=%ld [%s]\n",
			      i, bss->rets_close[i], want.err_code,
			      bss->paths_close[i]);
			continue;
		}

		CHECK(strncmp(want.path, bss->paths_stat[i], MAX_PATH_LEN),
		      "check", "failed to get stat path[%d]: %s vs %s\n", i,
		      want.path, bss->paths_stat[i]);
		CHECK(strncmp(want.path, bss->paths_close[i], MAX_PATH_LEN),
		      "check", "failed to get close path[%d]: %s vs %s\n", i,
		      want.path, bss->paths_close[i]);
		/* The d_path helper returns size plus NUL char, hence + 1 */
		CHECK(bss->rets_stat[i] != strlen(bss->paths_stat[i]) + 1,
		      "check",
		      "failed to match stat return [%d]: %d vs %zd [%s]\n", i,
		      bss->rets_stat[i], strlen(bss->paths_stat[i]) + 1,
		      bss->paths_stat[i]);
		CHECK(bss->rets_close[i] != strlen(bss->paths_stat[i]) + 1,
		      "check",
		      "failed to match stat return [%d]: %d vs %zd [%s]\n", i,
		      bss->rets_close[i], strlen(bss->paths_close[i]) + 1,
		      bss->paths_stat[i]);
	}

cleanup:
	test_d_path__destroy(skel);
}

static void test_bpf_d_path_check_rdonly_mem(void)
{
	struct test_d_path_check_rdonly_mem *skel;

	skel = test_d_path_check_rdonly_mem__open_and_load();
	ASSERT_ERR_PTR(skel, "unexpected_load_overwriting_rdonly_mem");

	test_d_path_check_rdonly_mem__destroy(skel);
}

static void test_bpf_d_path_check_types(void)
{
	struct test_d_path_check_types *skel;

	skel = test_d_path_check_types__open_and_load();
	ASSERT_ERR_PTR(skel, "unexpected_load_passing_wrong_type");

	test_d_path_check_types__destroy(skel);
}

static struct bpf_path_d_path_t {
	const char *prog_name;
} success_test_cases[] = {
	{
		.prog_name = "path_d_path_from_path_argument",
	},
};

static void test_bpf_path_d_path(struct bpf_path_d_path_t *t)
{
	int i, ret;
	struct bpf_link *link;
	struct bpf_program *prog;
	struct d_path_kfunc_success__bss *bss;
	struct d_path_kfunc_success *skel;

	/*
	 * Carrying global state across function invocations is super gross, but
	 * it was late and I was tired and I just wanted to get the darn test
	 * working. Zero'ing this out was a simple no brainer.
	 */
	memset(&src, 0, sizeof(src));

	skel = d_path_kfunc_success__open();
	if (!ASSERT_OK_PTR(skel, "d_path_kfunc_success__open"))
		return;

	bss = skel->bss;
	bss->my_pid = getpid();

	ret = d_path_kfunc_success__load(skel);
	if (CHECK(ret, "setup", "d_path_kfunc_success__load\n"))
		goto cleanup;

	link = NULL;
	prog = bpf_object__find_program_by_name(skel->obj, t->prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach"))
		goto cleanup;

	ret = trigger_fstat_events(bss->my_pid, /*want_error=*/false);
	if (ret < 0)
		goto cleanup;

	for (i = 0; i < MAX_FILES; i++) {
		struct want want = src.want[i];
		CHECK(strncmp(want.path, bss->paths_stat[i], MAX_PATH_LEN),
		      "check", "failed to get stat path[%d]: %s vs %s\n", i,
		      want.path, bss->paths_stat[i]);
		CHECK(bss->rets_stat[i] != strlen(bss->paths_stat[i]) + 1,
		      "check",
		      "failed to match stat return [%d]: %d vs %zd [%s]\n",
		      i, bss->rets_stat[i], strlen(bss->paths_stat[i]) + 1,
		      bss->paths_stat[i]);
	}
cleanup:
	bpf_link__destroy(link);
	d_path_kfunc_success__destroy(skel);
}

void test_d_path(void)
{
	int i = 0;

	if (test__start_subtest("basic"))
		test_bpf_d_path_basic();

	if (test__start_subtest("check_rdonly_mem"))
		test_bpf_d_path_check_rdonly_mem();

	if (test__start_subtest("check_alloc_mem"))
		test_bpf_d_path_check_types();

	for (; i < ARRAY_SIZE(success_test_cases); i++) {
		if (!test__start_subtest(success_test_cases[i].prog_name))
			continue;
		test_bpf_path_d_path(&success_test_cases[i]);
	}

	RUN_TESTS(d_path_kfunc_failure);
}
