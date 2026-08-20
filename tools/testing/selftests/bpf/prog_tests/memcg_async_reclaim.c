// SPDX-License-Identifier: GPL-2.0
/*
 * Memory controller eBPF async reclaim test
 */

#include <test_progs.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <linux/magic.h>

#include "cgroup_helpers.h"

struct bpf_args_s {
	u64 high_cgroup_id;
	u64 low_cgroup_id;
	u64 event_delta_threshold;
	u64 check_ns;
};

#include "memcg_async_reclaim.skel.h"

#define FILE_SIZE (32 * 1024 * 1024ul)
#define BUFFER_SIZE (4096)
#define CG_LIMIT (32 * 1024 * 1024ul)
#define READ_TIMES 50

#define CG_DIR "/memcg_async_reclaim"
#define CG_HIGH_DIR CG_DIR "/high"
#define CG_LOW_DIR CG_DIR "/low"

#define CHECK_PERIOD_NS (2 * 1000 * 1000ull)
#define EVENT_DELTA_THRESHOLD 1

/*
 * The workload files must sit on a regular filesystem: with swap
 * disabled for the cgroup, tmpfs/ramfs pages are unevictable and would
 * OOM the cgroup instead of exercising reclaim; they are also charged
 * as anonymous memory, so they never raise the WORKINGSET_REFAULT_FILE
 * events the BPF program monitors. Fall back to the current directory
 * when /tmp is backed by such a filesystem.
 */
static const char *workload_files_dir(void)
{
	struct statfs st;

	if (!statfs("/tmp", &st) &&
	    (st.f_type == TMPFS_MAGIC || st.f_type == RAMFS_MAGIC))
		return ".";
	return "/tmp";
}

/*
 * The workload children run after test_progs hijacked stdio, so
 * anything they print is lost with their private copy of the hijacked
 * buffer. The exit status is the only diagnostics channel that reaches
 * the parent, so each failing step gets its own code.
 */
enum child_exit_code {
	CHILD_EXIT_OK = 0,
	CHILD_EXIT_JOIN_CGROUP,
	CHILD_EXIT_WRITE_FILE,
	CHILD_EXIT_READ_FILE,
	CHILD_EXIT_TIME_FILE,
};

static const char *child_exit_str(int code)
{
	switch (code) {
	case CHILD_EXIT_OK:
		return "success";
	case CHILD_EXIT_JOIN_CGROUP:
		return "join cgroup";
	case CHILD_EXIT_WRITE_FILE:
		return "write data file";
	case CHILD_EXIT_READ_FILE:
		return "read data file";
	case CHILD_EXIT_TIME_FILE:
		return "write time file";
	default:
		return "unknown";
	}
}

static int setup_high_low_cgroups(u64 *high_cgroup_id, u64 *low_cgroup_id)
{
	int ret;
	char limit_buf[20];

	ret = setup_cgroup_environment();
	if (!ASSERT_OK(ret, "setup_cgroup_environment"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup " CG_DIR))
		goto cleanup;
	close(ret);

	ret = enable_controllers(CG_DIR, "memory");
	if (!ASSERT_OK(ret, "enable_controllers"))
		goto cleanup;

	snprintf(limit_buf, sizeof(limit_buf), "%lu", CG_LIMIT);
	ret = write_cgroup_file(CG_DIR, "memory.max", limit_buf);
	if (!ASSERT_OK(ret, "write_cgroup_file memory.max"))
		goto cleanup;

	/*
	 * Keep the workloads from swapping out. With CONFIG_SWAP=n the
	 * memory.swap.max file does not exist, and no swap can happen
	 * anyway, so skip the write.
	 */
	if (!access("/proc/swaps", F_OK)) {
		ret = write_cgroup_file(CG_DIR, "memory.swap.max", "0");
		if (!ASSERT_OK(ret, "write_cgroup_file memory.swap.max"))
			goto cleanup;
	}

	ret = create_and_get_cgroup(CG_HIGH_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup " CG_HIGH_DIR))
		goto cleanup;
	close(ret);

	*high_cgroup_id = get_cgroup_id(CG_HIGH_DIR);
	if (!ASSERT_GT(*high_cgroup_id, 0, "get_cgroup_id"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_LOW_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup " CG_LOW_DIR))
		goto cleanup;
	close(ret);

	*low_cgroup_id = get_cgroup_id(CG_LOW_DIR);
	if (!ASSERT_GT(*low_cgroup_id, 0, "get_cgroup_id"))
		goto cleanup;

	return 0;

cleanup:
	cleanup_cgroup_environment();
	return -1;
}

static int write_file(const char *filename)
{
	int ret = -1;
	size_t written = 0;
	char *buffer;
	FILE *fp;

	fp = fopen(filename, "wb");
	if (!fp)
		goto out;

	buffer = malloc(BUFFER_SIZE);
	if (!buffer)
		goto cleanup_fp;

	memset(buffer, 'A', BUFFER_SIZE);

	while (written < FILE_SIZE) {
		size_t to_write = FILE_SIZE - written < BUFFER_SIZE ?
				  FILE_SIZE - written : BUFFER_SIZE;

		if (fwrite(buffer, 1, to_write, fp) != to_write)
			goto cleanup;
		written += to_write;
	}

	ret = 0;
cleanup:
	free(buffer);
cleanup_fp:
	fclose(fp);
out:
	return ret;
}

static int read_file(const char *filename, int iterations)
{
	int ret = -1;
	long page_size = sysconf(_SC_PAGESIZE);
	char *map;
	size_t i;
	int fd;
	struct stat sb;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		goto out;

	if (fstat(fd, &sb) == -1)
		goto cleanup_fd;

	if (sb.st_size != FILE_SIZE) {
		fprintf(stderr, "File size mismatch: expected %lu, got %lu\n",
			(unsigned long)FILE_SIZE, (unsigned long)sb.st_size);
		goto cleanup_fd;
	}

	map = mmap(NULL, FILE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
		goto cleanup_fd;

	for (int iter = 0; iter < iterations; iter++) {
		for (i = 0; i < FILE_SIZE; i += page_size) {
			/* access a byte to trigger page fault */
			volatile char v = map[i];
			(void)v;
		}
	}

	if (munmap(map, FILE_SIZE) == -1)
		goto cleanup_fd;

	ret = 0;

cleanup_fd:
	close(fd);
out:
	return ret;
}

static int real_test_child_work(const char *cgroup_path, char *data_filename,
				char *time_filename, int read_times)
{
	struct timespec start, end;
	double elapsed;
	FILE *fp;

	if (join_parent_cgroup(cgroup_path))
		return CHILD_EXIT_JOIN_CGROUP;

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (write_file(data_filename))
		return CHILD_EXIT_WRITE_FILE;

	if (read_file(data_filename, read_times))
		return CHILD_EXIT_READ_FILE;

	clock_gettime(CLOCK_MONOTONIC, &end);

	if (!time_filename)
		return CHILD_EXIT_OK;

	elapsed = (end.tv_sec - start.tv_sec) +
		  (end.tv_nsec - start.tv_nsec) / 1000000000.0;
	printf("%.6f\n", elapsed);

	fp = fopen(time_filename, "w");
	if (!fp)
		return CHILD_EXIT_TIME_FILE;
	fprintf(fp, "%.6f", elapsed);
	fclose(fp);

	return CHILD_EXIT_OK;
}

static int get_time(char *time_filename, double *time)
{
	int ret = -1;
	FILE *fp;
	char buf[64];

	fp = fopen(time_filename, "r");
	if (!ASSERT_OK_PTR(fp, "fopen"))
		goto out;

	if (!ASSERT_OK_PTR(fgets(buf, sizeof(buf), fp), "fgets"))
		goto cleanup;

	if (sscanf(buf, "%lf", time) != 1) {
		PRINT_FAIL("sscanf %s", buf);
		goto cleanup;
	}

	ret = 0;
cleanup:
	fclose(fp);
out:
	return ret;
}

static int
run_high_low_workload(double *high_elapsed, double *low_elapsed, int read_times)
{
	char high_data_file[PATH_MAX];
	char low_data_file[PATH_MAX];
	char high_time_file[PATH_MAX];
	char low_time_file[PATH_MAX];
	const char *dir = workload_files_dir();
	pid_t high_pid = -1, low_pid = -1;
	pid_t wait_ret;
	int fd, status;
	int ret = -1;

	snprintf(high_data_file, sizeof(high_data_file),
		 "%s/memcg_async_high_data_XXXXXX", dir);
	snprintf(low_data_file, sizeof(low_data_file),
		 "%s/memcg_async_low_data_XXXXXX", dir);
	snprintf(high_time_file, sizeof(high_time_file),
		 "%s/memcg_async_high_time_XXXXXX", dir);
	snprintf(low_time_file, sizeof(low_time_file),
		 "%s/memcg_async_low_time_XXXXXX", dir);

	fd = mkstemp(high_data_file);
	if (!ASSERT_GE(fd, 0, "mkstemp"))
		goto cleanup;
	close(fd);

	fd = mkstemp(low_data_file);
	if (!ASSERT_GE(fd, 0, "mkstemp"))
		goto cleanup;
	close(fd);

	fd = mkstemp(high_time_file);
	if (!ASSERT_GE(fd, 0, "mkstemp"))
		goto cleanup;
	close(fd);

	fd = mkstemp(low_time_file);
	if (!ASSERT_GE(fd, 0, "mkstemp"))
		goto cleanup;
	close(fd);

	low_pid = fork();
	if (!ASSERT_GE(low_pid, 0, "fork low"))
		goto cleanup;
	if (low_pid == 0)
		_exit(real_test_child_work(CG_LOW_DIR, low_data_file,
					  low_time_file, read_times));

	high_pid = fork();
	if (!ASSERT_GE(high_pid, 0, "fork high"))
		goto cleanup;
	if (high_pid == 0)
		_exit(real_test_child_work(CG_HIGH_DIR, high_data_file,
					  high_time_file, read_times));

	wait_ret = waitpid(low_pid, &status, 0);
	if (!ASSERT_GT(wait_ret, 0, "low waitpid"))
		goto cleanup;
	/*
	 * The child has been reaped and its PID can already be reused,
	 * so mark it to keep cleanup from signaling an unrelated process.
	 */
	low_pid = -1;
	if (!ASSERT_TRUE(WIFEXITED(status), "low exited"))
		goto cleanup;
	if (WEXITSTATUS(status) != CHILD_EXIT_OK) {
		PRINT_FAIL("low child failed at: %s (exit status %d)",
			   child_exit_str(WEXITSTATUS(status)),
			   WEXITSTATUS(status));
		goto cleanup;
	}

	wait_ret = waitpid(high_pid, &status, 0);
	if (!ASSERT_GT(wait_ret, 0, "high waitpid"))
		goto cleanup;
	/* Same as above: the reaped PID must not be signaled again. */
	high_pid = -1;
	if (!ASSERT_TRUE(WIFEXITED(status), "high exited"))
		goto cleanup;
	if (WEXITSTATUS(status) != CHILD_EXIT_OK) {
		PRINT_FAIL("high child failed at: %s (exit status %d)",
			   child_exit_str(WEXITSTATUS(status)),
			   WEXITSTATUS(status));
		goto cleanup;
	}

	if (get_time(high_time_file, high_elapsed))
		goto cleanup;
	if (get_time(low_time_file, low_elapsed))
		goto cleanup;

	ret = 0;

cleanup:
	/* On failure, make sure no child process is left behind */
	if (ret) {
		if (high_pid > 0) {
			kill(high_pid, SIGKILL);
			(void)waitpid(high_pid, NULL, 0);
		}
		if (low_pid > 0) {
			kill(low_pid, SIGKILL);
			(void)waitpid(low_pid, NULL, 0);
		}
	}
	unlink(low_time_file);
	unlink(high_time_file);
	unlink(low_data_file);
	unlink(high_data_file);
	return ret;
}

static int
setup_bpf(u64 high_cgroup_id, u64 low_cgroup_id,
	  struct memcg_async_reclaim **skel_ptr)
{
	struct memcg_async_reclaim *skel;
	struct bpf_args_s bpf_args = {
		.high_cgroup_id = high_cgroup_id,
		.low_cgroup_id = low_cgroup_id,
		.event_delta_threshold = EVENT_DELTA_THRESHOLD,
		.check_ns = CHECK_PERIOD_NS,
	};
	LIBBPF_OPTS(bpf_test_run_opts, run_opts,
		.ctx_in = &bpf_args,
		.ctx_size_in = sizeof(bpf_args));
	int prog_init_fd, err;

	skel = memcg_async_reclaim__open_and_load();
	if (!ASSERT_OK_PTR(skel, "memcg_async_reclaim__open_and_load"))
		return -1;

	prog_init_fd = bpf_program__fd(skel->progs.wq_prog_init);

	err = bpf_prog_test_run_opts(prog_init_fd, &run_opts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		goto error_out;
	if (!ASSERT_EQ(run_opts.retval, 0, "prog_init retval"))
		goto error_out;

	*skel_ptr = skel;
	return 0;

error_out:
	memcg_async_reclaim__destroy(skel);
	return -1;
}

void test_memcg_wq_async_reclaim(void)
{
	u64 high_cgroup_id, low_cgroup_id;
	int err;
	double high_time = 0.0, low_time = 0.0;
	struct memcg_async_reclaim *skel = NULL;

	err = setup_high_low_cgroups(&high_cgroup_id, &low_cgroup_id);
	if (!ASSERT_OK(err, "setup_high_low_cgroups reclaim"))
		return;

	err = setup_bpf(high_cgroup_id, low_cgroup_id, &skel);
	if (!ASSERT_OK(err, "setup_bpf"))
		goto out;

	err = run_high_low_workload(&high_time, &low_time, READ_TIMES);
	if (!ASSERT_OK(err, "run_high_low_workload reclaim"))
		goto out;

	/*
	 * The timing comparison below alone cannot distinguish a working
	 * reclaim from a no-op one, so require that the BPF program
	 * actually reclaimed memory from the low cgroup.
	 */
	if (!ASSERT_GT(skel->bss->reclaim_calls, 0, "reclaim_calls"))
		goto out;
	if (!ASSERT_GT(skel->bss->reclaimed_bytes, 0, "reclaimed_bytes"))
		goto out;

	if (high_time >= low_time)
		PRINT_FAIL("high cgroup not improved with async reclaim: high_time=%f low_time=%f",
			   high_time, low_time);

out:
	if (skel)
		memcg_async_reclaim__destroy(skel);
	cleanup_cgroup_environment();
}
