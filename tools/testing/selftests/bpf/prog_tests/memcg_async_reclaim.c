// SPDX-License-Identifier: GPL-2.0
/*
 * Memory controller eBPF async reclaim test
 *
 * Setting TEST_MEMCG_ASYNC_RECLAIM_BENCH=1 adds a baseline run of the
 * workload without the BPF program to memcg_async_reclaim, and prints
 * the baseline and reclaim timings, plus the speedup of the pressured
 * cgroup, to stdout. The cgroups are recreated between the two runs so
 * that both start from the same cold state.
 */

#include <test_progs.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <linux/magic.h>

#include "cgroup_helpers.h"

struct bpf_args {
	u64 high_cgroup_id;
	u64 low_cgroup_id;
	u64 event_delta_threshold;
	u64 check_ns;
};

/* Reclaim outcomes reported by the BPF program through the ringbuf. */
enum reclaim_outcome {
	RECLAIM_OUTCOME_CALLED,
	RECLAIM_OUTCOME_SKIPPED_DYING,
	RECLAIM_OUTCOME_TARGET_GONE,
};

struct reclaim_event {
	u64 outcome;
};

#include "memcg_async_reclaim.skel.h"

#define FILE_SIZE (32 * 1024 * 1024ul)
#define BUFFER_SIZE (4096)
#define CG_LIMIT (32 * 1024 * 1024ul)
#define READ_TIMES 50

#define CG_DIR "/memcg_async_reclaim"
#define CG_HIGH_DIR CG_DIR "/high"
#define CG_LOW_DIR CG_DIR "/low"

#define CG_DYING_DIR "/memcg_async_reclaim_dying"
#define CG_DYING_TRIGGER_DIR CG_DYING_DIR "/trigger"
#define CG_DYING_TARGET_DIR CG_DYING_DIR "/target"

#define CHECK_PERIOD_NS (2 * 1000 * 1000ull)
#define EVENT_DELTA_THRESHOLD 1

/*
 * Timing for the dying test: after the target cgroup is removed, give
 * in-flight reclaim passes time to drain, then wait for a reclaim round
 * to hit the removed target. The keepalive reader keeps the trigger
 * cgroup refaulting, and the timer fires every CHECK_PERIOD_NS, so
 * such a round must show up within a few timer periods. The BPF
 * program reports every reclaim outcome through the ringbuf, so the
 * waits just poll it with a timeout.
 */
#define DYING_SETTLE_US (200 * 1000)
#define EVENT_POLL_TIMEOUT_MS (100)
#define EVENT_POLL_ROUNDS (50)

static bool usable_for_workload_files(const char *dir)
{
	struct statfs st;

	if (statfs(dir, &st))
		return false;

	return st.f_type != TMPFS_MAGIC && st.f_type != RAMFS_MAGIC;
}

/*
 * The workload files must sit on a regular filesystem: with swap
 * disabled for the cgroup, tmpfs/ramfs pages are unevictable and would
 * OOM the cgroup instead of exercising reclaim; they are also charged
 * as anonymous memory, so they never raise the WORKINGSET_REFAULT_FILE
 * events the BPF program monitors.
 *
 * /tmp is tmpfs on many systems, so fall back to the current directory.
 * That fallback needs the very same check: test_progs is routinely run
 * from a tmpfs working directory, and silently landing there produces an
 * OOM that looks like a reclaim failure. Returns NULL when neither
 * directory is usable, in which case the workload cannot run at all.
 */
static const char *workload_files_dir(void)
{
	if (usable_for_workload_files("/tmp"))
		return "/tmp";
	if (usable_for_workload_files("."))
		return ".";

	return NULL;
}

/*
 * Keep the workload from swapping out, so that reclaim has to evict page
 * cache instead. memory.swap.max only exists when the kernel is built with
 * CONFIG_SWAP, and /proc/swaps is registered by the same CONFIG_SWAP-gated
 * code (mm/swapfile.c), so it stands in for the file here. With CONFIG_SWAP=n
 * no swap can happen anyway, so skipping the write is the correct behaviour.
 */
static int disable_swap(const char *cgroup_dir)
{
	if (access("/proc/swaps", F_OK))
		return 0;

	return write_cgroup_file(cgroup_dir, "memory.swap.max", "0");
}

/*
 * The forked children run after test_progs hijacked stdio, so anything
 * they print is lost with their private copy of the hijacked buffer
 * unless the test runs under -v. The exit status is the one diagnostics
 * channel that always reaches the parent, so each failing step gets its
 * own code.
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

	ret = disable_swap(CG_DIR);
	if (!ASSERT_OK(ret, "disable_swap"))
		goto cleanup;

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

/*
 * The dying test needs an empty reclaim target plus a cgroup that keeps
 * refaulting while the target is removed, so reclaim rounds keep
 * starting and run into the removed target. The two have to be separate
 * cgroups: the target must hold no processes to be removed, and v2's
 * no-internal-process constraint keeps the refaulting workload out of
 * any parent that has domain children.
 */
static int setup_dying_cgroups(u64 *trigger_cgroup_id, u64 *target_cgroup_id)
{
	int ret;
	char limit_buf[20];

	ret = setup_cgroup_environment();
	if (!ASSERT_OK(ret, "setup_cgroup_environment"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_DYING_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup " CG_DYING_DIR))
		goto cleanup;
	close(ret);

	ret = enable_controllers(CG_DYING_DIR, "memory");
	if (!ASSERT_OK(ret, "enable_controllers"))
		goto cleanup;

	snprintf(limit_buf, sizeof(limit_buf), "%lu", CG_LIMIT);
	ret = write_cgroup_file(CG_DYING_DIR, "memory.max", limit_buf);
	if (!ASSERT_OK(ret, "write_cgroup_file memory.max"))
		goto cleanup;

	ret = disable_swap(CG_DYING_DIR);
	if (!ASSERT_OK(ret, "disable_swap"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_DYING_TRIGGER_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup " CG_DYING_TRIGGER_DIR))
		goto cleanup;
	close(ret);

	*trigger_cgroup_id = get_cgroup_id(CG_DYING_TRIGGER_DIR);
	if (!ASSERT_GT(*trigger_cgroup_id, 0, "get_cgroup_id"))
		goto cleanup;

	ret = create_and_get_cgroup(CG_DYING_TARGET_DIR);
	if (!ASSERT_GE(ret, 0, "create_and_get_cgroup " CG_DYING_TARGET_DIR))
		goto cleanup;
	close(ret);

	*target_cgroup_id = get_cgroup_id(CG_DYING_TARGET_DIR);
	if (!ASSERT_GT(*target_cgroup_id, 0, "get_cgroup_id"))
		goto cleanup;

	return 0;

cleanup:
	cleanup_cgroup_environment();
	return -1;
}

static int write_file(int fd)
{
	int ret = -1;
	size_t written = 0;
	char *buffer;

	buffer = malloc(BUFFER_SIZE);
	if (!buffer)
		goto out;

	memset(buffer, 'A', BUFFER_SIZE);

	while (written < FILE_SIZE) {
		size_t to_write = FILE_SIZE - written < BUFFER_SIZE ?
				  FILE_SIZE - written : BUFFER_SIZE;
		ssize_t n = write(fd, buffer, to_write);

		if (n <= 0)
			goto cleanup;
		written += n;
	}

	ret = 0;
cleanup:
	free(buffer);
out:
	return ret;
}

static int read_file(int fd, int iterations)
{
	long page_size = sysconf(_SC_PAGESIZE);
	struct stat sb;
	char *map;
	size_t i;

	if (fstat(fd, &sb) == -1)
		return -1;

	if (sb.st_size != FILE_SIZE) {
		fprintf(stderr, "File size mismatch: expected %lu, got %lu\n",
			(unsigned long)FILE_SIZE, (unsigned long)sb.st_size);
		return -1;
	}

	map = mmap(NULL, FILE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
		return -1;

	for (int iter = 0; iter < iterations; iter++) {
		for (i = 0; i < FILE_SIZE; i += page_size) {
			/* access a byte to trigger page fault */
			volatile char v = map[i];
			(void)v;
		}
	}

	if (munmap(map, FILE_SIZE) == -1)
		return -1;

	return 0;
}

static int real_test_child_work(const char *cgroup_path, int data_fd,
				int time_fd, int read_times)
{
	struct timespec start, end;
	double elapsed;
	char buf[32];
	int len;

	if (join_parent_cgroup(cgroup_path))
		return CHILD_EXIT_JOIN_CGROUP;

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (write_file(data_fd))
		return CHILD_EXIT_WRITE_FILE;

	if (read_file(data_fd, read_times))
		return CHILD_EXIT_READ_FILE;

	clock_gettime(CLOCK_MONOTONIC, &end);

	elapsed = (end.tv_sec - start.tv_sec) +
		  (end.tv_nsec - start.tv_nsec) / 1000000000.0;

	len = snprintf(buf, sizeof(buf), "%.6f", elapsed);
	/* snprintf() returns the untruncated length, so bound it before write() */
	if (len < 0 || len >= (int)sizeof(buf) || write(time_fd, buf, len) != len)
		return CHILD_EXIT_TIME_FILE;

	return CHILD_EXIT_OK;
}

static int get_time(int fd, double *time)
{
	char buf[64] = {};
	ssize_t n;

	/* The child wrote through the fork-shared description, so rewind. */
	if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		PRINT_FAIL("lseek time file");
		return -1;
	}

	n = read(fd, buf, sizeof(buf) - 1);
	if (!ASSERT_GT(n, 0, "read time file"))
		return -1;

	if (sscanf(buf, "%lf", time) != 1) {
		PRINT_FAIL("sscanf %s", buf);
		return -1;
	}

	return 0;
}

static int
run_high_low_workload(const char *dir, double *high_elapsed, double *low_elapsed,
		      int read_times)
{
	char high_data_file[PATH_MAX];
	char low_data_file[PATH_MAX];
	char high_time_file[PATH_MAX];
	char low_time_file[PATH_MAX];
	int high_data_fd = -1, low_data_fd = -1;
	int high_time_fd = -1, low_time_fd = -1;
	pid_t high_pid = -1, low_pid = -1;
	pid_t wait_ret;
	int status;
	int ret = -1;

	snprintf(high_data_file, sizeof(high_data_file),
		 "%s/memcg_async_high_data_XXXXXX", dir);
	snprintf(low_data_file, sizeof(low_data_file),
		 "%s/memcg_async_low_data_XXXXXX", dir);
	snprintf(high_time_file, sizeof(high_time_file),
		 "%s/memcg_async_high_time_XXXXXX", dir);
	snprintf(low_time_file, sizeof(low_time_file),
		 "%s/memcg_async_low_time_XXXXXX", dir);

	/*
	 * The mkstemp() fds are kept and inherited by the children rather
	 * than reopened by name: reopening would resolve the path again and
	 * follow whatever sits there by then.
	 */
	high_data_fd = mkstemp(high_data_file);
	if (!ASSERT_GE(high_data_fd, 0, "mkstemp high data"))
		goto cleanup;

	low_data_fd = mkstemp(low_data_file);
	if (!ASSERT_GE(low_data_fd, 0, "mkstemp low data"))
		goto cleanup;

	high_time_fd = mkstemp(high_time_file);
	if (!ASSERT_GE(high_time_fd, 0, "mkstemp high time"))
		goto cleanup;

	low_time_fd = mkstemp(low_time_file);
	if (!ASSERT_GE(low_time_fd, 0, "mkstemp low time"))
		goto cleanup;

	low_pid = fork();
	if (!ASSERT_GE(low_pid, 0, "fork low"))
		goto cleanup;
	if (low_pid == 0)
		_exit(real_test_child_work(CG_LOW_DIR, low_data_fd,
					   low_time_fd, read_times));

	high_pid = fork();
	if (!ASSERT_GE(high_pid, 0, "fork high"))
		goto cleanup;
	if (high_pid == 0)
		_exit(real_test_child_work(CG_HIGH_DIR, high_data_fd,
					   high_time_fd, read_times));

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

	if (get_time(high_time_fd, high_elapsed))
		goto cleanup;
	if (get_time(low_time_fd, low_elapsed))
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
	if (high_data_fd >= 0)
		close(high_data_fd);
	if (low_data_fd >= 0)
		close(low_data_fd);
	if (high_time_fd >= 0)
		close(high_time_fd);
	if (low_time_fd >= 0)
		close(low_time_fd);
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
	struct bpf_args args = {
		.high_cgroup_id = high_cgroup_id,
		.low_cgroup_id = low_cgroup_id,
		.event_delta_threshold = EVENT_DELTA_THRESHOLD,
		.check_ns = CHECK_PERIOD_NS,
	};
	LIBBPF_OPTS(bpf_test_run_opts, run_opts,
		.ctx_in = &args,
		.ctx_size_in = sizeof(args));
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

/*
 * A timer that stopped rearming produces no further reclaim rounds, which
 * the "no events" failures below would otherwise report as a kernel bug.
 * Only call this on a path that is already failing.
 */
static void report_timer_failures(struct memcg_async_reclaim *skel)
{
	u64 failures = skel->bss->timer_failures;

	if (failures)
		PRINT_FAIL("bpf_timer failed to rearm %llu time(s), so the reclaim loop stopped",
			   (unsigned long long)failures);
}

/*
 * A kfunc that fails on every call is indistinguishable from a cgroup with
 * nothing left to reclaim, which the reclaim_calls and reclaimed_bytes
 * assertions below cannot tell apart. Only call this on a path that is
 * already failing.
 */
static void report_reclaim_errors(struct memcg_async_reclaim *skel)
{
	u64 last_err = skel->bss->last_reclaim_err;

	if (last_err)
		PRINT_FAIL("bpf_proactive_reclaim() last failed with -%llu, nothing was reclaimed",
			   (unsigned long long)last_err);
}

/*
 * The benchmark numbers are only interesting when the test passes, but
 * dump_test_log() drops the captured log unless the test failed or -v was
 * given, so they have to bypass the hijack. The ?: stdout fallback is
 * required, not defensive: stdio_hijack() returns early in verbose mode and
 * never sets env.stdout_saved.
 *
 * This also bypasses the worker-to-dispatcher log protocol, so under -j the
 * line can interleave with the per-test records. It carries no '#' prefix:
 * test_progs uses that only for its own result records, and print_test_log()
 * dumps free-form test output verbatim.
 */
static void bench_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(env.stdout_saved ?: stdout, fmt, ap);
	va_end(ap);
}

void test_memcg_async_reclaim(void)
{
	u64 high_cgroup_id, low_cgroup_id;
	double high_time = 0.0, low_time = 0.0;
	double base_high_time = 0.0, base_low_time = 0.0;
	struct memcg_async_reclaim *skel = NULL;
	const char *dir;
	int err, bench;

	dir = workload_files_dir();
	if (!ASSERT_TRUE(dir != NULL, "workload_files_dir"))
		return;

	bench = !!getenv("TEST_MEMCG_ASYNC_RECLAIM_BENCH");

	err = setup_high_low_cgroups(&high_cgroup_id, &low_cgroup_id);
	if (!ASSERT_OK(err, "setup_high_low_cgroups reclaim"))
		return;

	/*
	 * Optional baseline for the benchmark numbers below: run the
	 * same workload once without the BPF program, so the log can
	 * report how much async reclaim improved the pressured cgroup.
	 */
	if (bench) {
		err = run_high_low_workload(dir, &base_high_time,
					    &base_low_time, READ_TIMES);
		if (!ASSERT_OK(err, "run_high_low_workload baseline"))
			goto out;

		/*
		 * The baseline left up to CG_LIMIT of page cache charged to the
		 * high and low cgroups, and memcg charges outlive the workload
		 * processes. Recreate the cgroups so that the instrumented run
		 * below starts from the same cold state the baseline did;
		 * otherwise the reported speedup compares a cold run against a
		 * warm one.
		 */
		cleanup_cgroup_environment();
		err = setup_high_low_cgroups(&high_cgroup_id, &low_cgroup_id);
		if (!ASSERT_OK(err, "setup_high_low_cgroups after baseline"))
			goto out;
	}

	err = setup_bpf(high_cgroup_id, low_cgroup_id, &skel);
	if (!ASSERT_OK(err, "setup_bpf"))
		goto out;

	err = run_high_low_workload(dir, &high_time, &low_time, READ_TIMES);
	if (!ASSERT_OK(err, "run_high_low_workload reclaim"))
		goto out;

	/*
	 * Timing alone cannot distinguish a working reclaim from a no-op
	 * one, so require that the BPF program actually reclaimed memory
	 * from the low cgroup.
	 */
	if (!ASSERT_GT(skel->bss->reclaim_calls, 0, "reclaim_calls")) {
		report_timer_failures(skel);
		report_reclaim_errors(skel);
		goto out;
	}
	if (!ASSERT_GT(skel->bss->reclaimed_bytes, 0, "reclaimed_bytes")) {
		report_reclaim_errors(skel);
		goto out;
	}

	/*
	 * The timing comparison is a benchmark and too flaky to fail CI
	 * runs, so it only logs the numbers; the counters above already
	 * proved that the BPF program reclaimed memory.
	 */
	if (bench && base_high_time > 0.0)
		bench_printf("memcg_async_reclaim: baseline high=%f low=%f, "
			     "reclaim high=%f low=%f, high speedup=%.1f%%\n",
			     base_high_time, base_low_time, high_time, low_time,
			     100.0 * (base_high_time - high_time) / base_high_time);

out:
	if (skel)
		memcg_async_reclaim__destroy(skel);
	cleanup_cgroup_environment();
}

/*
 * Keep refaults flowing through the trigger cgroup so reclaim rounds
 * keep being triggered while the target cgroup is being removed. The
 * child joins the trigger cgroup and writes the data file there, so
 * that the file pages are charged to the trigger cgroup and actually
 * come under its memory limit; then it re-reads the file in a loop
 * until it is killed.
 */
static pid_t spawn_keepalive_reader(int data_fd)
{
	pid_t pid = fork();

	if (pid != 0)
		return pid;

	if (join_parent_cgroup(CG_DYING_TRIGGER_DIR))
		_exit(CHILD_EXIT_JOIN_CGROUP);
	if (write_file(data_fd))
		_exit(CHILD_EXIT_WRITE_FILE);
	for (;;) {
		if (read_file(data_fd, READ_TIMES))
			_exit(CHILD_EXIT_READ_FILE);
	}
}

/* Reclaim outcomes observed so far, tallied from ringbuf events. */
struct reclaim_events_seen {
	int called;
	int skipped_dying;
	int target_gone;
};

static int on_reclaim_event(void *ctx, void *data, size_t sz)
{
	struct reclaim_events_seen *seen = ctx;
	const struct reclaim_event *ev = data;

	if (sz < sizeof(*ev))
		return 0;

	switch (ev->outcome) {
	case RECLAIM_OUTCOME_CALLED:
		seen->called++;
		break;
	case RECLAIM_OUTCOME_SKIPPED_DYING:
		seen->skipped_dying++;
		break;
	case RECLAIM_OUTCOME_TARGET_GONE:
		seen->target_gone++;
		break;
	}

	return 0;
}

/*
 * Remove the reclaim target while the BPF program keeps running and verify
 * that reclaim stops instead of reclaiming from the removed cgroup.
 *
 * The target stays empty; the workload lives in the trigger cgroup and only
 * keeps refaults flowing so that reclaim rounds keep starting, both before
 * and after the target is removed. A CALLED event while the target is alive
 * proves that rounds really run (the kfunc returns 0 on the empty target, but
 * the call is still counted).
 *
 * Once rmdir has returned, bpf_cgroup_from_id() has already stopped resolving
 * the target: kernfs deactivates the directory node inside the rmdir syscall,
 * see cgroup_is_dying() in the BPF program. TARGET_GONE is therefore the
 * outcome this test can rely on, and the one it asserts. SKIPPED_DYING needs
 * an attempt to land in the short window between cgroup_destroy_locked()
 * clearing CSS_ONLINE and kernfs_remove() deactivating the node, so it is
 * counted and reported on failure but never required.
 */
void test_memcg_async_reclaim_dying(void)
{
	u64 trigger_cgroup_id, target_cgroup_id;
	char data_file[PATH_MAX] = "";
	struct reclaim_events_seen seen = {};
	struct memcg_async_reclaim *skel = NULL;
	struct ring_buffer *rb = NULL;
	u64 calls_before;
	const char *dir;
	pid_t reader_pid = -1;
	int data_fd = -1;
	int err, status, i, n;

	dir = workload_files_dir();
	if (!ASSERT_TRUE(dir != NULL, "workload_files_dir"))
		return;

	err = setup_dying_cgroups(&trigger_cgroup_id, &target_cgroup_id);
	if (!ASSERT_OK(err, "setup_dying_cgroups"))
		return;

	err = setup_bpf(trigger_cgroup_id, target_cgroup_id, &skel);
	if (!ASSERT_OK(err, "setup_bpf"))
		goto out;

	rb = ring_buffer__new(bpf_map__fd(skel->maps.reclaim_events),
			      on_reclaim_event, &seen, NULL);
	if (!ASSERT_OK_PTR(rb, "ring_buffer__new"))
		goto out;

	snprintf(data_file, sizeof(data_file),
		 "%s/memcg_async_dying_XXXXXX", dir);
	/* Kept open and inherited, see run_high_low_workload(). */
	data_fd = mkstemp(data_file);
	if (!ASSERT_GE(data_fd, 0, "mkstemp"))
		goto out;

	reader_pid = spawn_keepalive_reader(data_fd);
	if (!ASSERT_GT(reader_pid, 0, "fork keepalive reader"))
		goto out;

	/* Wait for reclaim rounds to reach the live target cgroup. */
	for (i = 0; i < EVENT_POLL_ROUNDS && !seen.called; i++) {
		n = ring_buffer__poll(rb, EVENT_POLL_TIMEOUT_MS);
		if (!ASSERT_GE(n, 0, "ring_buffer__poll"))
			goto out;

		/*
		 * The reader loops until killed, so finding it already gone
		 * means the refaults the BPF program waits for never started.
		 * Report its exit code rather than letting the assert below
		 * blame the kernel for the full poll window.
		 */
		if (waitpid(reader_pid, &status, WNOHANG) == reader_pid) {
			/* Reaped, so cleanup must not signal a reused PID. */
			reader_pid = -1;
			if (WIFEXITED(status))
				PRINT_FAIL("keepalive reader exited early: %s",
					   child_exit_str(WEXITSTATUS(status)));
			else
				PRINT_FAIL("keepalive reader died, status 0x%x",
					   status);
			goto out;
		}
	}
	if (!ASSERT_GT(seen.called, 0, "reclaim events")) {
		report_timer_failures(skel);
		goto out;
	}

	remove_cgroup(CG_DYING_TARGET_DIR);

	/* Let reclaim passes that were already in flight drain. */
	usleep(DYING_SETTLE_US);

	calls_before = skel->bss->reclaim_calls;

	/*
	 * Wait for a reclaim round to hit the removed cgroup. Only TARGET_GONE
	 * ends the wait: an attempt that lands inside the rmdir window reports
	 * SKIPPED_DYING first, and stopping there would miss the events that
	 * follow it.
	 */
	for (i = 0; i < EVENT_POLL_ROUNDS && !seen.target_gone; i++) {
		n = ring_buffer__poll(rb, EVENT_POLL_TIMEOUT_MS);
		if (!ASSERT_GE(n, 0, "ring_buffer__poll"))
			goto out;
	}

	/*
	 * TARGET_GONE is what the test can rely on: by the time rmdir has
	 * returned, bpf_cgroup_from_id() has stopped resolving the target.
	 * SKIPPED_DYING only happens if an attempt lands inside the rmdir
	 * window, so it is reported here rather than asserted.
	 */
	if (!seen.target_gone) {
		report_timer_failures(skel);
		PRINT_FAIL("no reclaim round hit the removed cgroup (gone=%d, dying=%d)",
			   seen.target_gone, seen.skipped_dying);
		goto out;
	}

	/*
	 * Reclaim must have stopped with the target. Both counters stay put for
	 * the same reason: once rmdir has returned, bpf_cgroup_from_id() fails,
	 * so every attempt takes the TARGET_GONE path before it can reach
	 * reclaim_calls++. This therefore checks that reclaim really stops, not
	 * that cgroup_is_dying() works -- see that function in the BPF program
	 * for why the dying window cannot be hit reliably from userspace.
	 *
	 * reclaimed_bytes is compared against 0 rather than against its
	 * pre-removal value: the target is empty for the whole test, so
	 * bpf_proactive_reclaim() has nothing to reclaim and must have returned
	 * 0 on every call, before and after the removal alike. An "unchanged"
	 * comparison would be 0 == 0 and could never fail.
	 */
	if (!ASSERT_EQ(skel->bss->reclaim_calls, calls_before, "reclaim_calls"))
		goto out;
	if (!ASSERT_EQ(skel->bss->reclaimed_bytes, 0ULL, "reclaimed_bytes"))
		goto out;

out:
	if (reader_pid > 0) {
		kill(reader_pid, SIGKILL);
		(void)waitpid(reader_pid, NULL, 0);
	}
	if (data_fd >= 0)
		close(data_fd);
	if (data_file[0])
		unlink(data_file);
	if (rb)
		ring_buffer__free(rb);
	if (skel)
		memcg_async_reclaim__destroy(skel);
	cleanup_cgroup_environment();
}
