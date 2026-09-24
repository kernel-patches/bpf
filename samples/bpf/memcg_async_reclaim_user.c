// SPDX-License-Identifier: GPL-2.0
/*
 * memcg_async_reclaim - refault-driven asynchronous proactive reclaim
 *
 * A BPF program watches the workingset refaults of one cgroup and, whenever
 * they grow, reclaims from a second cgroup on a workqueue through
 * bpf_proactive_reclaim(). The monitored workload is never blocked: reclaim
 * runs asynchronously, in bounded batches, against somebody else's memory.
 *
 * Two modes:
 *
 *   bench  Create a high/low priority cgroup pair, run a memory-pressured
 *          workload in both, and report the effect on the pressured one. By
 *          default the same workload is first run without the BPF program to
 *          produce a baseline. Self-contained: creates and removes everything.
 *
 *   watch  Watch two existing cgroups given by path and keep reclaiming for as
 *          long as the program runs. Removing the target while it runs is
 *          handled: reclaim stops and the events say so.
 *
 * Both modes need root.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/compiler.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cgroup_helpers.h"
#include "memcg_async_reclaim.h"
#include "memcg_async_reclaim.skel.h"

/*
 * The bench workload lasts tens of milliseconds, so its tick has to be far
 * shorter than that to catch any refaults at all. A daemon has no such
 * constraint, and a short tick means a stat flush per tick against the
 * monitored cgroup, so watch defaults to something production-shaped.
 */
#define BENCH_INTERVAL_MS	2
#define WATCH_INTERVAL_MS	10

#define DEFAULT_THRESHOLD	1
#define DEFAULT_BATCH_BYTES	(128 * 1024UL)
#define DEFAULT_MAX_BATCHES	32
#define DEFAULT_SWAPPINESS	(-1L)
#define DEFAULT_STATS_SEC	10

#define DEFAULT_CG_LIMIT	(32 * 1024 * 1024UL)
#define DEFAULT_FILE_SIZE	(32 * 1024 * 1024UL)
#define DEFAULT_READ_TIMES	50UL
#define WRITE_BUFFER_SIZE	4096

#define BENCH_CG_DIR		"/memcg_async_reclaim"
#define BENCH_CG_HIGH_DIR	BENCH_CG_DIR "/high"
#define BENCH_CG_LOW_DIR	BENCH_CG_DIR "/low"

/* How long a single ring_buffer__poll() blocks while waiting for a signal. */
#define POLL_SLICE_MS		200

struct options {
	/* shared */
	unsigned long interval_ms;	/* 0 means "use the mode's default" */
	unsigned long threshold;
	unsigned long batch_bytes;
	unsigned long max_batches;
	long swappiness;
	bool verbose;
	/* bench */
	unsigned long cg_limit;
	unsigned long file_size;
	unsigned long read_times;
	bool no_baseline;
	/* watch */
	const char *monitor_path;
	const char *target_path;
	unsigned long duration_sec;
	unsigned long stats_sec;
};

struct counters {
	unsigned long long rounds;
	unsigned long long calls;
	unsigned long long bytes;
};

struct session {
	struct memcg_async_reclaim *skel;
	struct ring_buffer *rb;
	bool verbose;
	double start;
	unsigned long long called;
	unsigned long long skipped_dying;
	unsigned long long target_gone;
	struct counters last;
};

/* Set by the signal handler, polled with READ_ONCE() in the main loops. */
static sig_atomic_t exiting;

static void handle_signal(__maybe_unused int sig)
{
	WRITE_ONCE(exiting, 1);
}

static double now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int parse_ulong(const char *s, unsigned long *out)
{
	unsigned long v;
	char *end;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || end == s || *end)
		return -1;

	*out = v;

	return 0;
}

static int parse_long(const char *s, long *out)
{
	long v;
	char *end;

	errno = 0;
	v = strtol(s, &end, 0);
	if (errno || end == s || *end)
		return -1;

	*out = v;

	return 0;
}

/* Accepts a plain byte count or one suffixed with K, M or G. */
static int parse_size(const char *s, unsigned long *out)
{
	unsigned long v;
	char *end;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || end == s)
		return -1;

	switch (*end) {
	case 'k':
	case 'K':
		v <<= 10;
		end++;
		break;
	case 'm':
	case 'M':
		v <<= 20;
		end++;
		break;
	case 'g':
	case 'G':
		v <<= 30;
		end++;
		break;
	case '\0':
		break;
	default:
		return -1;
	}

	if (*end)
		return -1;

	*out = v;

	return 0;
}

static void fmt_bytes(char *buf, size_t len, unsigned long long bytes)
{
	if (bytes >= (1ULL << 30))
		snprintf(buf, len, "%.1f GiB", bytes / (double)(1ULL << 30));
	else if (bytes >= (1ULL << 20))
		snprintf(buf, len, "%.1f MiB", bytes / (double)(1ULL << 20));
	else if (bytes >= (1ULL << 10))
		snprintf(buf, len, "%.1f KiB", bytes / (double)(1ULL << 10));
	else
		snprintf(buf, len, "%llu B", bytes);
}

static const char *outcome_str(__u64 outcome)
{
	switch (outcome) {
	case RECLAIM_OUTCOME_CALLED:
		return "called";
	case RECLAIM_OUTCOME_SKIPPED_DYING:
		return "skipped-dying";
	case RECLAIM_OUTCOME_TARGET_GONE:
		return "target-gone";
	default:
		return "unknown";
	}
}

/* session code */

static int on_reclaim_event(void *ctx, void *data, size_t sz)
{
	struct session *s = ctx;
	const struct reclaim_event *ev = data;

	if (sz < sizeof(*ev))
		return 0;

	switch (ev->outcome) {
	case RECLAIM_OUTCOME_CALLED:
		s->called++;
		break;
	case RECLAIM_OUTCOME_SKIPPED_DYING:
		s->skipped_dying++;
		break;
	case RECLAIM_OUTCOME_TARGET_GONE:
		s->target_gone++;
		break;
	}

	if (s->verbose)
		printf("[%7.3fs] event %-13s called=%llu dying=%llu gone=%llu\n",
		       now_sec() - s->start, outcome_str(ev->outcome),
		       s->called, s->skipped_dying, s->target_gone);

	return 0;
}

static void read_counters(struct session *s, struct counters *c)
{
	c->rounds = s->skel->bss->reclaim_rounds;
	c->calls = s->skel->bss->reclaim_calls;
	c->bytes = s->skel->bss->reclaimed_bytes;
}

static int session_start(struct session *s, const struct options *o,
			 __u64 monitor_id, __u64 target_id)
{
	struct reclaim_cfg cfg = {
		.monitor_cgroup_id = monitor_id,
		.target_cgroup_id = target_id,
		.refault_threshold = o->threshold,
		.interval_ns = (unsigned long long)o->interval_ms * 1000000ULL,
		.batch_bytes = o->batch_bytes,
		.max_batches = o->max_batches,
		.swappiness = o->swappiness,
	};
	LIBBPF_OPTS(bpf_test_run_opts, run_opts,
		    .ctx_in = &cfg,
		    .ctx_size_in = sizeof(cfg));
	int init_fd, err;

	s->verbose = o->verbose;
	s->start = now_sec();

	s->skel = memcg_async_reclaim__open_and_load();
	if (!s->skel) {
		fprintf(stderr, "ERROR: failed to open or load the BPF object\n");
		return -1;
	}

	/*
	 * The syscall program installs the timer and the work item into the
	 * map and starts the timer; from then on the chain runs on its own.
	 */
	init_fd = bpf_program__fd(s->skel->progs.reclaim_prog_init);
	err = bpf_prog_test_run_opts(init_fd, &run_opts);
	if (err || run_opts.retval) {
		fprintf(stderr, "ERROR: reclaim_prog_init failed: %s (retval %d)\n",
			err ? strerror(errno) : "rejected by the program",
			run_opts.retval);
		goto err_out;
	}

	s->rb = ring_buffer__new(bpf_map__fd(s->skel->maps.reclaim_events),
				 on_reclaim_event, s, NULL);
	if (!s->rb) {
		fprintf(stderr, "ERROR: failed to create the ring buffer\n");
		goto err_out;
	}

	read_counters(s, &s->last);

	return 0;

err_out:
	memcg_async_reclaim__destroy(s->skel);
	s->skel = NULL;

	return -1;
}

/* Poll until the timeout expires; returns early on a signal or an error. */
static int session_poll(struct session *s, int timeout_ms)
{
	int deadline_ms = timeout_ms, n;

	while (!READ_ONCE(exiting) && deadline_ms > 0) {
		int slice = deadline_ms > POLL_SLICE_MS ? POLL_SLICE_MS
							 : deadline_ms;

		n = ring_buffer__poll(s->rb, slice);
		/* A signal interrupts epoll_wait(), which is how we stop. */
		if (n < 0 && n != -EINTR)
			return -1;

		deadline_ms -= slice;
	}

	return 0;
}

static void print_counters(struct session *s, const char *prefix)
{
	struct counters now;
	char bytes[32], delta[32];

	read_counters(s, &now);
	fmt_bytes(bytes, sizeof(bytes), now.bytes);
	fmt_bytes(delta, sizeof(delta), now.bytes - s->last.bytes);

	printf("%s rounds=%llu(+%llu) calls=%llu(+%llu) reclaimed=%s(+%s)\n",
	       prefix, now.rounds, now.rounds - s->last.rounds,
	       now.calls, now.calls - s->last.calls, bytes, delta);

	s->last = now;
}

static void session_stop(struct session *s)
{
	unsigned long long failures, last_err;

	if (!s->skel)
		return;

	ring_buffer__free(s->rb);
	s->rb = NULL;

	failures = s->skel->bss->timer_failures;
	last_err = s->skel->bss->last_reclaim_err;

	printf("\nran for %.1fs\n", now_sec() - s->start);
	print_counters(s, "total:");
	printf("events: called=%llu skipped_dying=%llu target_gone=%llu\n",
	       s->called, s->skipped_dying, s->target_gone);
	if (failures)
		printf("WARNING: monitor timer rearm failed %llu time(s), reclaim stopped early\n",
		       failures);
	if (last_err)
		printf("WARNING: bpf_proactive_reclaim() last failed with -%llu\n",
		       last_err);

	/* Destroying the skeleton drops the map, which cancels timer and wq. */
	memcg_async_reclaim__destroy(s->skel);
	s->skel = NULL;
}

/* watch mode setup code */

/*
 * cgroup_helpers' get_cgroup_id() resolves paths relative to the private
 * hierarchy it mounts for the bench mode, so watch mode needs its own lookup
 * against the paths the user gave. cgroupfs file handles are always 8 bytes
 * and hold the cgroup id, so there is no need for the two-call size probe.
 */
static __u64 cgroup_id_from_path(const char *path)
{
	struct {
		struct file_handle fh;
		__u64 cgid;
	} h = {};
	int mnt_id;

	h.fh.handle_bytes = sizeof(h.cgid);

	if (name_to_handle_at(AT_FDCWD, path, &h.fh, &mnt_id, 0))
		return 0;
	/*
	 * Only the size is checked, not handle_type: cgroupfs encodes through
	 * kernfs_encode_fh(), whose FILEID_KERNFS is not visible to userspace.
	 */
	if (h.fh.handle_bytes != sizeof(h.cgid))
		return 0;

	return h.cgid;
}

static bool memcg_on_path(const char *path)
{
	char file[PATH_MAX];
	int fd;

	snprintf(file, sizeof(file), "%s/memory.current", path);
	fd = open(file, O_RDONLY);
	if (fd < 0)
		return false;
	close(fd);

	return true;
}

/* bench mode code */

/*
 * The workload files must sit on a regular filesystem: with swap disabled for
 * the cgroup, tmpfs pages are unevictable and would OOM the cgroup instead of
 * exercising reclaim; they are also charged as shmem rather than as the page
 * cache this workload is meant to build, so they never raise the workingset
 * refaults the BPF program watches.
 *
 * /tmp is tmpfs on many systems, so fall back to the current directory. That
 * fallback needs the same check: both directories are tmpfs more often than
 * not.
 */
static const char *workload_files_dir(void)
{
	static const char * const dirs[] = { "/tmp", "." };
	struct statfs st;
	int i;

	for (i = 0; i < 2; i++)
		if (!statfs(dirs[i], &st) && st.f_type != TMPFS_MAGIC &&
		    st.f_type != RAMFS_MAGIC)
			return dirs[i];

	return NULL;
}

/*
 * Keep the workload from swapping out, so that reclaim has to evict page cache.
 * memory.swap.max only exists when the kernel is built with CONFIG_SWAP, and
 * /proc/swaps is registered by the same CONFIG_SWAP-gated code (mm/swapfile.c),
 * so it stands in for the config here.
 */
static int disable_swap(const char *cgroup_dir)
{
	if (access("/proc/swaps", F_OK))
		return 0;

	return write_cgroup_file(cgroup_dir, "memory.swap.max", "0");
}

static int setup_bench_cgroups(const struct options *o, __u64 *high_id,
			       __u64 *low_id)
{
	char limit_buf[32];
	int fd;

	if (setup_cgroup_environment()) {
		fprintf(stderr, "ERROR: failed to set up the cgroup environment\n");
		return -1;
	}

	fd = create_and_get_cgroup(BENCH_CG_DIR);
	if (fd < 0)
		goto err;
	close(fd);

	if (enable_controllers(BENCH_CG_DIR, "memory"))
		goto err;

	snprintf(limit_buf, sizeof(limit_buf), "%lu", o->cg_limit);
	if (write_cgroup_file(BENCH_CG_DIR, "memory.max", limit_buf))
		goto err;
	if (disable_swap(BENCH_CG_DIR))
		goto err;

	fd = create_and_get_cgroup(BENCH_CG_HIGH_DIR);
	if (fd < 0)
		goto err;
	close(fd);

	fd = create_and_get_cgroup(BENCH_CG_LOW_DIR);
	if (fd < 0)
		goto err;
	close(fd);

	*high_id = get_cgroup_id(BENCH_CG_HIGH_DIR);
	*low_id = get_cgroup_id(BENCH_CG_LOW_DIR);
	if (!*high_id || !*low_id) {
		fprintf(stderr, "ERROR: failed to read the cgroup ids\n");
		goto err;
	}

	return 0;

err:
	cleanup_cgroup_environment();

	return -1;
}

/*
 * The forked children cannot report through stdio, so the exit status is the
 * one diagnostics channel that reliably reaches the parent: each failing step
 * gets its own code.
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

static int write_file(int fd, unsigned long file_size)
{
	char *buffer;
	size_t written = 0;

	buffer = malloc(WRITE_BUFFER_SIZE);
	if (!buffer)
		return -1;

	memset(buffer, 'A', WRITE_BUFFER_SIZE);

	while (written < file_size) {
		size_t to_write = file_size - written < WRITE_BUFFER_SIZE ?
				  file_size - written : WRITE_BUFFER_SIZE;
		ssize_t n = write(fd, buffer, to_write);

		if (n <= 0) {
			free(buffer);
			return -1;
		}
		written += n;
	}

	free(buffer);

	return 0;
}

static int read_file(int fd, unsigned long file_size, unsigned long iterations)
{
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned long i, iter;
	struct stat sb;
	char *map;

	if (fstat(fd, &sb) || (unsigned long)sb.st_size != file_size)
		return -1;

	map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
		return -1;

	for (iter = 0; iter < iterations; iter++)
		for (i = 0; i < file_size; i += page_size)
			/* touch a byte per page to trigger the fault */
			(void)READ_ONCE(map[i]);

	return munmap(map, file_size) ? -1 : 0;
}

static int child_work(const char *cgroup_path, int data_fd, int time_fd,
		      const struct options *o)
{
	struct timespec start, end;
	char buf[32];
	double elapsed;
	int len;

	if (join_parent_cgroup(cgroup_path))
		return CHILD_EXIT_JOIN_CGROUP;

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (write_file(data_fd, o->file_size))
		return CHILD_EXIT_WRITE_FILE;
	if (read_file(data_fd, o->file_size, o->read_times))
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

static int get_time(int fd, double *elapsed)
{
	char buf[64] = {};
	ssize_t n;

	/* The child wrote through the fork-shared description, so rewind. */
	if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		fprintf(stderr, "ERROR: lseek time file: %s\n", strerror(errno));
		return -1;
	}

	n = read(fd, buf, sizeof(buf) - 1);
	if (n <= 0) {
		fprintf(stderr, "ERROR: read time file: %s\n", strerror(errno));
		return -1;
	}

	if (sscanf(buf, "%lf", elapsed) != 1) {
		fprintf(stderr, "ERROR: cannot parse time '%s'\n", buf);
		return -1;
	}

	return 0;
}

/*
 * Reap one workload child and turn its exit code into a diagnostic. @pid is
 * cleared on every path, including failure: once the child has been reaped its
 * PID can be reused, and the error path signals whatever is left in it.
 */
static int reap_child(pid_t *pid, const char *who)
{
	int status;

	if (waitpid(*pid, &status, 0) <= 0) {
		fprintf(stderr, "ERROR: waitpid %s: %s\n", who, strerror(errno));
		*pid = -1;
		return -1;
	}
	*pid = -1;

	if (!WIFEXITED(status)) {
		fprintf(stderr, "ERROR: %s child died, status 0x%x\n", who, status);
		return -1;
	}
	if (WEXITSTATUS(status) != CHILD_EXIT_OK) {
		fprintf(stderr, "ERROR: %s child failed at: %s (exit status %d)\n",
			who, child_exit_str(WEXITSTATUS(status)),
			WEXITSTATUS(status));
		return -1;
	}

	return 0;
}

/*
 * Run the workload in the high and low priority cgroups at the same time and
 * report how long each took. The high priority one is the cgroup the BPF
 * program protects, the low priority one is what it reclaims from.
 */
static int run_workload(const char *dir, const struct options *o,
			double *high_elapsed, double *low_elapsed)
{
	char high_data[PATH_MAX], low_data[PATH_MAX];
	char high_time[PATH_MAX], low_time[PATH_MAX];
	int high_data_fd = -1, low_data_fd = -1;
	int high_time_fd = -1, low_time_fd = -1;
	pid_t high_pid = -1, low_pid = -1;
	int ret = -1;

	snprintf(high_data, sizeof(high_data), "%s/memcg_high_data_XXXXXX", dir);
	snprintf(low_data, sizeof(low_data), "%s/memcg_low_data_XXXXXX", dir);
	snprintf(high_time, sizeof(high_time), "%s/memcg_high_time_XXXXXX", dir);
	snprintf(low_time, sizeof(low_time), "%s/memcg_low_time_XXXXXX", dir);

	/*
	 * The mkstemp() fds are kept and inherited by the children rather than
	 * reopened by name: reopening would resolve the path again and follow
	 * whatever sits there by then.
	 */
	high_data_fd = mkstemp(high_data);
	low_data_fd = mkstemp(low_data);
	high_time_fd = mkstemp(high_time);
	low_time_fd = mkstemp(low_time);
	if (high_data_fd < 0 || low_data_fd < 0 || high_time_fd < 0 ||
	    low_time_fd < 0) {
		fprintf(stderr, "ERROR: mkstemp: %s\n", strerror(errno));
		goto cleanup;
	}

	low_pid = fork();
	if (low_pid < 0) {
		fprintf(stderr, "ERROR: fork low: %s\n", strerror(errno));
		goto cleanup;
	}
	if (low_pid == 0)
		_exit(child_work(BENCH_CG_LOW_DIR, low_data_fd, low_time_fd, o));

	high_pid = fork();
	if (high_pid < 0) {
		fprintf(stderr, "ERROR: fork high: %s\n", strerror(errno));
		goto cleanup;
	}
	if (high_pid == 0)
		_exit(child_work(BENCH_CG_HIGH_DIR, high_data_fd, high_time_fd, o));

	if (reap_child(&low_pid, "low"))
		goto cleanup;
	if (reap_child(&high_pid, "high"))
		goto cleanup;

	if (get_time(high_time_fd, high_elapsed))
		goto cleanup;
	if (get_time(low_time_fd, low_elapsed))
		goto cleanup;

	ret = 0;

cleanup:
	/* On failure, make sure no child process is left behind. */
	if (ret) {
		if (high_pid > 0) {
			kill(high_pid, SIGKILL);
			waitpid(high_pid, NULL, 0);
		}
		if (low_pid > 0) {
			kill(low_pid, SIGKILL);
			waitpid(low_pid, NULL, 0);
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
	unlink(high_data);
	unlink(low_data);
	unlink(high_time);
	unlink(low_time);

	return ret;
}

static void print_speedup(const char *who, double baseline, double measured)
{
	if (baseline <= 0.0)
		return;

	printf("%s: baseline=%.3fs reclaim=%.3fs speedup=%+.1f%%\n", who,
	       baseline, measured,
	       100.0 * (baseline - measured) / baseline);
}

static int do_bench(struct options *o)
{
	double base_high = 0.0, base_low = 0.0;
	double high = 0.0, low = 0.0;
	struct session s = {};
	__u64 high_id, low_id;
	const char *dir;
	int ret = 1;

	dir = workload_files_dir();
	if (!dir) {
		fprintf(stderr, "ERROR: neither /tmp nor the working directory is on a\n"
			"       regular filesystem; the workload needs one because\n"
			"       tmpfs pages are not reclaimable without swap.\n");
		return 1;
	}

	if (setup_bench_cgroups(o, &high_id, &low_id))
		return 1;

	if (!o->no_baseline) {
		printf("baseline run (no BPF program)...\n");
		if (run_workload(dir, o, &base_high, &base_low))
			goto out;

		/*
		 * The baseline left up to cg_limit of page cache charged to the
		 * two cgroups, and memcg charges outlive the workload processes.
		 * Recreate the cgroups so that the instrumented run starts from
		 * the same cold state; otherwise the reported speedup compares a
		 * cold run against a warm one.
		 */
		cleanup_cgroup_environment();
		if (setup_bench_cgroups(o, &high_id, &low_id))
			return 1;
	}

	if (session_start(&s, o, high_id, low_id))
		goto out;

	printf("reclaim run (BPF program active)...\n");
	if (run_workload(dir, o, &high, &low))
		goto out;

	printf("\nworkload: file_size=%lu read_times=%lu memory.max=%lu\n",
	       o->file_size, o->read_times, o->cg_limit);
	printf("high priority: %.3fs   low priority: %.3fs\n", high, low);
	if (!o->no_baseline) {
		print_speedup("high", base_high, high);
		print_speedup("low", base_low, low);
	}

	ret = 0;

out:
	session_stop(&s);
	cleanup_cgroup_environment();

	return ret;
}

/* watch mode code */

static int do_watch(struct options *o)
{
	struct session s = {};
	__u64 monitor_id, target_id;
	double next_stats, deadline = 0;
	int ret = 1;

	if (!o->monitor_path || !o->target_path) {
		fprintf(stderr, "ERROR: watch needs both --monitor and --target\n");
		return 1;
	}

	monitor_id = cgroup_id_from_path(o->monitor_path);
	if (!monitor_id) {
		fprintf(stderr, "ERROR: cannot resolve %s: %s\n", o->monitor_path,
			strerror(errno));
		return 1;
	}
	if (!memcg_on_path(o->monitor_path)) {
		fprintf(stderr, "ERROR: %s has no memory.current; the memory\n"
			"       controller is not enabled on that cgroup.\n",
			o->monitor_path);
		return 1;
	}

	target_id = cgroup_id_from_path(o->target_path);
	if (!target_id) {
		fprintf(stderr, "ERROR: cannot resolve %s: %s\n", o->target_path,
			strerror(errno));
		return 1;
	}
	if (!memcg_on_path(o->target_path)) {
		fprintf(stderr, "ERROR: %s has no memory.current; the memory\n"
			"       controller is not enabled on that cgroup.\n",
			o->target_path);
		return 1;
	}

	if (session_start(&s, o, monitor_id, target_id))
		return 1;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	printf("monitor: %s (id %llu)\n", o->monitor_path,
	       (unsigned long long)monitor_id);
	printf("target:  %s (id %llu)\n", o->target_path,
	       (unsigned long long)target_id);
	printf("interval=%lums threshold=%lu batch=%lu max_batches=%lu swappiness=%ld\n",
	       o->interval_ms, o->threshold, o->batch_bytes, o->max_batches,
	       o->swappiness);
	if (o->duration_sec)
		printf("running for %lus, ", o->duration_sec);
	printf("interrupt with SIGINT to stop\n\n");

	next_stats = now_sec() + o->stats_sec;
	if (o->duration_sec)
		deadline = s.start + o->duration_sec;

	while (!READ_ONCE(exiting)) {
		double now = now_sec();
		int wait_ms;

		if (deadline && now >= deadline)
			break;

		wait_ms = (int)((next_stats - now) * 1000);
		if (wait_ms < 0)
			wait_ms = 0;

		if (session_poll(&s, wait_ms)) {
			fprintf(stderr, "ERROR: ring buffer poll failed\n");
			goto out;
		}

		if (now_sec() >= next_stats) {
			char prefix[32];

			snprintf(prefix, sizeof(prefix), "[%5.0fs]",
				 now_sec() - s.start);
			print_counters(&s, prefix);
			next_stats += o->stats_sec;
		}
	}

	ret = 0;

out:
	session_stop(&s);

	return ret;
}

/* cli code */

static void usage(const char *prog)
{
	printf("Usage: %s <mode> [options]\n\n"
	       "Modes:\n"
	       "  bench    create a high/low priority cgroup pair, run a memory\n"
	       "           pressured workload in both, and report the effect of\n"
	       "           asynchronous reclaim on the pressured one\n"
	       "  watch    watch an existing cgroup and reclaim from another one\n"
	       "           whenever it comes under pressure, until interrupted\n\n"
	       "Common options:\n"
	       "  -i, --interval MS     monitor tick (bench: %d, watch: %d)\n"
	       "  -t, --threshold N     refault delta per tick that starts a round (%d)\n"
	       "  -b, --batch BYTES     bytes requested per callback (%luK)\n"
	       "  -n, --max-batches N   callbacks per reclaim round (%d)\n"
	       "  -S, --swappiness N    -1 = the memcg's own, 0..200, 201 = anon\n"
	       "                        pages only (needs swap; the default) (%ld)\n"
	       "  -v, --verbose         print every reclaim event\n"
	       "  -h, --help\n\n"
	       "bench options:\n"
	       "  -l, --limit BYTES     memory.max for the test cgroups (%luM)\n"
	       "  -f, --file-size BYTES workload file size (%luM)\n"
	       "  -R, --read-times N    workload re-read iterations (%lu)\n"
	       "      --no-baseline     skip the run without the BPF program\n\n"
	       "watch options:\n"
	       "  -m, --monitor PATH    cgroup to watch (required)\n"
	       "  -T, --target PATH     cgroup to reclaim from (required)\n"
	       "  -D, --duration SEC    stop after SEC seconds instead of on signal\n"
	       "  -s, --stats SEC       print a statistics line every SEC seconds (%d)\n\n"
	       "BYTES accepts a K, M or G suffix. Both modes need root.\n\n"
	       "One call to bpf_proactive_reclaim() reclaims at most the kernel's\n"
	       "MEMCG_CHARGE_BATCH pages, so --batch above that limit only means a\n"
	       "round needs more callbacks, not that a single callback does more.\n",
	       prog, BENCH_INTERVAL_MS, WATCH_INTERVAL_MS, DEFAULT_THRESHOLD,
	       DEFAULT_BATCH_BYTES / 1024, DEFAULT_MAX_BATCHES,
	       DEFAULT_SWAPPINESS, DEFAULT_CG_LIMIT / (1024 * 1024),
	       DEFAULT_FILE_SIZE / (1024 * 1024), DEFAULT_READ_TIMES,
	       DEFAULT_STATS_SEC);
}

enum {
	OPT_NO_BASELINE = 256,
};

static int parse_options(int argc, char **argv, struct options *o)
{
	static const struct option long_opts[] = {
		{ "interval",	required_argument,	NULL, 'i' },
		{ "threshold",	required_argument,	NULL, 't' },
		{ "batch",	required_argument,	NULL, 'b' },
		{ "max-batches",	required_argument,	NULL, 'n' },
		{ "swappiness",	required_argument,	NULL, 'S' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "limit",	required_argument,	NULL, 'l' },
		{ "file-size",	required_argument,	NULL, 'f' },
		{ "read-times",	required_argument,	NULL, 'R' },
		{ "no-baseline",	no_argument,		NULL, OPT_NO_BASELINE },
		{ "monitor",	required_argument,	NULL, 'm' },
		{ "target",	required_argument,	NULL, 'T' },
		{ "duration",	required_argument,	NULL, 'D' },
		{ "stats",	required_argument,	NULL, 's' },
		{ }
	};
	int c;

	while ((c = getopt_long(argc, argv, "i:t:b:n:S:vhl:f:R:m:T:D:s:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'i':
			if (parse_ulong(optarg, &o->interval_ms))
				return -1;
			break;
		case 't':
			if (parse_ulong(optarg, &o->threshold))
				return -1;
			break;
		case 'b':
			if (parse_size(optarg, &o->batch_bytes))
				return -1;
			break;
		case 'n':
			if (parse_ulong(optarg, &o->max_batches))
				return -1;
			break;
		case 'S':
			if (parse_long(optarg, &o->swappiness))
				return -1;
			break;
		case 'v':
			o->verbose = true;
			break;
		case 'l':
			if (parse_size(optarg, &o->cg_limit))
				return -1;
			break;
		case 'f':
			if (parse_size(optarg, &o->file_size))
				return -1;
			break;
		case 'R':
			if (parse_ulong(optarg, &o->read_times))
				return -1;
			break;
		case OPT_NO_BASELINE:
			o->no_baseline = true;
			break;
		case 'm':
			o->monitor_path = optarg;
			break;
		case 'T':
			o->target_path = optarg;
			break;
		case 'D':
			if (parse_ulong(optarg, &o->duration_sec))
				return -1;
			break;
		case 's':
			if (parse_ulong(optarg, &o->stats_sec))
				return -1;
			break;
		default:
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct options o = {
		.threshold = DEFAULT_THRESHOLD,
		.batch_bytes = DEFAULT_BATCH_BYTES,
		.max_batches = DEFAULT_MAX_BATCHES,
		.swappiness = DEFAULT_SWAPPINESS,
		.cg_limit = DEFAULT_CG_LIMIT,
		.file_size = DEFAULT_FILE_SIZE,
		.read_times = DEFAULT_READ_TIMES,
		.stats_sec = DEFAULT_STATS_SEC,
	};
	const char *mode;
	bool bench;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	mode = argv[1];
	if (!strcmp(mode, "-h") || !strcmp(mode, "--help")) {
		usage(argv[0]);
		return 0;
	}

	bench = !strcmp(mode, "bench");
	if (!bench && strcmp(mode, "watch")) {
		fprintf(stderr, "ERROR: unknown mode '%s', expected bench or watch\n\n",
			mode);
		usage(argv[0]);
		return 1;
	}

	/* Let getopt_long see the options rather than the mode. */
	optind = 2;
	if (parse_options(argc, argv, &o)) {
		usage(argv[0]);
		return 1;
	}

	if (!o.interval_ms)
		o.interval_ms = bench ? BENCH_INTERVAL_MS : WATCH_INTERVAL_MS;
	if (!o.stats_sec)
		o.stats_sec = DEFAULT_STATS_SEC;
	if (!o.threshold || !o.batch_bytes || !o.max_batches) {
		fprintf(stderr, "ERROR: --threshold, --batch and --max-batches must be non-zero\n");
		return 1;
	}
	if (o.swappiness != -1 && (o.swappiness < 0 || o.swappiness > 201)) {
		fprintf(stderr, "ERROR: --swappiness must be -1, 0..200, or 201\n");
		return 1;
	}
	/*
	 * One round budgets max_batches * batch_bytes, and the BPF side keeps
	 * requeueing until it is spent, so bound the product: it also keeps the
	 * multiplication from wrapping.
	 */
	if (o.max_batches > (1UL << 30) / o.batch_bytes) {
		fprintf(stderr, "ERROR: --max-batches * --batch must not exceed 1G\n");
		return 1;
	}

	return bench ? do_bench(&o) : do_watch(&o);
}
