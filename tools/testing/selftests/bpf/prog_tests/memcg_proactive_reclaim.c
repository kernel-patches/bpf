// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <limits.h>
#include <linux/magic.h>
#include <sys/statfs.h>
#include <unistd.h>

#include "cgroup_helpers.h"
#include "memcg_proactive_reclaim.skel.h"

#define CG_PATH "/memcg_proactive_reclaim"

/*
 * Large enough that a single reclaim pass cannot come close to it, so that
 * "reclaimed less than was asked for" is not page-size noise: one pass is
 * capped at MEMCG_CHARGE_BATCH pages, which is 256 KiB on 4K pages but 4 MiB
 * on 64K pages.
 */
#define FILE_SIZE (32 * 1024 * 1024UL)
#define BUF_SIZE (64 * 1024)

/*
 * memcg stats are flushed lazily: reading memory.stat only flushes once
 * pending updates exceed MEMCG_CHARGE_BATCH * num_online_cpus(), so on a
 * large machine the write may only show up after the periodic flusher
 * (every 2s, later on a busy machine) has run.
 */
#define MEMCG_STAT_RETRIES		40
#define MEMCG_STAT_RETRY_DELAY_US	(250 * 1000)

struct reclaim_args {
	__u64 cgroup_id;
	__u64 size;
};

/*
 * The data file has to sit on a writable regular filesystem: tmpfs pages are
 * charged as shmem, so whether they can be reclaimed at all depends on swap
 * being available, and a read-only mount cannot host the file at all (EROFS
 * applies to root too). /tmp is tmpfs on many systems, and test_progs is
 * routinely run from a tmpfs working directory, so both candidates need the
 * check.
 */
static const char * const workload_dirs[] = { "/tmp", "." };

static bool usable_dir(const char *dir)
{
	struct statfs st;

	return !statfs(dir, &st) && st.f_type != TMPFS_MAGIC &&
	       st.f_type != RAMFS_MAGIC && !access(dir, W_OK);
}

static bool memcg_stat(const char *stat, const char *key,
		       unsigned long long *val)
{
	char needle[32];
	const char *p;

	snprintf(needle, sizeof(needle), "\n%s ", key);
	p = strstr(stat, needle);
	return p && sscanf(p + strlen(needle), "%llu", val) == 1;
}

/*
 * statfs() only sees the top of a stacking filesystem: when /tmp is an
 * overlayfs over tmpfs, as in virtme-ng guests, the check above passes but
 * the data still ends up as shmem. Wait for the write to show up in the
 * cgroup's stats ("file" includes shmem) and report how much of it is shmem.
 * Both keys are always present, so failing to read them is an error.
 */
static int read_shmem_charge(const char *cg, unsigned long long *shmem)
{
	static char buf[8192];
	unsigned long long file = 0;
	int i;

	for (i = 0; i < MEMCG_STAT_RETRIES; i++) {
		if (!ASSERT_OK(read_cgroup_file(cg, "memory.stat", buf,
						sizeof(buf)), "read memory.stat") ||
		    !ASSERT_TRUE(memcg_stat(buf, "file", &file), "parse file") ||
		    !ASSERT_TRUE(memcg_stat(buf, "shmem", shmem), "parse shmem"))
			return -1;
		if (file >= FILE_SIZE / 2)
			return 0;
		usleep(MEMCG_STAT_RETRY_DELAY_US);
	}

	ASSERT_GE(file, FILE_SIZE / 2, "file in memory.stat");
	return -1;
}

/* Charge FILE_SIZE of clean page cache to the current cgroup. */
static int write_data_file(const char *dir, char *path, size_t len)
{
	static char buf[BUF_SIZE];
	off_t off;
	int fd;

	snprintf(path, len, "%s/memcg_proactive_reclaim_XXXXXX", dir);
	fd = mkstemp(path);
	if (!ASSERT_GE(fd, 0, "mkstemp"))
		return -1;

	for (off = 0; off < (off_t)FILE_SIZE; off += sizeof(buf))
		if (!ASSERT_EQ(write(fd, buf, sizeof(buf)),
			       (ssize_t)sizeof(buf), "write"))
			goto err;
	if (!ASSERT_OK(fsync(fd), "fsync"))
		goto err;

	return fd;
err:
	close(fd);
	unlink(path);
	return -1;
}

void test_memcg_proactive_reclaim(void)
{
	struct memcg_proactive_reclaim *skel = NULL;
	struct reclaim_args args = {};

	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .ctx_in = &args,
		    .ctx_size_in = sizeof(args));

	char data_file[PATH_MAX], cg[64];
	unsigned long long shmem;
	__u64 cgroup_id;
	int cg_fd = -1, data_fd = -1, err, i;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_environment"))
		return;

	/*
	 * Try each candidate in a cgroup of its own, so that the stats of one
	 * attempt do not leak into the next.
	 */
	for (i = 0; i < ARRAY_SIZE(workload_dirs); i++) {
		if (!usable_dir(workload_dirs[i]))
			continue;

		snprintf(cg, sizeof(cg), CG_PATH "_%d", i);
		cg_fd = create_and_get_cgroup(cg);
		if (!ASSERT_OK_FD(cg_fd, "create_and_get_cgroup"))
			goto out;
		if (!ASSERT_OK(join_cgroup(cg), "join_cgroup"))
			goto out;

		data_fd = write_data_file(workload_dirs[i], data_file,
					  sizeof(data_file));
		if (data_fd < 0 || read_shmem_charge(cg, &shmem))
			goto out;

		/*
		 * All or nothing: the file is either entirely shmem (tmpfs,
		 * possibly under a stacking filesystem) or not shmem at all
		 * (disk-backed), so half of FILE_SIZE is a safe midpoint.
		 */
		if (shmem < FILE_SIZE / 2)
			break;

		printf("%s: %s is backed by shmem (%llu MiB charged)\n",
		       __func__, workload_dirs[i], shmem >> 20);
		close(data_fd);
		unlink(data_file);
		data_fd = -1;
		close(cg_fd);
		cg_fd = -1;
	}

	/*
	 * No candidate is usable: tmpfs (initramfs-based CI, for instance),
	 * a read-only mount, or a stacking filesystem on top of tmpfs. That is
	 * an environment limitation, not a test failure.
	 */
	if (data_fd < 0) {
		test__skip();
		goto out;
	}

	cgroup_id = get_cgroup_id(cg);
	if (!ASSERT_GT(cgroup_id, 0, "get_cgroup_id"))
		goto out;

	skel = memcg_proactive_reclaim__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	args.cgroup_id = cgroup_id;
	args.size = FILE_SIZE;
	skel->bss->reclaimed = 0;
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.memcg_proactive_reclaim),
				     &opts);
	if (!ASSERT_OK(err, "test_run"))
		goto out;
	if (!ASSERT_EQ(opts.retval, 0, "retval"))
		goto out;

	/*
	 * A single call is a single bounded pass: it reclaims something, but
	 * stops well short of the requested size instead of retrying until the
	 * goal is reached the way a write to memory.reclaim does.
	 */
	ASSERT_GT(skel->bss->reclaimed, 0, "reclaimed");
	ASSERT_LT(skel->bss->reclaimed, (__s64)FILE_SIZE, "single pass");

out:
	if (skel)
		memcg_proactive_reclaim__destroy(skel);
	if (cg_fd >= 0)
		close(cg_fd);
	if (data_fd >= 0) {
		close(data_fd);
		unlink(data_file);
	}
	cleanup_cgroup_environment();
}
