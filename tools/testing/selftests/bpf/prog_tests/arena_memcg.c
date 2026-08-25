// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#ifndef PAGE_SIZE /* on some archs it comes in sys/user.h */
#define PAGE_SIZE getpagesize()
#endif

#include "cgroup_helpers.h"
#include "arena_memcg.skel.h"

#define CG_PATH		"/arena_memcg"

/* Budget the arena gets on top of whatever is already charged after load. */
#define ARENA_BUDGET	(64 * 1024 * 1024)

static void dump_memcg(int (*rd)(const char *, const char *, char *, size_t))
{
	char buf[512];

	/*
	 * memory.current reads 0 once the child has left the cgroup, so it only
	 * carries information when dumped from the live child; memory.peak and
	 * memory.events survive the child and tell the story either way.
	 */
	if (!rd(CG_PATH, "memory.current", buf, sizeof(buf)))
		fprintf(stderr, "memory.current: %s", buf);
	if (!rd(CG_PATH, "memory.max", buf, sizeof(buf)))
		fprintf(stderr, "memory.max: %s", buf);
	if (!rd(CG_PATH, "memory.peak", buf, sizeof(buf)))
		fprintf(stderr, "memory.peak: %s", buf);
	if (!rd(CG_PATH, "memory.events", buf, sizeof(buf)))
		fprintf(stderr, "memory.events:\n%s", buf);
	fflush(stderr);
}

/* Read one key from a flat keyed cgroup file, e.g. "oom_kill" in memory.events. */
static long cg_read_key(const char *cg, const char *file, const char *key)
{
	char buf[512], *p;

	if (read_cgroup_file(cg, file, buf, sizeof(buf)))
		return -1;
	p = strstr(buf, key);
	if (!p)
		return -1;
	return strtol(p + strlen(key), NULL, 10);
}

void serial_test_arena_memcg(void)
{
	int cgroup_fd = -1, status, err;
	const long ps = PAGE_SIZE;
	char buf[64];
	pid_t pid;

	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		return;

	cgroup_fd = create_and_get_cgroup(CG_PATH);
	if (!ASSERT_OK_FD(cgroup_fd, "create_and_get_cgroup"))
		goto out;

	/* No memory controller -> nothing to test. */
	if (read_cgroup_file(CG_PATH, "memory.current", buf, sizeof(buf))) {
		fprintf(stderr, "%s:SKIP:no memory controller\n", __func__);
		test__skip();
		goto out;
	}

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out;
	if (pid == 0) {
		struct arena_memcg *cskel;
		__u32 i, npages;
		char *base;
		size_t sz;
		long cur;

		/*
		 * Do everything from the child: the arena vma is VM_DONTCOPY so
		 * it would not survive fork(), only the child should be under the
		 * limit so that a memcg OOM cannot pick test_progs, and a map is
		 * charged to the memcg of the task that creates it - so join
		 * before load. The cgroup work dir belongs to the parent that set
		 * the environment up, so reach it with the _parent() helpers.
		 * Errors are reported to the parent through the exit code, since
		 * ASSERT_* in a forked child does not reach it.
		 */
		snprintf(buf, sizeof(buf), "%d", getpid());
		if (write_cgroup_file_parent(CG_PATH, "cgroup.procs", buf))
			_exit(2);

		cskel = arena_memcg__open_and_load();
		if (!cskel)
			_exit(3);

		base = bpf_map__initial_value(cskel->maps.arena, &sz);
		if (!base)
			_exit(4);
		npages = bpf_map__max_entries(cskel->maps.arena);

		/*
		 * Cap only now, after load: everything but the fault-in is
		 * charged, so the arena gets a fixed budget regardless of what
		 * the load itself cost, and the load can never hit the limit.
		 */
		if (read_cgroup_file_parent(CG_PATH, "memory.current", buf, sizeof(buf)))
			_exit(5);
		cur = strtol(buf, NULL, 10);
		snprintf(buf, sizeof(buf), "%ld", cur + ARENA_BUDGET);
		if (write_cgroup_file_parent(CG_PATH, "memory.max", buf))
			_exit(6);

		for (i = 0; i < npages; i++)
			base[(size_t)i * ps] = 1;
		/* Faulted everything without dying: dump why (only under -v). */
		dump_memcg(read_cgroup_file_parent);
		_exit(0);
	}

	if (!ASSERT_EQ(waitpid(pid, &status, 0), pid, "waitpid"))
		goto out;

	/* A non-zero exit means the child failed to set up; the code says where. */
	if (WIFEXITED(status) && WEXITSTATUS(status)) {
		ASSERT_OK(WEXITSTATUS(status), "child setup");
		goto out;
	}

	/*
	 * Faulting a valid arena address until memory.max is hit must not look
	 * like an invalid access. Without the fix the fault path allocated with
	 * the non-blocking allocator, turned its -ENOMEM into VM_FAULT_SIGSEGV,
	 * and the child died with SIGSEGV on a valid address; now it is handled
	 * by the memcg OOM path instead. A SIGKILL alone would not prove the
	 * memcg OOM killer did it (a global OOM or an unrelated crash could also
	 * kill the child), so check memory.events.oom_kill, which records the
	 * memcg OOM and survives the child.
	 */
	if (!ASSERT_TRUE(WIFSIGNALED(status), "child killed by signal"))
		goto out;
	if (!ASSERT_GE(cg_read_key(CG_PATH, "memory.events", "oom_kill"), 1,
		       "memcg oom_kill"))
		dump_memcg(read_cgroup_file);
out:
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	cleanup_cgroup_environment();
}
