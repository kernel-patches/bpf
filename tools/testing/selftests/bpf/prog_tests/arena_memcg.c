// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#ifndef PAGE_SIZE /* on some archs it comes in sys/user.h */
#include <unistd.h>
#define PAGE_SIZE getpagesize()
#endif

#include "cgroup_helpers.h"
#include "arena_memcg.skel.h"

#define CG_PATH		"/arena_memcg"

/* Budget the arena gets on top of whatever is already charged after load. */
#define ARENA_BUDGET	(64 * 1024 * 1024)

/*
 * cgroup_helpers builds paths from getpid(), but the work dir belongs to the
 * process that set the environment up. The child references it through that
 * pid, so build the path explicitly.
 */
static void cg_file_path(char *buf, size_t sz, pid_t owner, const char *file)
{
	snprintf(buf, sz, "/mnt/cgroup-test-work-dir%d%s/%s", owner, CG_PATH, file);
}

static long cg_read_ulong(pid_t owner, const char *file)
{
	char path[PATH_MAX], buf[64];
	long val = -1;
	FILE *f;

	cg_file_path(path, sizeof(path), owner, file);
	f = fopen(path, "r");
	if (!f)
		return -1;
	if (fgets(buf, sizeof(buf), f))
		val = strtol(buf, NULL, 10);
	fclose(f);
	return val;
}

static int cg_write(pid_t owner, const char *file, const char *val)
{
	char path[PATH_MAX];
	int fd, len, ret = -1;

	cg_file_path(path, sizeof(path), owner, file);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	len = strlen(val);
	if (write(fd, val, len) == len)
		ret = 0;
	close(fd);
	return ret;
}

void serial_test_arena_memcg(void)
{
	int cgroup_fd = -1, status;
	const long ps = PAGE_SIZE;
	pid_t owner, pid;

	if (setup_cgroup_environment())
		return;
	owner = getpid();

	cgroup_fd = create_and_get_cgroup(CG_PATH);
	if (!ASSERT_OK_FD(cgroup_fd, "create_and_get_cgroup"))
		goto out;

	/* No memory controller -> nothing to test. */
	if (cg_read_ulong(owner, "memory.current") < 0) {
		test__skip();
		goto out;
	}

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto out;
	if (pid == 0) {
		struct arena_memcg *cskel;
		__u32 i, npages;
		char buf[32];
		char *base;
		size_t sz;
		long cur;

		/*
		 * Do everything from the child: the arena vma is VM_DONTCOPY so
		 * it would not survive fork(), only the child should be under the
		 * limit so that a memcg OOM cannot pick test_progs, and a map is
		 * charged to the memcg of the task that creates it - so join
		 * before load. Errors are reported to the parent through the exit
		 * code, since ASSERT_* in a forked child does not reach it.
		 */
		snprintf(buf, sizeof(buf), "%d", getpid());
		if (cg_write(owner, "cgroup.procs", buf))
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
		cur = cg_read_ulong(owner, "memory.current");
		if (cur < 0)
			_exit(5);
		snprintf(buf, sizeof(buf), "%ld", cur + ARENA_BUDGET);
		if (cg_write(owner, "memory.max", buf))
			_exit(6);

		for (i = 0; i < npages; i++)
			base[(size_t)i * ps] = 1;
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
	 * by the memcg OOM path and the child is killed by SIGKILL instead. A
	 * clean exit means the child failed to set up (see the exit codes).
	 */
	if (!ASSERT_TRUE(WIFSIGNALED(status), "child killed by signal"))
		goto out;
	ASSERT_NEQ(WTERMSIG(status), SIGSEGV, "not killed by SIGSEGV");
out:
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	cleanup_cgroup_environment();
}
