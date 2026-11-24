// SPDX-License-Identifier: GPL-2.0
/*
 * Test that a task which called vfork() only runs again once the child has
 * left the mm, i.e. once it has switched to its new mm in exec or has dropped
 * the mm in exit, also when it is killed in the middle of an exec.
 *
 * The first field of /proc/<pid>/statm is the size of the mm a task is on.
 * The parent has a mapping that is larger than anything the child ends up
 * with: an exec'd image of this program is a lot smaller and a task that has
 * dropped its mm shows 0.
 *
 * A parent that is woken up too early only has a few instructions to look
 * before the child is gone. So it runs in a realtime scheduling class and the
 * child, which is on the same cpu, doesn't. On a kernel with preemption the
 * parent runs as soon as it's woken up and the child doesn't get any further
 * meanwhile. Without preemption the child gets too far for the parent to see
 * anything so the tests are skipped there.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kselftest_harness.h"

/* 32 bit architectures that only have the time64 system calls. */
#if !defined(SYS_futex) && defined(SYS_futex_time64)
#define SYS_futex SYS_futex_time64
#endif

/* Makes the exec'd image wait to be killed. */
#define EXECED_ARG	"execed"

/* Exit status of a child that never made it into the exec'd image. */
#define EXIT_NO_EXEC	127

/* How often the parent looks at a child. */
#define ROUNDS		16

/* What only the mm of the parent has. */
#define MAPPING_SIZE	(1UL << 30)

/* How many readers of /proc/<pid>/stat share one cpu. */
#define READERS		8

/* Size in pages of the mm @pid is on, 0 if it has none. */
static long mm_size(pid_t pid)
{
	char path[64], buf[128];
	ssize_t len;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/statm", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0)
		return -1;
	buf[len] = '\0';
	return strtol(buf, NULL, 10);
}

/* A kernel that preempts kernel code says so in its version string. */
static bool kernel_preempts(void)
{
	struct utsname u;

	return !uname(&u) && strstr(u.version, "PREEMPT");
}

/* The child only gets to call exec and _exit(). */
static pid_t vfork_exec(void)
{
	pid_t pid = vfork();

	if (pid == 0) {
		execl("/proc/self/exe", "vfork-mm", EXECED_ARG, (char *)NULL);
		_exit(EXIT_NO_EXEC);
	}
	return pid;
}

/*
 * Same, but the child tells whoever reads from @tell who it is and waits to
 * be told on @go. The kernel clears *@tid when the child releases the mm.
 */
static pid_t vfork_exec_tid(int tell, int go, int *tid)
{
	pid_t pid = vfork();

	if (pid == 0) {
		pid_t self = getpid();
		char c;

		*tid = self;
		syscall(SYS_set_tid_address, tid);
		if (write(tell, &self, sizeof(self)) == sizeof(self) &&
		    read(go, &c, 1) == 1)
			execl("/proc/self/exe", "vfork-mm", EXECED_ARG,
			      (char *)NULL);
		_exit(EXIT_NO_EXEC);
	}
	return pid;
}

static pid_t vfork_exit(void)
{
	pid_t pid = vfork();

	if (pid == 0)
		_exit(EXIT_SUCCESS);
	return pid;
}

FIXTURE(vfork_mm)
{
	char *map;
	long pages;
	/* The clear_child_tid word of a child, shared with the helper. */
	int *tid;
	/* The cpu the parent and its children are on. */
	int cpu;
	/* The cpus the test was started on. */
	cpu_set_t allowed;
};

FIXTURE_SETUP(vfork_mm)
{
	struct sched_param param = { .sched_priority = 1 };
	cpu_set_t cpus;
	long size;

	if (!kernel_preempts())
		SKIP(return, "Needs a kernel with preemption");

	self->pages = MAPPING_SIZE / sysconf(_SC_PAGESIZE);
	self->map = mmap(NULL, MAPPING_SIZE, PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (self->map == MAP_FAILED)
		SKIP(return, "Can't map %lu bytes", MAPPING_SIZE);
	size = mm_size(getpid());
	if (size < 0)
		SKIP(return, "Can't read /proc/self/statm");
	ASSERT_GE(size, self->pages);

	self->tid = mmap(NULL, sizeof(*self->tid), PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(self->tid, MAP_FAILED);

	/* Too many cpus for the mask: the helper takes any cpu it can get. */
	if (sched_getaffinity(0, sizeof(self->allowed), &self->allowed))
		memset(&self->allowed, 0xff, sizeof(self->allowed));

	/* The policy isn't inherited, the cpu is. */
	self->cpu = sched_getcpu();
	CPU_ZERO(&cpus);
	CPU_SET(self->cpu, &cpus);
	if (sched_setaffinity(0, sizeof(cpus), &cpus) ||
	    sched_setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &param))
		SKIP(return, "Can't make the parent preempt the child");
}

FIXTURE_TEARDOWN(vfork_mm)
{
	munmap(self->map, MAPPING_SIZE);
	munmap(self->tid, sizeof(*self->tid));
}

TEST_F(vfork_mm, exec)
{
	int status;
	pid_t pid;
	long size;
	int i;

	for (i = 0; i < ROUNDS; i++) {
		pid = vfork_exec();
		/* Look before anything else. */
		size = mm_size(pid);
		ASSERT_GT(pid, 0);
		kill(pid, SIGKILL);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		/* It didn't exit on its own so the exec didn't fail. */
		ASSERT_TRUE(WIFSIGNALED(status));
		ASSERT_GE(size, 0);
		ASSERT_LT(size, self->pages) {
			TH_LOG("round %d: vfork() returned with the child still on the mm", i);
		}
	}
}

/* Take exec_update_lock of @pid for reading until it's gone. */
static void stat_reader(pid_t pid, int ready)
{
	char path[64], buf[1024];
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0 || pread(fd, buf, sizeof(buf), 0) <= 0 ||
	    write(ready, "", 1) != 1)
		_exit(EXIT_FAILURE);
	while (pread(fd, buf, sizeof(buf), 0) > 0)
		;
	_exit(EXIT_SUCCESS);
}

/*
 * Kill whoever shows up on @tell right when it has released its mm in exec.
 * It only stops there if it has to wait for exec_update_lock. So there are
 * more readers of its /proc/<pid>/stat than the one cpu they share can run:
 * most of them are preempted at any time, some of them with the lock held.
 */
static void killer(FIXTURE_DATA(vfork_mm) *self, pid_t parent, int tell,
		   int go)
{
	struct sched_param param = { .sched_priority = 1 };
	pid_t helper = getpid();
	cpu_set_t cpus;
	int ready[2];
	int cpu, tid;
	pid_t pid;
	char c;
	int i;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (getppid() != parent)
		_exit(EXIT_FAILURE);

	/* Any cpu the test may use but the one of the child. */
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (cpu == self->cpu || !CPU_ISSET(cpu, &self->allowed))
			continue;
		CPU_ZERO(&cpus);
		CPU_SET(cpu, &cpus);
		if (!sched_setaffinity(0, sizeof(cpus), &cpus))
			break;
	}

	if (read(tell, &pid, sizeof(pid)) != sizeof(pid) ||
	    pipe2(ready, O_CLOEXEC))
		_exit(EXIT_FAILURE);

	for (i = 0; i < READERS; i++) {
		pid_t reader = fork();

		if (reader < 0)
			_exit(EXIT_FAILURE);
		if (reader == 0) {
			prctl(PR_SET_PDEATHSIG, SIGKILL);
			if (getppid() != helper)
				_exit(EXIT_FAILURE);
			stat_reader(pid, ready[1]);
		}
	}
	for (i = 0; i < READERS; i++) {
		if (read(ready[0], &c, 1) != 1)
			_exit(EXIT_FAILURE);
	}

	/* The kernel wakes us up when it has cleared the word. */
	if (sched_setscheduler(0, SCHED_FIFO, &param) || write(go, "", 1) != 1)
		_exit(EXIT_FAILURE);
	while ((tid = __atomic_load_n(self->tid, __ATOMIC_RELAXED)))
		syscall(SYS_futex, self->tid, FUTEX_WAIT, tid, NULL, NULL, 0);
	kill(pid, SIGKILL);

	/* The readers go when we do. */
	for (;;)
		pause();
}

/*
 * A child that is killed in exec after it has released the mm doesn't get to
 * switch to a new one. It leaves the mm when it exits.
 */
TEST_F(vfork_mm, exec_killed)
{
	pid_t parent = getpid();
	int tell[2], go[2];
	pid_t pid, helper;
	int nomm = 0;
	int status;
	long size;
	int i;

	for (i = 0; i < ROUNDS; i++) {
		ASSERT_EQ(pipe2(tell, O_CLOEXEC), 0);
		ASSERT_EQ(pipe2(go, O_CLOEXEC), 0);
		*self->tid = 1;

		helper = fork();
		ASSERT_GE(helper, 0);
		if (helper == 0) {
			close(tell[1]);
			close(go[0]);
			killer(self, parent, tell[0], go[1]);
		}
		close(tell[0]);
		close(go[1]);

		pid = vfork_exec_tid(tell[1], go[0], self->tid);
		/* Look before anything else. */
		size = mm_size(pid);
		ASSERT_GT(pid, 0);
		kill(pid, SIGKILL);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		kill(helper, SIGKILL);
		ASSERT_EQ(waitpid(helper, NULL, 0), helper);
		close(tell[1]);
		close(go[0]);
		ASSERT_TRUE(WIFSIGNALED(status));
		ASSERT_GE(size, 0);
		ASSERT_LT(size, self->pages) {
			TH_LOG("round %d: vfork() returned with the child still on the mm", i);
		}
		if (!size)
			nomm++;
	}
	if (!nomm)
		SKIP(return, "The child was never killed before it got to the new mm");
}

TEST_F(vfork_mm, exit)
{
	int status;
	pid_t pid;
	long size;
	int i;

	for (i = 0; i < ROUNDS; i++) {
		pid = vfork_exit();
		/* Look before anything else. */
		size = mm_size(pid);
		ASSERT_GT(pid, 0);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(size, 0) {
			TH_LOG("round %d: vfork() returned with the child still on the mm", i);
		}
	}
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], EXECED_ARG)) {
		for (;;)
			pause();
	}
	return test_harness_run(argc, argv);
}
