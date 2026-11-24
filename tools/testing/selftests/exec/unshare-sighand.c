// SPDX-License-Identifier: GPL-2.0
/*
 * Test exec in a task that shares its signal table with another process
 * without being one of its threads, i.e. CLONE_SIGHAND without CLONE_THREAD.
 * The exec has to give the task a private table before it resets the
 * handlers so the other process keeps the table they shared. If the other
 * process waits for the task in vfork() the task has to have its private
 * table before that process runs again.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kselftest_harness.h"

#define STACK_SIZE	(64 * 1024)

/* Makes the exec'd image check its dispositions. */
#define EXECED_ARG	"execed"
/* Makes the exec'd image check the signal its vfork() parent ignored. */
#define EXECED_VFORK_ARG	"execed-vfork"

/* Exit status of a sharer that never made it into the exec'd image. */
#define EXIT_NO_EXEC	127

/* Handled before the clone. */
static const int handled_signals[] = { SIGUSR1, SIGUSR2 };
/* Handled by the sharer right before its exec. */
#define SHARER_SIGNAL	SIGTERM
/* Ignored before the clone. */
#define IGNORED_SIGNAL	SIGHUP
/* Ignored by a vfork() parent as soon as it runs again. */
#define VFORK_SIGNAL	SIGINT

/* How often a vfork() parent races with the exec of its child. */
#define VFORK_ROUNDS	16

/* How much the thread that holds the mmap lock has to work on. */
#define WRITER_SIZE	(1UL << 30)

static void handler(int sig)
{
}

static int set_disposition(int sig, sighandler_t disposition)
{
	const struct sigaction sa = { .sa_handler = disposition };

	return sigaction(sig, &sa, NULL);
}

static const char *disposition_name(sighandler_t disposition)
{
	if (disposition == SIG_DFL)
		return "default";
	if (disposition == SIG_IGN)
		return "ignored";
	return "handled";
}

static bool has_disposition(const char *who, int sig, sighandler_t disposition)
{
	struct sigaction sa;

	if (sigaction(sig, NULL, &sa))
		return false;
	ksft_print_msg("%s: signal %d (%s) is %s\n", who, sig, strsignal(sig),
		       disposition_name(sa.sa_handler));
	return sa.sa_handler == disposition;
}

/* The signals with a handler must have @handled, the ignored one SIG_IGN. */
static bool check_dispositions(const char *who, sighandler_t handled)
{
	bool ret = true;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(handled_signals); i++)
		ret &= has_disposition(who, handled_signals[i], handled);
	ret &= has_disposition(who, SHARER_SIGNAL, handled);
	ret &= has_disposition(who, IGNORED_SIGNAL, SIG_IGN);
	return ret;
}

static int setup_dispositions(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(handled_signals); i++) {
		if (set_disposition(handled_signals[i], handler))
			return -1;
	}
	return set_disposition(IGNORED_SIGNAL, SIG_IGN);
}

static int sharer(void *arg)
{
	/* The parent only gets to see this if the table really is shared. */
	if (!set_disposition(SHARER_SIGNAL, handler))
		execl("/proc/self/exe", "unshare-sighand", EXECED_ARG,
		      (char *)NULL);
	_exit(EXIT_NO_EXEC);
}

TEST(exec_unshares_sighand)
{
	char *stack;
	int status;
	pid_t pid;

	ASSERT_EQ(setup_dispositions(), 0);

	stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	ASSERT_NE(stack, MAP_FAILED);

	pid = clone(sharer, stack + STACK_SIZE,
		    CLONE_VM | CLONE_SIGHAND | SIGCHLD, NULL);
	ASSERT_GT(pid, 0);
	ASSERT_EQ(waitpid(pid, &status, 0), pid);
	ASSERT_TRUE(WIFEXITED(status));
	/* The exec'd image has the handlers reset and SIG_IGN inherited. */
	EXPECT_EQ(WEXITSTATUS(status), EXIT_SUCCESS);

	/* The table was shared up to the exec and the exec left it alone. */
	EXPECT_TRUE(check_dispositions("parent", handler));

	EXPECT_EQ(munmap(stack, STACK_SIZE), 0);
}

struct mmap_writer {
	pthread_t thread;
	char *map;
	bool stop;
};

/*
 * Hold the mmap lock for writing most of the time. An exec that waits for
 * the mmap lock of the old mm after it has woken up a vfork() parent gives
 * that parent all the time it needs.
 */
static void *mmap_writer(void *arg)
{
	struct mmap_writer *writer = arg;

	while (!__atomic_load_n(&writer->stop, __ATOMIC_RELAXED)) {
		mprotect(writer->map, WRITER_SIZE, PROT_NONE);
		mprotect(writer->map, WRITER_SIZE, PROT_READ);
	}
	return NULL;
}

static int vfork_sharer(void *arg)
{
	execl("/proc/self/exe", "unshare-sighand", EXECED_VFORK_ARG,
	      (char *)NULL);
	_exit(EXIT_NO_EXEC);
}

TEST(exec_unshares_sighand_before_vfork_returns)
{
	struct sched_param param = { .sched_priority = 1 };
	struct mmap_writer writer = {};
	cpu_set_t cpu;
	char *stack;
	int status;
	pid_t pid;
	int i;

	stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	ASSERT_NE(stack, MAP_FAILED);

	/* One page table entry per page, all of them the zero page. */
	writer.map = mmap(NULL, WRITER_SIZE, PROT_READ,
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	ASSERT_NE(writer.map, MAP_FAILED);
	madvise(writer.map, WRITER_SIZE, MADV_NOHUGEPAGE);
	madvise(writer.map, WRITER_SIZE, MADV_POPULATE_READ);
	ASSERT_EQ(pthread_create(&writer.thread, NULL, mmap_writer, &writer), 0);

	/*
	 * The task that is cloned below runs on our cpu and, as the policy
	 * isn't inherited, not in a realtime scheduling class. On a kernel
	 * with preemption we run as soon as it wakes us up and it doesn't get
	 * any further meanwhile. Without the privilege for that only an exec
	 * that sleeps after it has woken us up is caught.
	 */
	CPU_ZERO(&cpu);
	CPU_SET(sched_getcpu(), &cpu);
	if (!sched_setaffinity(0, sizeof(cpu), &cpu))
		sched_setscheduler(0, SCHED_FIFO | SCHED_RESET_ON_FORK, &param);

	for (i = 0; i < VFORK_ROUNDS; i++) {
		ASSERT_EQ(set_disposition(VFORK_SIGNAL, SIG_DFL), 0);

		pid = clone(vfork_sharer, stack + STACK_SIZE,
			    CLONE_VM | CLONE_VFORK | CLONE_SIGHAND | SIGCHLD,
			    NULL);
		/* The task has its own table. This is none of its business. */
		set_disposition(VFORK_SIGNAL, SIG_IGN);
		ASSERT_GT(pid, 0);
		ASSERT_EQ(waitpid(pid, &status, 0), pid);
		ASSERT_TRUE(WIFEXITED(status));
		ASSERT_EQ(WEXITSTATUS(status), EXIT_SUCCESS) {
			TH_LOG("round %d: ignored after vfork(), ignored in the exec'd image", i);
		}
	}

	__atomic_store_n(&writer.stop, true, __ATOMIC_RELAXED);
	ASSERT_EQ(pthread_join(writer.thread, NULL), 0);
	EXPECT_EQ(munmap(writer.map, WRITER_SIZE), 0);
	EXPECT_EQ(munmap(stack, STACK_SIZE), 0);
}

int main(int argc, char **argv)
{
	struct sigaction sa;

	if (argc == 2 && !strcmp(argv[1], EXECED_ARG))
		return check_dispositions("exec'd image", SIG_DFL) ?
		       EXIT_SUCCESS : EXIT_FAILURE;
	if (argc == 2 && !strcmp(argv[1], EXECED_VFORK_ARG)) {
		if (sigaction(VFORK_SIGNAL, NULL, &sa))
			return EXIT_FAILURE;
		return sa.sa_handler == SIG_DFL ? EXIT_SUCCESS : EXIT_FAILURE;
	}
	return test_harness_run(argc, argv);
}
