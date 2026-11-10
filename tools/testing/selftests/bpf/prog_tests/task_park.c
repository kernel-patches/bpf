// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <pthread.h>
#include <signal.h>
#include <sys/syscall.h>
#include "task_park.skel.h"
#include "verifier_task_park.skel.h"
#include "verifier_task_park_frames.skel.h"

static int run_syscall_prog(struct bpf_program *prog, __u32 *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!err)
		*retval = opts.retval;
	return err;
}

/* A thread blocked in a syscall program that parks. */
struct waiter {
	struct bpf_program *prog;
	pthread_t thread;
	pid_t tid;
	__u32 retval;
	int err;
	int done;
};

static void *waiter_fn(void *arg)
{
	struct waiter *w = arg;

	__atomic_store_n(&w->tid, syscall(SYS_gettid), __ATOMIC_RELEASE);
	w->err = run_syscall_prog(w->prog, &w->retval);
	__atomic_store_n(&w->done, 1, __ATOMIC_RELEASE);
	return NULL;
}

static bool waiter_done(struct waiter *w)
{
	return __atomic_load_n(&w->done, __ATOMIC_ACQUIRE);
}

static int start_waiter(struct waiter *w, struct bpf_program *prog)
{
	memset(w, 0, sizeof(*w));
	w->prog = prog;
	return pthread_create(&w->thread, NULL, waiter_fn, w);
}

/*
 * Whether the waiter thread sleeps in the kernel, which for this thread can
 * only be the park: state 'S' in /proc/self/task/<tid>/stat, read past the
 * parenthesised comm.
 */
static bool waiter_sleeping(struct waiter *w)
{
	pid_t tid = __atomic_load_n(&w->tid, __ATOMIC_ACQUIRE);
	char path[64], buf[512], *p;
	int fd, n;

	if (!tid)
		return false;
	snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return false;
	buf[n] = 0;
	p = strrchr(buf, ')');
	return p && p[1] == ' ' && p[2] == 'S';
}

/*
 * Wake the waiter until it has returned. A wake before the waiter published
 * itself finds no task and sets nothing; one that finds the task sets the
 * condition, so the waiter returns 0 only after a wake run that found it,
 * and such a run returns 0 or 1. Returns the last result that found a task,
 * or -ESRCH if none did.
 */
static int wake_until_done(struct task_park *skel, struct waiter *w)
{
	int i, last = -ESRCH;
	__u32 retval;

	for (i = 0; i < 5000 && !waiter_done(w); i++) {
		if (run_syscall_prog(skel->progs.wake_waiter, &retval))
			break;
		if ((__s32)retval >= 0)
			last = retval;
		usleep(1000);
	}
	return last;
}

static void test_timeout(struct task_park *skel)
{
	__u32 retval;

	if (ASSERT_OK(run_syscall_prog(skel->progs.park_timeout, &retval), "park_timeout"))
		ASSERT_EQ((__s32)retval, -ETIMEDOUT, "timeout_ret");
}

static void test_flags(struct task_park *skel)
{
	__u32 retval;

	if (ASSERT_OK(run_syscall_prog(skel->progs.bad_flags, &retval), "bad_flags"))
		ASSERT_EQ(retval, 0, "flags_ret");
}

static void test_pending(struct task_park *skel)
{
	__u32 retval;

	if (ASSERT_OK(run_syscall_prog(skel->progs.park_pending, &retval), "park_pending"))
		ASSERT_EQ((__s32)retval, -ETIMEDOUT, "pending_ret");
}

static void test_wake(struct task_park *skel)
{
	struct waiter w;
	int last;

	if (!ASSERT_OK(start_waiter(&w, skel->progs.park_until_woken), "pthread_create"))
		return;
	last = wake_until_done(skel, &w);
	pthread_join(w.thread, NULL);
	ASSERT_GE(last, 0, "wake_found_waiter");
	ASSERT_OK(w.err, "park_until_woken");
	ASSERT_EQ((__s32)w.retval, 0, "wake_park_ret");
}

/*
 * Wake a waiter that is known to be asleep, without a timer: once the thread
 * shows as sleeping, the one wake that follows must report that it found the
 * task asleep.
 */
static void test_wake_asleep(struct task_park *skel)
{
	__u64 timeout = skel->data->park_timeout_ns;
	struct waiter w;
	__u32 retval;
	int i;

	skel->data->park_timeout_ns = ~0ULL;
	if (!ASSERT_OK(start_waiter(&w, skel->progs.park_until_woken), "pthread_create"))
		goto out;
	for (i = 0; i < 5000 && !waiter_sleeping(&w); i++)
		usleep(1000);
	if (ASSERT_TRUE(waiter_sleeping(&w), "waiter_sleeping")) {
		if (ASSERT_OK(run_syscall_prog(skel->progs.wake_waiter, &retval), "wake_waiter"))
			ASSERT_EQ((__s32)retval, 1, "wake_found_asleep");
	}
	/* Bound any further park before draining, so a lost wake cannot hang the join. */
	skel->data->park_timeout_ns = timeout;
	wake_until_done(skel, &w);
	pthread_join(w.thread, NULL);
	ASSERT_OK(w.err, "park_until_woken");
	ASSERT_EQ((__s32)w.retval, 0, "wake_park_ret");
out:
	skel->data->park_timeout_ns = timeout;
}

static void sig_noop(int sig)
{
}

/*
 * A program that parks cannot be the target of a tail call: a prog array takes
 * a syscall program that wakes and refuses one that parks.
 */
static void test_prog_array(struct task_park *skel)
{
	int map_fd = bpf_map__fd(skel->maps.jmp_table);
	__u32 key = 0;
	int fd;

	fd = bpf_program__fd(skel->progs.wake_waiter);
	ASSERT_OK(bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY), "member_that_wakes");
	fd = bpf_program__fd(skel->progs.park_timeout);
	ASSERT_EQ(bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY), -EINVAL, "member_that_parks");
}

/* A signal ends the sleep, and the park reports it as -EINTR. */
static void test_signal(struct task_park *skel)
{
	struct sigaction sa = { .sa_handler = sig_noop }, old_sa;
	struct waiter w;
	bool interrupted;
	int i;

	if (!ASSERT_OK(sigaction(SIGUSR2, &sa, &old_sa), "sigaction"))
		return;
	if (!ASSERT_OK(start_waiter(&w, skel->progs.park_until_woken), "pthread_create"))
		goto out;
	/* A signal handled before the thread enters its syscall ends nothing: resend. */
	for (i = 0; i < 5000 && !waiter_done(&w); i++) {
		pthread_kill(w.thread, SIGUSR2);
		usleep(1000);
	}
	interrupted = waiter_done(&w);
	if (!interrupted)
		wake_until_done(skel, &w);
	pthread_join(w.thread, NULL);
	ASSERT_TRUE(interrupted, "interrupted");
	ASSERT_OK(w.err, "park_until_woken");
	ASSERT_EQ((__s32)w.retval, -EINTR, "signal_park_ret");
out:
	sigaction(SIGUSR2, &old_sa, NULL);
}

void test_task_park(void)
{
	struct task_park *skel;

	RUN_TESTS(verifier_task_park);
	RUN_TESTS(verifier_task_park_frames);

	skel = task_park__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (test__start_subtest("timeout"))
		test_timeout(skel);
	if (test__start_subtest("flags"))
		test_flags(skel);
	if (test__start_subtest("pending"))
		test_pending(skel);
	if (test__start_subtest("wake"))
		test_wake(skel);
	if (test__start_subtest("wake_asleep"))
		test_wake_asleep(skel);
	if (test__start_subtest("prog_array"))
		test_prog_array(skel);
	if (test__start_subtest("signal"))
		test_signal(skel);
	task_park__destroy(skel);
}
