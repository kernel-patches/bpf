// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include <sched.h>
#include "bpf_kthread.skel.h"
#include "verifier_bpf_kthread.skel.h"

/* The context of the syscall programs, as the programs declare it. */
struct kthread_args {
	__u32 idx;
	__u32 start;
	__u32 body;
	__u32 bind;
	__u32 cpu;
};

enum body {
	BODY_WORKER,
	BODY_SPAWNER,
	BODY_SELF_STOPPER,
	BODY_RING,
	BODY_STOP_CHECKER,
	BODY_SELF_BINDER,
};

static int run_prog(struct bpf_program *prog, struct kthread_args *args, int *retval)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = args,
		.ctx_size_in = args ? sizeof(*args) : 0,
	);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!err)
		*retval = opts.retval;
	return err;
}

static int create_thread_on(struct bpf_kthread *skel, __u32 idx, bool start, enum body body,
			    int cpu)
{
	struct kthread_args args = {
		.idx = idx, .start = start, .body = body, .bind = cpu >= 0, .cpu = cpu,
	};
	int err, retval;

	err = run_prog(skel->progs.create_thread, &args, &retval);
	if (!ASSERT_OK(err, "create_thread") || !ASSERT_EQ(retval, 0, "create_ret"))
		return -1;
	return 0;
}

static int create_thread(struct bpf_kthread *skel, __u32 idx, bool start, enum body body)
{
	return create_thread_on(skel, idx, start, body, -1);
}

static int bind_thread(struct bpf_kthread *skel, __u32 idx, __u32 cpu)
{
	struct kthread_args args = { .idx = idx, .cpu = cpu };
	int retval;

	if (!ASSERT_OK(run_prog(skel->progs.bind_thread, &args, &retval), "bind_thread"))
		return -EFAULT;
	return retval;
}

/* Returns what the program returned, which for stop_thread is what the stop returned. */
static int control_thread(struct bpf_program *prog, __u32 idx)
{
	struct kthread_args args = { .idx = idx };
	int retval;

	if (!ASSERT_OK(run_prog(prog, &args, &retval), bpf_program__name(prog)))
		return -EFAULT;
	return retval;
}

#define start_thread(skel, idx) control_thread((skel)->progs.start_thread, idx)
#define wake_thread(skel, idx) control_thread((skel)->progs.wake_thread, idx)
#define stop_thread(skel, idx) control_thread((skel)->progs.stop_thread, idx)

/* Poll until *p is nonzero, for up to two seconds. */
static bool wait_for(__u32 *p)
{
	int i;

	for (i = 0; i < 2000; i++) {
		if (__atomic_load_n(p, __ATOMIC_ACQUIRE))
			return true;
		usleep(1000);
	}
	return false;
}

/* Poll until *p exceeds @seen, for up to two seconds: the thread has looped again. */
static bool wait_past(__u32 *p, __u32 seen)
{
	int i;

	for (i = 0; i < 2000; i++) {
		if (__atomic_load_n(p, __ATOMIC_ACQUIRE) > seen)
			return true;
		usleep(1000);
	}
	return false;
}

/* Whether the thread sleeps: state 'S' in /proc/<tid>/stat, read past the parenthesised comm. */
static bool thread_sleeping(__u32 tid)
{
	char path[64], buf[512], *p;
	int fd, n;

	snprintf(path, sizeof(path), "/proc/%u/stat", tid);
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

/* Poll until the thread sleeps, for up to two seconds. */
static bool wait_sleeping(__u32 tid)
{
	int i;

	for (i = 0; i < 2000; i++) {
		if (thread_sleeping(tid))
			return true;
		usleep(1000);
	}
	return false;
}

/* The lowest and highest CPUs the test may run on; a bound thread has to run there. */
static int allowed_cpus(int *lo, int *hi)
{
	cpu_set_t set;
	int cpu;

	if (sched_getaffinity(0, sizeof(set), &set))
		return -1;
	*lo = *hi = -1;
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (!CPU_ISSET(cpu, &set))
			continue;
		if (*lo < 0)
			*lo = cpu;
		*hi = cpu;
	}
	return *lo < 0 ? -1 : 0;
}

static bool task_exists(__u32 tid)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/%u", tid);
	return !access(path, F_OK);
}

/* Poll until the task has left /proc, for up to two seconds. */
static bool wait_gone(__u32 tid)
{
	int i;

	for (i = 0; i < 2000; i++) {
		if (!task_exists(tid))
			return true;
		usleep(1000);
	}
	return false;
}

static int read_file(const char *path, char *buf, size_t size)
{
	int fd, n;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, size - 1);
	close(fd);
	if (n < 0)
		return -errno;
	buf[n] = 0;
	return n;
}

/*
 * The thread is named after the program that created it and its index among
 * the program's threads. /proc shows a kernel thread's full name whatever its
 * length; the comm the thread reads for itself is what tracepoints and perf
 * report, and the name is short enough to fit it.
 */
static void check_comm(struct bpf_kthread *skel, __u32 tid, __u32 idx)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	char path[64], buf[512], want[64];

	if (!ASSERT_OK(bpf_prog_get_info_by_fd(bpf_program__fd(skel->progs.create_thread),
					       &info, &len), "prog_info"))
		return;
	snprintf(want, sizeof(want), "bpfk/%u:%u", info.id, idx);

	snprintf(path, sizeof(path), "/proc/%u/comm", tid);
	if (!ASSERT_GT(read_file(path, buf, sizeof(buf)), 0, "read comm"))
		return;
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0;
	ASSERT_STREQ(buf, want, "comm");
	ASSERT_STREQ(skel->bss->comms[idx], want, "task comm");
}

/*
 * A started thread runs its callback, which parks until woken; its return ends
 * the thread and is what the stop reports.
 */
static void test_start_exit(void)
{
	struct bpf_kthread *skel;
	__u32 tid;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (create_thread(skel, 0, true, BODY_WORKER))
		goto out;
	if (!ASSERT_TRUE(wait_for(&skel->bss->runs[0]), "ran"))
		goto out;
	tid = skel->bss->tids[0];
	ASSERT_TRUE(task_exists(tid), "alive");
	ASSERT_TRUE(wait_sleeping(tid), "parked");
	check_comm(skel, tid, 0);

	__atomic_store_n(&skel->bss->exit_now[0], 1, __ATOMIC_RELEASE);
	ASSERT_GE(wake_thread(skel, 0), 0, "wake ret");
	ASSERT_TRUE(wait_gone(tid), "exited");
	ASSERT_EQ(stop_thread(skel, 0), 1, "exit code");
	ASSERT_EQ(skel->bss->runs[0], 1, "runs");
	ASSERT_EQ(stop_thread(skel, 0), -ESRCH, "slot empty");
out:
	bpf_kthread__destroy(skel);
}

/* A stop ends a running callback through bpf_kthread_should_stop(). */
static void test_stop_running(void)
{
	struct bpf_kthread *skel;
	__u32 tid;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (create_thread(skel, 1, true, BODY_WORKER))
		goto out;
	if (!ASSERT_TRUE(wait_for(&skel->bss->runs[1]), "ran"))
		goto out;
	tid = skel->bss->tids[1];
	ASSERT_EQ(stop_thread(skel, 1), 0, "stop ret");
	ASSERT_TRUE(wait_gone(tid), "exited");
out:
	bpf_kthread__destroy(skel);
}

/* A stop makes every park return -ESHUTDOWN, except one that has a wake to consume. */
static void test_stop_park_rets(void)
{
	struct bpf_kthread *skel;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (create_thread(skel, 0, true, BODY_STOP_CHECKER))
		goto out;
	if (!ASSERT_TRUE(wait_for(&skel->bss->runs[0]), "ran"))
		goto out;
	ASSERT_EQ(stop_thread(skel, 0), 1, "stop ret");
	ASSERT_EQ(skel->bss->stop_park_rets[0], -ESHUTDOWN, "park the stop ended");
	ASSERT_EQ(skel->bss->stop_park_rets[1], -ESHUTDOWN, "poll after the stop");
	ASSERT_EQ(skel->bss->stop_park_rets[2], 0, "park with a wake pending");
	ASSERT_EQ(skel->bss->stop_park_rets[3], -ESHUTDOWN, "park after the wake");
out:
	bpf_kthread__destroy(skel);
}

/* A thread stopped before it is started never runs its callback. */
static void test_stop_parked(void)
{
	struct bpf_kthread *skel;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (create_thread(skel, 2, false, BODY_WORKER))
		goto out;
	ASSERT_EQ(stop_thread(skel, 2), -EINTR, "stop ret");
	ASSERT_EQ(skel->bss->runs[2], 0, "runs");
out:
	bpf_kthread__destroy(skel);
}

/* A parked thread starts through an RCU-protected pointer; a second start is a no-op. */
static void test_start_later(void)
{
	struct bpf_kthread *skel;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (create_thread(skel, 2, false, BODY_WORKER))
		goto out;
	ASSERT_EQ(start_thread(skel, 2), 0, "start ret");
	if (!ASSERT_TRUE(wait_for(&skel->bss->runs[2]), "ran"))
		goto out;
	ASSERT_EQ(start_thread(skel, 2), 0, "second start ret");
	ASSERT_EQ(stop_thread(skel, 2), 0, "stop ret");
	ASSERT_EQ(skel->bss->runs[2], 1, "runs");
out:
	bpf_kthread__destroy(skel);
}

/* A thread cannot stop itself. */
static void test_self_stop(void)
{
	struct bpf_kthread *skel;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (create_thread(skel, 3, true, BODY_SELF_STOPPER))
		goto out;
	if (!ASSERT_TRUE(wait_for(&skel->bss->runs[3]), "ran"))
		goto out;
	ASSERT_EQ(skel->bss->self_stop_ret, -EDEADLK, "self stop ret");
	ASSERT_EQ(stop_thread(skel, 3), 0, "stop ret");
out:
	bpf_kthread__destroy(skel);
}

/* A thread creates and starts another thread from its callback. */
static void test_spawn(void)
{
	struct bpf_kthread *skel;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (create_thread(skel, 0, true, BODY_SPAWNER))
		goto out;
	if (!ASSERT_TRUE(wait_for(&skel->bss->runs[1]), "child ran") ||
	    !ASSERT_TRUE(wait_for(&skel->bss->runs[0]), "parent ran"))
		goto out;
	ASSERT_EQ(skel->bss->spawn_ret, 0, "spawn ret");
	ASSERT_NEQ(skel->bss->tids[0], skel->bss->tids[1], "distinct threads");
	check_comm(skel, skel->bss->tids[0], 0);
	check_comm(skel, skel->bss->tids[1], 1);
	ASSERT_EQ(stop_thread(skel, 1), 0, "stop child");
	ASSERT_EQ(stop_thread(skel, 0), 0, "stop parent");
out:
	bpf_kthread__destroy(skel);
}

/* Tasks that are no BPF kthreads, nonzero flags, and a stop before the start. */
static void test_misuse(void)
{
	struct bpf_kthread *skel;
	int retval;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (ASSERT_OK(run_prog(skel->progs.control_foreign_task, NULL, &retval), "foreign")) {
		ASSERT_EQ(retval, 0, "foreign ret");
		ASSERT_EQ(skel->bss->foreign_start_ret, -ESRCH, "foreign start ret");
		ASSERT_EQ(skel->bss->foreign_stop_ret, -ESRCH, "foreign stop ret");
	}
	if (ASSERT_OK(run_prog(skel->progs.misuse, NULL, &retval), "misuse"))
		ASSERT_EQ(retval, 0, "misuse ret");
	bpf_kthread__destroy(skel);
}

/* The program's release stops the threads it still has. */
static void test_program_free(void)
{
	struct bpf_kthread *skel;
	__u32 tid;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (create_thread(skel, 0, true, BODY_WORKER))
		goto out;
	if (!ASSERT_TRUE(wait_for(&skel->bss->runs[0]), "ran"))
		goto out;
	tid = skel->bss->tids[0];
	bpf_kthread__destroy(skel);
	ASSERT_TRUE(wait_gone(tid), "exited");
	return;
out:
	bpf_kthread__destroy(skel);
}

/*
 * Threads stopping each other in a ring. The stop that would close the ring of
 * waits is refused with -EDEADLK, the others return their successor's exit
 * code as the ring unwinds, and every thread exits. The thread the refused
 * stop was aimed at is the one left in its slot; the others were taken by the
 * threads that stopped them.
 */
static void test_stop_ring(__u32 size)
{
	struct bpf_kthread *skel;
	int refused = 0, left = 0, ret;
	__u32 i, peer;

	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	skel->bss->ring_size = size;
	for (i = 0; i < size; i++)
		if (create_thread(skel, i, false, BODY_RING))
			goto out;
	for (i = 0; i < size; i++)
		if (!ASSERT_EQ(start_thread(skel, i), 0, "start ret"))
			goto out;
	for (i = 0; i < size; i++) {
		if (!ASSERT_TRUE(wait_for(&skel->bss->runs[i]), "ran") ||
		    !ASSERT_TRUE(wait_gone(skel->bss->tids[i]), "exited"))
			goto out;
	}
	for (i = 0; i < size; i++) {
		peer = i + 1 < size ? i + 1 : 0;
		ret = skel->bss->ring_stop_ret[i];
		if (ret == -EDEADLK)
			refused++;
		else
			ASSERT_EQ(ret, peer + 1, "ring stop ret");
	}
	ASSERT_EQ(refused, 1, "one stop refused");
	for (i = 0; i < size; i++) {
		ret = stop_thread(skel, i);
		if (ret == -ESRCH)
			continue;
		ASSERT_EQ(ret, i + 1, "exit code");
		left++;
	}
	ASSERT_EQ(left, 1, "one thread left in its slot");
out:
	bpf_kthread__destroy(skel);
}

/*
 * A thread bound before its start runs on that CPU, and the last bind wins. A
 * thread bound while it runs moves at its next sleep, which for a body that
 * parks is at once, since the park sleeps with migration enabled; its next
 * iteration runs on the new CPU.
 */
static void test_bind(void)
{
	struct bpf_kthread *skel;
	int lo, hi;
	__u32 loops;

	if (!ASSERT_OK(allowed_cpus(&lo, &hi), "allowed_cpus"))
		return;
	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (create_thread_on(skel, 0, false, BODY_WORKER, lo))
		goto out;
	ASSERT_EQ(bind_thread(skel, 0, -1), -EINVAL, "bind impossible cpu");
	ASSERT_EQ(bind_thread(skel, 0, hi), 0, "bind ret");
	ASSERT_EQ(start_thread(skel, 0), 0, "start ret");
	if (!ASSERT_TRUE(wait_past(&skel->bss->loops[0], 0), "ran"))
		goto out;
	ASSERT_EQ(skel->bss->cpus[0], hi, "cpu");
	ASSERT_EQ(bind_thread(skel, 0, lo), 0, "bind running ret");
	loops = skel->bss->loops[0];
	ASSERT_GE(wake_thread(skel, 0), 0, "wake ret");
	if (ASSERT_TRUE(wait_past(&skel->bss->loops[0], loops), "looped"))
		ASSERT_EQ(skel->bss->cpus[0], lo, "cpu after bind");
	ASSERT_EQ(stop_thread(skel, 0), 0, "stop ret");
out:
	bpf_kthread__destroy(skel);
}

/*
 * A thread binds itself: it is migratable during the call, so the bind takes
 * effect before it returns, and the thread's first iteration runs on the CPU.
 */
static void test_self_bind(void)
{
	struct bpf_kthread *skel;
	int lo, hi;

	if (!ASSERT_OK(allowed_cpus(&lo, &hi), "allowed_cpus"))
		return;
	skel = bpf_kthread__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	skel->bss->self_bind_cpu = lo;
	if (create_thread(skel, 0, true, BODY_SELF_BINDER))
		goto out;
	if (!ASSERT_TRUE(wait_past(&skel->bss->loops[0], 0), "ran"))
		goto out;
	ASSERT_EQ(skel->bss->self_bind_ret, 0, "self bind ret");
	ASSERT_EQ(skel->bss->cpus[0], lo, "cpu");
	ASSERT_EQ(stop_thread(skel, 0), 0, "stop ret");
out:
	bpf_kthread__destroy(skel);
}

void test_bpf_kthread(void)
{
	RUN_TESTS(verifier_bpf_kthread);

	if (test__start_subtest("start_exit"))
		test_start_exit();
	if (test__start_subtest("stop_running"))
		test_stop_running();
	if (test__start_subtest("stop_park_rets"))
		test_stop_park_rets();
	if (test__start_subtest("stop_parked"))
		test_stop_parked();
	if (test__start_subtest("start_later"))
		test_start_later();
	if (test__start_subtest("self_stop"))
		test_self_stop();
	if (test__start_subtest("spawn"))
		test_spawn();
	if (test__start_subtest("misuse"))
		test_misuse();
	if (test__start_subtest("program_free"))
		test_program_free();
	if (test__start_subtest("stop_ring2"))
		test_stop_ring(2);
	if (test__start_subtest("stop_ring3"))
		test_stop_ring(3);
	if (test__start_subtest("bind"))
		test_bind();
	if (test__start_subtest("self_bind"))
		test_self_bind();
}
