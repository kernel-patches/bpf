// SPDX-License-Identifier: GPL-2.0
/*
 * Attach and detach uprobes while a process keeps its mmap_lock busy.
 * Other processes should be able to fork, and children of the busy process
 * should have the same breakpoints as everybody else.
 */
#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <test_progs.h>
#include "bpf/libbpf_internal.h"
#include "uprobe_busy_mm.skel.h"

#ifndef MADV_POPULATE_READ
#define MADV_POPULATE_READ 22
#endif

#define LOAD(x)		__atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define STORE(x, v)	__atomic_store_n(&(x), v, __ATOMIC_SEQ_CST)
#define INC(x)		__atomic_add_fetch(&(x), 1, __ATOMIC_SEQ_CST)

#define AREA_MAX	(64UL << 30)
#define AREA_MIN	(64UL << 20)
#define MAX_CHILDREN	8
#define MAX_TRIES	10
#define TIMEOUT_NS	(30 * 1000000000ULL)

struct shared {
	/* written by the test */
	int stop;
	int gen;		/* odd while attach or detach is in progress */
	int attached;
	int hold_ms;
	bool do_fork;
	char insn[4];
	/* written by the busy process */
	int ready;
	int hold_seq;		/* number of times mmap_lock was let go */
	__u64 hold_ns;		/* for how long it was held the last time */
	int in_hold;
	int in_fork;
	int forks;		/* number of times fork() returned */
	int errors;
	int checked[2];		/* children that checked their breakpoint, by ->attached */
};

static struct shared *sh;

static noinline void uprobe_busy_mm_func(void)
{
	asm volatile ("");
}

static __u64 now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*
 * MADV_POPULATE_READ holds mmap_lock for reading while it maps zero page
 * all over the area. It costs page tables only.
 */
static void *hold_mmap_lock(void *arg)
{
	size_t size = AREA_MIN;
	void *area;
	__u64 t;

	area = mmap(NULL, AREA_MAX, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (area == MAP_FAILED)
		goto err;
	/* EINVAL without CONFIG_TRANSPARENT_HUGEPAGE */
	madvise(area, AREA_MAX, MADV_NOHUGEPAGE);

	t = now_ns();
	if (madvise(area, size, MADV_POPULATE_READ))
		goto err;
	t = now_ns() - t;
	size *= sh->hold_ms * 1000000ULL / t + 1;
	if (size > AREA_MAX)
		size = AREA_MAX;

	while (!LOAD(sh->stop)) {
		STORE(sh->in_hold, 1);
		t = now_ns();
		madvise(area, size, MADV_POPULATE_READ);
		/* before anything that can fault and wait for fork() */
		INC(sh->hold_seq);
		STORE(sh->hold_ns, now_ns() - t);
		STORE(sh->in_hold, 0);
		madvise(area, size, MADV_DONTNEED);
		STORE(sh->ready, 1);
	}
	return NULL;
err:
	INC(sh->errors);
	STORE(sh->ready, 1);
	return NULL;
}

/*
 * fork() began while attach or detach was in progress.
 * When it's over the child should be like other processes.
 */
static int child(int gen)
{
	bool attached, bp;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (!(gen & 1))
		return 0;
	gen++;

	while (LOAD(sh->gen) < gen) {
		if (LOAD(sh->stop))
			return 0;
		usleep(100);
	}

	attached = LOAD(sh->attached);
	bp = memcmp((void *)uprobe_busy_mm_func, sh->insn, sizeof(sh->insn));
	if (LOAD(sh->gen) != gen)
		return 0;
	if (bp != attached)
		return 1;

	/* SIGTRAP when there is a breakpoint without uprobe */
	uprobe_busy_mm_func();
	if (LOAD(sh->gen) == gen)
		INC(sh->checked[attached]);
	return 0;
}

static void busy_process(void)
{
	int status, gen, nr = 0;
	pthread_t thread;
	pid_t pid;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	if (pthread_create(&thread, NULL, hold_mmap_lock, NULL)) {
		INC(sh->errors);
		STORE(sh->ready, 1);
		_exit(1);
	}

	while (sh->do_fork && !LOAD(sh->stop)) {
		while (nr && waitpid(-1, &status, nr < MAX_CHILDREN ? WNOHANG : 0) > 0) {
			if (status)
				INC(sh->errors);
			nr--;
		}

		gen = LOAD(sh->gen);
		STORE(sh->in_fork, 1);
		pid = fork();
		if (!pid)
			_exit(child(gen));
		INC(sh->forks);
		STORE(sh->in_fork, 0);
		if (pid < 0) {
			INC(sh->errors);
			break;
		}
		nr++;
	}

	while (nr-- && wait(&status) > 0)
		if (status)
			INC(sh->errors);
	pthread_join(thread, NULL);
	_exit(0);
}

/* The busy process gave up or is gone */
static bool busy_process_failed(pid_t pid)
{
	siginfo_t si = {};

	return LOAD(sh->errors) ||
	       waitid(P_PID, pid, &si, WEXITED | WNOHANG | WNOWAIT) || si.si_pid;
}

static pid_t start_busy_process(int hold_ms, bool do_fork)
{
	__u64 t = now_ns();
	pid_t pid;

	sh = mmap(NULL, sizeof(*sh), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_NEQ(sh, MAP_FAILED, "mmap"))
		return -1;

	sh->hold_ms = hold_ms;
	sh->do_fork = do_fork;
	memcpy(sh->insn, (void *)uprobe_busy_mm_func, sizeof(sh->insn));

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork")) {
		munmap(sh, sizeof(*sh));
		return -1;
	}
	if (!pid)
		busy_process();

	while (!LOAD(sh->ready) && !busy_process_failed(pid) && now_ns() - t < TIMEOUT_NS)
		usleep(1000);
	if (!ASSERT_TRUE(LOAD(sh->ready), "busy_process_ready")) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		munmap(sh, sizeof(*sh));
		return -1;
	}
	return pid;
}

static void stop_busy_process(pid_t pid)
{
	int status = -1;

	STORE(sh->stop, 1);
	waitpid(pid, &status, 0);
	ASSERT_EQ(status, 0, "busy_process_status");
	ASSERT_EQ(sh->errors, 0, "errors");
	munmap(sh, sizeof(*sh));
}

/* Returns hold_seq of the hold that has just begun, -1 if there won't be one */
static int wait_for_hold(pid_t pid, bool in_fork)
{
	__u64 t = now_ns();
	int seq;

	while (!busy_process_failed(pid) && now_ns() - t < TIMEOUT_NS) {
		if (!LOAD(sh->in_hold) || (in_fork && !LOAD(sh->in_fork))) {
			usleep(100);
			continue;
		}
		seq = LOAD(sh->hold_seq);
		/* let them get into the kernel */
		usleep(10000);
		if (LOAD(sh->hold_seq) == seq && (!in_fork || LOAD(sh->in_fork)))
			return seq;
	}

	return -1;
}

static struct bpf_link *attach(struct uprobe_busy_mm *skel, bool multi,
			       const char *path, unsigned long offset)
{
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts, .offsets = &offset, .cnt = 1);

	if (multi)
		return bpf_program__attach_uprobe_multi(skel->progs.probe_multi, -1, path,
							NULL, &opts);
	return bpf_program__attach_uprobe(skel->progs.probe_perf, false, -1, path, offset);
}

/*
 * Wait for a child to check its breakpoint in this state. fork() that began
 * during attach or detach may sleep until the next hold is over.
 */
static void wait_for_check(int attached, int checked)
{
	__u64 t = now_ns(), max = 2 * LOAD(sh->hold_ns) + 100 * 1000000ULL;

	while (LOAD(sh->checked[attached]) == checked && now_ns() - t < max)
		usleep(1000);
}

static void test_fork(struct uprobe_busy_mm *skel, bool multi)
{
	struct bpf_link *link;
	ssize_t offset;
	int i, checked;
	pid_t pid;
	__u64 t;

	offset = get_uprobe_offset(&uprobe_busy_mm_func);
	if (!ASSERT_GE(offset, 0, "get_uprobe_offset"))
		return;

	pid = start_busy_process(20, true);
	if (pid < 0)
		return;
	skel->bss->hits = 0;
	t = now_ns();

	for (i = 0; !busy_process_failed(pid) && now_ns() - t < TIMEOUT_NS; i++) {
		if (i >= 10 && LOAD(sh->checked[0]) && LOAD(sh->checked[1]))
			break;

		checked = LOAD(sh->checked[1]);
		INC(sh->gen);
		link = attach(skel, multi, "/proc/self/exe", offset);
		if (!ASSERT_OK_PTR(link, "attach"))
			break;
		STORE(sh->attached, 1);
		INC(sh->gen);
		wait_for_check(1, checked);

		checked = LOAD(sh->checked[0]);
		INC(sh->gen);
		bpf_link__destroy(link);
		STORE(sh->attached, 0);
		INC(sh->gen);
		wait_for_check(0, checked);
	}

	ASSERT_GT(LOAD(sh->checked[1]), 0, "checked_attached");
	ASSERT_GT(LOAD(sh->checked[0]), 0, "checked_detached");
	ASSERT_GE(skel->bss->hits, LOAD(sh->checked[1]), "hits");
	stop_busy_process(pid);
}

struct attach_args {
	struct uprobe_busy_mm *skel;
	unsigned long offset;
	struct bpf_link *link;
	int done;
};

static void *attach_thread(void *arg)
{
	struct attach_args *args = arg;

	args->link = attach(args->skel, true, "/proc/self/exe", args->offset);
	STORE(args->done, 1);
	return NULL;
}

/* fork() doesn't wait for attach that waits for mmap_lock of the busy process */
static void test_fork_not_blocked(struct uprobe_busy_mm *skel)
{
	struct attach_args args = { .skel = skel };
	pid_t pid, child_pid;
	bool ok = false;
	pthread_t thread;
	ssize_t offset;
	int i, seq;

	offset = get_uprobe_offset(&uprobe_busy_mm_func);
	if (!ASSERT_GE(offset, 0, "get_uprobe_offset"))
		return;
	args.offset = offset;

	pid = start_busy_process(300, false);
	if (pid < 0)
		return;

	for (i = 0; i < MAX_TRIES && !ok && !LOAD(sh->errors); i++) {
		seq = wait_for_hold(pid, false);
		if (!ASSERT_GE(seq, 0, "wait_for_hold"))
			break;

		args.done = 0;
		if (!ASSERT_OK(pthread_create(&thread, NULL, attach_thread, &args),
			       "pthread_create"))
			break;
		/* attach waits for RCU first, fork() isn't blocked by that */
		usleep(LOAD(sh->hold_ns) / 2000);

		child_pid = fork();
		if (!child_pid)
			_exit(0);
		ok = child_pid > 0 && !LOAD(args.done) && LOAD(sh->hold_seq) == seq;
		if (child_pid > 0)
			waitpid(child_pid, NULL, 0);

		pthread_join(thread, NULL);
		if (!ASSERT_OK_PTR(args.link, "attach"))
			break;
		bpf_link__destroy(args.link);
	}

	ASSERT_TRUE(ok, "fork_not_blocked");
	stop_busy_process(pid);
}

/* attach doesn't wait for fork() that waits for mmap_lock of the busy process */
static void test_attach_not_blocked(struct uprobe_busy_mm *skel)
{
	const char *path = "./uprobe_multi", *sym = "uprobe_multi_func_00000";
	unsigned long *offsets = NULL;
	struct bpf_link *link;
	bool ok = false;
	int i, seq, forks;
	pid_t pid;

	if (!ASSERT_OK(elf_resolve_syms_offsets(path, 1, &sym, &offsets, STT_FUNC),
		       "elf_resolve_syms_offsets"))
		return;

	pid = start_busy_process(300, true);
	if (pid < 0)
		goto out;

	for (i = 0; i < MAX_TRIES && !ok && !LOAD(sh->errors); i++) {
		seq = wait_for_hold(pid, true);
		if (!ASSERT_GE(seq, 0, "wait_for_hold"))
			break;

		forks = LOAD(sh->forks);

		link = attach(skel, true, path, offsets[0]);
		/*
		 * attach that waited for fork() returns as soon as fork() has
		 * copied mm, maybe before the busy process bumps forks and
		 * hold_seq. Give it a quarter of the hold to do that.
		 */
		usleep(LOAD(sh->hold_ns) / 4000);
		ok = LOAD(sh->in_fork) && LOAD(sh->forks) == forks &&
		     LOAD(sh->hold_seq) == seq;
		if (!ASSERT_OK_PTR(link, "attach"))
			break;
		bpf_link__destroy(link);
	}

	ASSERT_TRUE(ok, "attach_not_blocked");
	stop_busy_process(pid);
out:
	free(offsets);
}

void serial_test_uprobe_busy_mm(void)
{
	struct uprobe_busy_mm *skel;

	skel = uprobe_busy_mm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_busy_mm__open_and_load"))
		return;

	if (test__start_subtest("fork_multi"))
		test_fork(skel, true);
	if (test__start_subtest("fork_perf"))
		test_fork(skel, false);
	if (test__start_subtest("fork_not_blocked"))
		test_fork_not_blocked(skel);
	if (test__start_subtest("attach_not_blocked"))
		test_attach_not_blocked(skel);

	uprobe_busy_mm__destroy(skel);
}
