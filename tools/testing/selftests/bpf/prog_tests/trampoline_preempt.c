// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <test_progs.h>
#include "trampoline_preempt.skel.h"

#define NR_ROUNDS 20

struct ctx {
	struct trampoline_preempt *skel;
	int cpu;
	int go_pipe[2];
	int done_pipe[2];
	sigset_t sigset;
	int err_a;
	int err_b;
};

static int pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		return -errno;
	return 0;
}

static void *worker_a(void *arg)
{
	struct ctx *c = arg;
	char comm[16] = {};
	char ch = 'a';

	c->err_a = pin_to_cpu(c->cpu);
	if (!c->err_a && prctl(PR_GET_NAME, comm, 0, 0, 0))
		c->err_a = -errno;
	c->skel->bss->tid_a = (int)syscall(SYS_gettid);

	if (write(c->done_pipe[1], &ch, 1) != 1 || c->err_a)
		goto out;

	while (read(c->go_pipe[0], &ch, 1) == 1) {
		if (prctl(PR_SET_NAME, comm, 0, 0, 0)) {
			c->err_a = -errno;
			break;
		}
		if (write(c->done_pipe[1], &ch, 1) != 1) {
			c->err_a = -EIO;
			break;
		}
	}

out:
	close(c->done_pipe[1]);
	c->done_pipe[1] = -1;
	return NULL;
}

static void *worker_b(void *arg)
{
	struct sched_param sp = { .sched_priority = 1 };
	struct timespec ts = { .tv_sec = 5 };
	struct ctx *c = arg;
	char comm[16] = {};
	char ch = 'b';
	int i;

	c->err_b = pin_to_cpu(c->cpu);
	if (c->err_b)
		goto out;
	if (sched_setscheduler(0, SCHED_FIFO, &sp)) {
		c->err_b = -errno;
		goto out;
	}
	if (prctl(PR_GET_NAME, comm, 0, 0, 0)) {
		c->err_b = -errno;
		goto out;
	}
	c->skel->bss->tid_b = (int)syscall(SYS_gettid);

	for (i = 0; i < NR_ROUNDS; i++) {
		if (write(c->go_pipe[1], &ch, 1) != 1) {
			c->err_b = -EIO;
			break;
		}
		while (sigtimedwait(&c->sigset, NULL, &ts) < 0) {
			if (errno == EINTR)
				continue;
			c->err_b = -errno;
			break;
		}
		if (c->err_b)
			break;
		if (prctl(PR_SET_NAME, comm, 0, 0, 0)) {
			c->err_b = -errno;
			break;
		}
		if (read(c->done_pipe[0], &ch, 1) != 1) {
			c->err_b = -EIO;
			break;
		}
	}

out:
	close(c->go_pipe[1]);
	c->go_pipe[1] = -1;
	return NULL;
}

static void run_subtest(bool is_fexit)
{
	struct ctx c = {
		.go_pipe = { -1, -1 },
		.done_pipe = { -1, -1 },
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	sigset_t oldset;
	pthread_t ta, tb;
	bool ta_started = false, tb_started = false, sigmask_set = false;
	char ch;
	int err;

	c.skel = trampoline_preempt__open_and_load();
	if (!ASSERT_OK_PTR(c.skel, "open_and_load"))
		return;

	if (c.skel->kconfig->CONFIG_PREEMPT_RT) {
		test__skip();
		goto out;
	}

	c.cpu = sched_getcpu();
	if (!ASSERT_GE(c.cpu, 0, "sched_getcpu"))
		goto out;

	if (!ASSERT_OK(pipe(c.go_pipe), "go_pipe"))
		goto out;
	if (!ASSERT_OK(pipe(c.done_pipe), "done_pipe"))
		goto out;

	sigemptyset(&c.sigset);
	sigaddset(&c.sigset, SIGUSR1);
	if (!ASSERT_OK(pthread_sigmask(SIG_BLOCK, &c.sigset, &oldset), "sigmask"))
		goto out;
	sigmask_set = true;

	c.skel->bss->sig = SIGUSR1;
	prog = is_fexit ? c.skel->progs.on_fexit : c.skel->progs.on_fentry;
	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto out;

	if (!ASSERT_OK(pthread_create(&ta, NULL, worker_a, &c), "pthread_a"))
		goto out;
	ta_started = true;

	if (!ASSERT_EQ(read(c.done_pipe[0], &ch, 1), 1, "ready_a"))
		goto out;
	if (!ASSERT_OK(c.err_a, "setup_a"))
		goto out;

	if (!ASSERT_OK(pthread_create(&tb, NULL, worker_b, &c), "pthread_b"))
		goto out;
	tb_started = true;

	pthread_join(tb, NULL);
	tb_started = false;
	pthread_join(ta, NULL);
	ta_started = false;

	if (c.err_b == -EPERM || c.err_b == -EACCES) {
		test__skip();
		goto out;
	}

	ASSERT_OK(c.err_a, "worker_a_err");
	ASSERT_OK(c.err_b, "worker_b_err");
	ASSERT_EQ(c.skel->bss->sig_err, 0, "sig_err");
	ASSERT_EQ(c.skel->bss->runs_a, NR_ROUNDS, "runs_a");
	ASSERT_EQ(c.skel->bss->runs_b, NR_ROUNDS, "runs_b");

	err = bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &info_len);
	if (ASSERT_OK(err, "prog_info"))
		ASSERT_EQ(info.recursion_misses, 0, "recursion_misses");

out:
	if (c.go_pipe[1] >= 0)
		close(c.go_pipe[1]);
	if (tb_started)
		pthread_join(tb, NULL);
	if (ta_started)
		pthread_join(ta, NULL);
	if (c.go_pipe[0] >= 0)
		close(c.go_pipe[0]);
	if (c.done_pipe[0] >= 0)
		close(c.done_pipe[0]);
	if (c.done_pipe[1] >= 0)
		close(c.done_pipe[1]);
	if (sigmask_set)
		pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	bpf_link__destroy(link);
	trampoline_preempt__destroy(c.skel);
}

void test_trampoline_preempt(void)
{
	if (test__start_subtest("fentry"))
		run_subtest(false);
	if (test__start_subtest("fexit"))
		run_subtest(true);
}
