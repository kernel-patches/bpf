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

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

enum subtest_kind {
	SUBTEST_FENTRY,
	SUBTEST_FEXIT,
	SUBTEST_FENTRY_S,
	SUBTEST_FEXIT_S,
	SUBTEST_RAW_TP,
	SUBTEST_RAW_TP_S,
	SUBTEST_TP_BTF,
	SUBTEST_FSESSION,
	SUBTEST_TP_SYSCALL,
	SUBTEST_TAILCALL_RAW_TP,
	SUBTEST_TAILCALL_TP,
	SUBTEST_TWO_DISPATCHERS,
	SUBTEST_TP_DUAL,
	SUBTEST_NESTED_PROG,
};

enum recursion_kind {
	RECURSION_RAW_TP,
	RECURSION_TP_BTF,
	RECURSION_TEST_RUN,
	RECURSION_TWO_HOPS,
};

struct ctx {
	struct trampoline_preempt *skel;
	int cpu;
	int go_pipe[2];
	int done_pipe[2];
	sigset_t sigset;
	int err_a;
	int err_b;
	int overlaps;
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
		/* B preempted A only if A is still inside the program */
		if (*(volatile int *)&c->skel->bss->a_inside)
			c->overlaps++;
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

static void run_subtest(enum subtest_kind kind)
{
	struct ctx c = {
		.go_pipe = { -1, -1 },
		.done_pipe = { -1, -1 },
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_program *prog = NULL, *extra = NULL, *tail = NULL, *p;
	struct bpf_link *link = NULL, *link2 = NULL, *wakeup_link = NULL;
	struct bpf_map *jmp = NULL;
	sigset_t oldset;
	pthread_t ta, tb;
	bool ta_started = false, tb_started = false, sigmask_set = false;
	bool via_map, dual = false;
	__u32 zero = 0;
	int tail_fd;
	char ch;
	int err;

	c.skel = trampoline_preempt__open();
	if (!ASSERT_OK_PTR(c.skel, "open"))
		return;

	switch (kind) {
	case SUBTEST_FENTRY:
		prog = c.skel->progs.on_fentry;
		break;
	case SUBTEST_FEXIT:
		prog = c.skel->progs.on_fexit;
		break;
	case SUBTEST_FENTRY_S:
		prog = c.skel->progs.on_fentry_s;
		break;
	case SUBTEST_FEXIT_S:
		prog = c.skel->progs.on_fexit_s;
		break;
	case SUBTEST_RAW_TP:
		prog = c.skel->progs.on_raw_tp;
		break;
	case SUBTEST_RAW_TP_S:
		prog = c.skel->progs.on_raw_tp_s;
		break;
	case SUBTEST_TP_BTF:
		prog = c.skel->progs.on_tp_btf;
		break;
	case SUBTEST_FSESSION:
		prog = c.skel->progs.on_fsession;
		break;
	case SUBTEST_TP_SYSCALL:
		prog = c.skel->progs.on_tp_syscall;
		break;
	case SUBTEST_TAILCALL_RAW_TP:
		prog = c.skel->progs.dispatcher_raw_tp;
		tail = c.skel->progs.handler_raw_tp;
		jmp = c.skel->maps.jmp_raw_tp;
		break;
	case SUBTEST_TAILCALL_TP:
		prog = c.skel->progs.dispatcher_tp;
		tail = c.skel->progs.handler_tp;
		jmp = c.skel->maps.jmp_tp;
		break;
	case SUBTEST_TWO_DISPATCHERS:
		prog = c.skel->progs.dispatcher_a;
		extra = c.skel->progs.dispatcher_b;
		tail = c.skel->progs.handler_raw_tp;
		jmp = c.skel->maps.jmp_raw_tp;
		break;
	case SUBTEST_TP_DUAL:
		prog = c.skel->progs.on_tp_dual;
		dual = true;
		break;
	case SUBTEST_NESTED_PROG:
		prog = c.skel->progs.on_raw_tp_nested;
		break;
	}
	via_map = kind == SUBTEST_NESTED_PROG;
	bpf_object__for_each_program(p, c.skel->obj)
		bpf_program__set_autoload(p, p == prog || p == extra || p == tail ||
					  (via_map && p == c.skel->progs.on_wakeup_delete));

	err = trampoline_preempt__load(c.skel);
	if (err == -EOPNOTSUPP || err == -ENOTSUPP) {
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "load"))
		goto out;

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
	if (via_map) {
		wakeup_link = bpf_program__attach(c.skel->progs.on_wakeup_delete);
		if (!ASSERT_OK_PTR(wakeup_link, "attach_wakeup"))
			goto out;
	}
	if (dual) {
		LIBBPF_OPTS(bpf_tracepoint_opts, topts, .bpf_cookie = 1);

		link = bpf_program__attach_tracepoint_opts(prog, "syscalls",
							   "sys_enter_prctl", &topts);
		if (!ASSERT_OK_PTR(link, "attach_sys_enter"))
			goto out;
		topts.bpf_cookie = 2;
		link2 = bpf_program__attach_tracepoint_opts(prog, "task",
							    "task_rename", &topts);
		if (!ASSERT_OK_PTR(link2, "attach_task_rename"))
			goto out;
	} else {
		link = bpf_program__attach(prog);
		if (!ASSERT_OK_PTR(link, "attach"))
			goto out;
	}
	if (extra) {
		link2 = bpf_program__attach(extra);
		if (!ASSERT_OK_PTR(link2, "attach_extra"))
			goto out;
	}
	if (tail) {
		tail_fd = bpf_program__fd(tail);
		if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(jmp), &zero, &tail_fd,
						   BPF_ANY), "jmp_update"))
			goto out;
	}

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
	if (!c.overlaps) {
		/* B never preempted A inside the program, so nothing was tested */
		test__skip();
		goto out;
	}
	ASSERT_EQ(c.overlaps, NR_ROUNDS, "overlaps");
	ASSERT_EQ(c.skel->bss->stack_corrupt, 0, "stack_corrupt");
	ASSERT_EQ(c.skel->bss->runs_a, NR_ROUNDS, "runs_a");
	ASSERT_EQ(c.skel->bss->runs_b, NR_ROUNDS, "runs_b");
	ASSERT_EQ(c.skel->bss->b_inside_a, c.skel->bss->runs_b, "b_inside_a");

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
	bpf_link__destroy(link2);
	bpf_link__destroy(wakeup_link);
	trampoline_preempt__destroy(c.skel);
}

/*
 * The program calls bpf_printk(), which fires the bpf_trace_printk tracepoint
 * the program is attached to. The nested run must be rejected as recursion.
 * With two hops, a second program runs in between, so the check has to look
 * past the frame right below.
 */
static void run_recursion_subtest(enum recursion_kind kind)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct trampoline_preempt *skel;
	struct bpf_program *prog, *hop = NULL, *trigger, *p;
	struct bpf_link *link = NULL, *hop_link = NULL;
	int err;

	skel = trampoline_preempt__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	switch (kind) {
	case RECURSION_TP_BTF:
		prog = skel->progs.recur_tp_btf;
		break;
	case RECURSION_TWO_HOPS:
		prog = skel->progs.recur_two_hops;
		hop = skel->progs.recur_hop;
		break;
	default:
		prog = skel->progs.recur_raw_tp;
		break;
	}
	trigger = kind == RECURSION_TEST_RUN ? prog : skel->progs.recur_trigger;
	bpf_object__for_each_program(p, skel->obj)
		bpf_program__set_autoload(p, p == prog || p == hop || p == trigger);

	err = trampoline_preempt__load(skel);
	if (err == -EOPNOTSUPP || err == -ENOTSUPP) {
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "load"))
		goto out;
	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto out;
	if (hop) {
		hop_link = bpf_program__attach(hop);
		if (!ASSERT_OK_PTR(hop_link, "attach_hop"))
			goto out;
	}

	skel->bss->recur_tid = (int)syscall(SYS_gettid);
	err = bpf_prog_test_run_opts(bpf_program__fd(trigger), &opts);
	skel->bss->recur_tid = 0;
	if (!ASSERT_OK(err, "test_run"))
		goto out;

	ASSERT_EQ(skel->bss->recur_runs, 1, "recur_runs");
	err = bpf_prog_get_info_by_fd(bpf_program__fd(prog), &info, &info_len);
	if (ASSERT_OK(err, "prog_info"))
		ASSERT_EQ(info.recursion_misses, 1, "recursion_misses");
	if (hop) {
		ASSERT_EQ(skel->bss->hop_runs, 1, "hop_runs");
		memset(&info, 0, sizeof(info));
		err = bpf_prog_get_info_by_fd(bpf_program__fd(hop), &info, &info_len);
		if (ASSERT_OK(err, "hop_info"))
			ASSERT_EQ(info.recursion_misses, 0, "hop_recursion_misses");
	}
out:
	bpf_link__destroy(hop_link);
	bpf_link__destroy(link);
	trampoline_preempt__destroy(skel);
}

void test_trampoline_preempt(void)
{
	if (test__start_subtest("fentry"))
		run_subtest(SUBTEST_FENTRY);
	if (test__start_subtest("fexit"))
		run_subtest(SUBTEST_FEXIT);
	if (test__start_subtest("fentry_s"))
		run_subtest(SUBTEST_FENTRY_S);
	if (test__start_subtest("fexit_s"))
		run_subtest(SUBTEST_FEXIT_S);
	if (test__start_subtest("raw_tp"))
		run_subtest(SUBTEST_RAW_TP);
	if (test__start_subtest("raw_tp_s"))
		run_subtest(SUBTEST_RAW_TP_S);
	if (test__start_subtest("tp_btf"))
		run_subtest(SUBTEST_TP_BTF);
	if (test__start_subtest("fsession"))
		run_subtest(SUBTEST_FSESSION);
	if (test__start_subtest("tp_syscall"))
		run_subtest(SUBTEST_TP_SYSCALL);
	if (test__start_subtest("tailcall_raw_tp"))
		run_subtest(SUBTEST_TAILCALL_RAW_TP);
	if (test__start_subtest("tailcall_tp"))
		run_subtest(SUBTEST_TAILCALL_TP);
	if (test__start_subtest("two_dispatchers"))
		run_subtest(SUBTEST_TWO_DISPATCHERS);
	if (test__start_subtest("tp_dual"))
		run_subtest(SUBTEST_TP_DUAL);
	if (test__start_subtest("nested_prog"))
		run_subtest(SUBTEST_NESTED_PROG);
	if (test__start_subtest("recursion_raw_tp"))
		run_recursion_subtest(RECURSION_RAW_TP);
	if (test__start_subtest("recursion_tp_btf"))
		run_recursion_subtest(RECURSION_TP_BTF);
	if (test__start_subtest("recursion_test_run"))
		run_recursion_subtest(RECURSION_TEST_RUN);
	if (test__start_subtest("recursion_two_hops"))
		run_recursion_subtest(RECURSION_TWO_HOPS);
}
