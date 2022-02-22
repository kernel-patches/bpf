// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <test_progs.h>
#include "test_bpf_cookie.skel.h"
#include "kprobe_multi_bpf_cookie.skel.h"

/* uprobe attach point */
static void trigger_func(void)
{
	asm volatile ("");
}

static void kprobe_subtest(struct test_bpf_cookie *skel)
{
	DECLARE_LIBBPF_OPTS(bpf_kprobe_opts, opts);
	struct bpf_link *link1 = NULL, *link2 = NULL;
	struct bpf_link *retlink1 = NULL, *retlink2 = NULL;

	/* attach two kprobes */
	opts.bpf_cookie = 0x1;
	opts.retprobe = false;
	link1 = bpf_program__attach_kprobe_opts(skel->progs.handle_kprobe,
						 SYS_NANOSLEEP_KPROBE_NAME, &opts);
	if (!ASSERT_OK_PTR(link1, "link1"))
		goto cleanup;

	opts.bpf_cookie = 0x2;
	opts.retprobe = false;
	link2 = bpf_program__attach_kprobe_opts(skel->progs.handle_kprobe,
						 SYS_NANOSLEEP_KPROBE_NAME, &opts);
	if (!ASSERT_OK_PTR(link2, "link2"))
		goto cleanup;

	/* attach two kretprobes */
	opts.bpf_cookie = 0x10;
	opts.retprobe = true;
	retlink1 = bpf_program__attach_kprobe_opts(skel->progs.handle_kretprobe,
						    SYS_NANOSLEEP_KPROBE_NAME, &opts);
	if (!ASSERT_OK_PTR(retlink1, "retlink1"))
		goto cleanup;

	opts.bpf_cookie = 0x20;
	opts.retprobe = true;
	retlink2 = bpf_program__attach_kprobe_opts(skel->progs.handle_kretprobe,
						    SYS_NANOSLEEP_KPROBE_NAME, &opts);
	if (!ASSERT_OK_PTR(retlink2, "retlink2"))
		goto cleanup;

	/* trigger kprobe && kretprobe */
	usleep(1);

	ASSERT_EQ(skel->bss->kprobe_res, 0x1 | 0x2, "kprobe_res");
	ASSERT_EQ(skel->bss->kretprobe_res, 0x10 | 0x20, "kretprobe_res");

cleanup:
	bpf_link__destroy(link1);
	bpf_link__destroy(link2);
	bpf_link__destroy(retlink1);
	bpf_link__destroy(retlink2);
}

static void kprobe_multi_subtest(void)
{
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
	int err, prog_fd, link1_fd = -1, link2_fd = -1;
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct kprobe_multi_bpf_cookie *skel = NULL;
	__u64 addrs[8], cookies[8];

	skel = kprobe_multi_bpf_cookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		goto cleanup;

	kallsyms_find("bpf_fentry_test1", &addrs[0]);
	kallsyms_find("bpf_fentry_test2", &addrs[1]);
	kallsyms_find("bpf_fentry_test3", &addrs[2]);
	kallsyms_find("bpf_fentry_test4", &addrs[3]);
	kallsyms_find("bpf_fentry_test5", &addrs[4]);
	kallsyms_find("bpf_fentry_test6", &addrs[5]);
	kallsyms_find("bpf_fentry_test7", &addrs[6]);
	kallsyms_find("bpf_fentry_test8", &addrs[7]);

	cookies[0] = 1;
	cookies[1] = 2;
	cookies[2] = 3;
	cookies[3] = 4;
	cookies[4] = 5;
	cookies[5] = 6;
	cookies[6] = 7;
	cookies[7] = 8;

	opts.kprobe_multi.addrs = ptr_to_u64(&addrs);
	opts.kprobe_multi.cnt = 8;
	opts.kprobe_multi.cookies = ptr_to_u64(&cookies);
	prog_fd = bpf_program__fd(skel->progs.test2);

	link1_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE_MULTI, &opts);
	if (!ASSERT_GE(link1_fd, 0, "link1_fd"))
		return;

	cookies[0] = 8;
	cookies[1] = 7;
	cookies[2] = 6;
	cookies[3] = 5;
	cookies[4] = 4;
	cookies[5] = 3;
	cookies[6] = 2;
	cookies[7] = 1;

	opts.flags = BPF_F_KPROBE_MULTI_RETURN;
	prog_fd = bpf_program__fd(skel->progs.test3);

	link2_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_KPROBE_MULTI, &opts);
	if (!ASSERT_GE(link2_fd, 0, "link2_fd"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(topts.retval, 0, "test_run");

	ASSERT_EQ(skel->bss->test2_result, 8, "test2_result");
	ASSERT_EQ(skel->bss->test3_result, 8, "test3_result");

cleanup:
	close(link1_fd);
	close(link2_fd);
	kprobe_multi_bpf_cookie__destroy(skel);
}

static void uprobe_subtest(struct test_bpf_cookie *skel)
{
	DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts);
	struct bpf_link *link1 = NULL, *link2 = NULL;
	struct bpf_link *retlink1 = NULL, *retlink2 = NULL;
	ssize_t uprobe_offset;

	uprobe_offset = get_uprobe_offset(&trigger_func);
	if (!ASSERT_GE(uprobe_offset, 0, "uprobe_offset"))
		goto cleanup;

	/* attach two uprobes */
	opts.bpf_cookie = 0x100;
	opts.retprobe = false;
	link1 = bpf_program__attach_uprobe_opts(skel->progs.handle_uprobe, 0 /* self pid */,
						"/proc/self/exe", uprobe_offset, &opts);
	if (!ASSERT_OK_PTR(link1, "link1"))
		goto cleanup;

	opts.bpf_cookie = 0x200;
	opts.retprobe = false;
	link2 = bpf_program__attach_uprobe_opts(skel->progs.handle_uprobe, -1 /* any pid */,
						"/proc/self/exe", uprobe_offset, &opts);
	if (!ASSERT_OK_PTR(link2, "link2"))
		goto cleanup;

	/* attach two uretprobes */
	opts.bpf_cookie = 0x1000;
	opts.retprobe = true;
	retlink1 = bpf_program__attach_uprobe_opts(skel->progs.handle_uretprobe, -1 /* any pid */,
						   "/proc/self/exe", uprobe_offset, &opts);
	if (!ASSERT_OK_PTR(retlink1, "retlink1"))
		goto cleanup;

	opts.bpf_cookie = 0x2000;
	opts.retprobe = true;
	retlink2 = bpf_program__attach_uprobe_opts(skel->progs.handle_uretprobe, 0 /* self pid */,
						   "/proc/self/exe", uprobe_offset, &opts);
	if (!ASSERT_OK_PTR(retlink2, "retlink2"))
		goto cleanup;

	/* trigger uprobe && uretprobe */
	trigger_func();

	ASSERT_EQ(skel->bss->uprobe_res, 0x100 | 0x200, "uprobe_res");
	ASSERT_EQ(skel->bss->uretprobe_res, 0x1000 | 0x2000, "uretprobe_res");

cleanup:
	bpf_link__destroy(link1);
	bpf_link__destroy(link2);
	bpf_link__destroy(retlink1);
	bpf_link__destroy(retlink2);
}

static void tp_subtest(struct test_bpf_cookie *skel)
{
	DECLARE_LIBBPF_OPTS(bpf_tracepoint_opts, opts);
	struct bpf_link *link1 = NULL, *link2 = NULL, *link3 = NULL;

	/* attach first tp prog */
	opts.bpf_cookie = 0x10000;
	link1 = bpf_program__attach_tracepoint_opts(skel->progs.handle_tp1,
						    "syscalls", "sys_enter_nanosleep", &opts);
	if (!ASSERT_OK_PTR(link1, "link1"))
		goto cleanup;

	/* attach second tp prog */
	opts.bpf_cookie = 0x20000;
	link2 = bpf_program__attach_tracepoint_opts(skel->progs.handle_tp2,
						    "syscalls", "sys_enter_nanosleep", &opts);
	if (!ASSERT_OK_PTR(link2, "link2"))
		goto cleanup;

	/* trigger tracepoints */
	usleep(1);

	ASSERT_EQ(skel->bss->tp_res, 0x10000 | 0x20000, "tp_res1");

	/* now we detach first prog and will attach third one, which causes
	 * two internal calls to bpf_prog_array_copy(), shuffling
	 * bpf_prog_array_items around. We test here that we don't lose track
	 * of associated bpf_cookies.
	 */
	bpf_link__destroy(link1);
	link1 = NULL;
	kern_sync_rcu();
	skel->bss->tp_res = 0;

	/* attach third tp prog */
	opts.bpf_cookie = 0x40000;
	link3 = bpf_program__attach_tracepoint_opts(skel->progs.handle_tp3,
						    "syscalls", "sys_enter_nanosleep", &opts);
	if (!ASSERT_OK_PTR(link3, "link3"))
		goto cleanup;

	/* trigger tracepoints */
	usleep(1);

	ASSERT_EQ(skel->bss->tp_res, 0x20000 | 0x40000, "tp_res2");

cleanup:
	bpf_link__destroy(link1);
	bpf_link__destroy(link2);
	bpf_link__destroy(link3);
}

static void burn_cpu(void)
{
	volatile int j = 0;
	cpu_set_t cpu_set;
	int i, err;

	/* generate some branches on cpu 0 */
	CPU_ZERO(&cpu_set);
	CPU_SET(0, &cpu_set);
	err = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set);
	ASSERT_OK(err, "set_thread_affinity");

	/* spin the loop for a while (random high number) */
	for (i = 0; i < 1000000; ++i)
		++j;
}

static void pe_subtest(struct test_bpf_cookie *skel)
{
	DECLARE_LIBBPF_OPTS(bpf_perf_event_opts, opts);
	struct bpf_link *link = NULL;
	struct perf_event_attr attr;
	int pfd = -1;

	/* create perf event */
	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.freq = 1;
	attr.sample_freq = 4000;
	pfd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (!ASSERT_GE(pfd, 0, "perf_fd"))
		goto cleanup;

	opts.bpf_cookie = 0x100000;
	link = bpf_program__attach_perf_event_opts(skel->progs.handle_pe, pfd, &opts);
	if (!ASSERT_OK_PTR(link, "link1"))
		goto cleanup;

	burn_cpu(); /* trigger BPF prog */

	ASSERT_EQ(skel->bss->pe_res, 0x100000, "pe_res1");

	/* prevent bpf_link__destroy() closing pfd itself */
	bpf_link__disconnect(link);
	/* close BPF link's FD explicitly */
	close(bpf_link__fd(link));
	/* free up memory used by struct bpf_link */
	bpf_link__destroy(link);
	link = NULL;
	kern_sync_rcu();
	skel->bss->pe_res = 0;

	opts.bpf_cookie = 0x200000;
	link = bpf_program__attach_perf_event_opts(skel->progs.handle_pe, pfd, &opts);
	if (!ASSERT_OK_PTR(link, "link2"))
		goto cleanup;

	burn_cpu(); /* trigger BPF prog */

	ASSERT_EQ(skel->bss->pe_res, 0x200000, "pe_res2");

cleanup:
	close(pfd);
	bpf_link__destroy(link);
}

void test_bpf_cookie(void)
{
	struct test_bpf_cookie *skel;

	skel = test_bpf_cookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->bss->my_tid = syscall(SYS_gettid);

	if (test__start_subtest("kprobe"))
		kprobe_subtest(skel);
	if (test__start_subtest("multi_kprobe"))
		kprobe_multi_subtest();
	if (test__start_subtest("uprobe"))
		uprobe_subtest(skel);
	if (test__start_subtest("tracepoint"))
		tp_subtest(skel);
	if (test__start_subtest("perf_event"))
		pe_subtest(skel);

	test_bpf_cookie__destroy(skel);
}
