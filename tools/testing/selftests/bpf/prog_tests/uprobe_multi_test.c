// SPDX-License-Identifier: GPL-2.0

#include <unistd.h>
#include <pthread.h>
#include <test_progs.h>
#include "uprobe_multi.skel.h"
#include "uprobe_multi_bench.skel.h"
#include "uprobe_multi_usdt.skel.h"
#include "uprobe_multi_session.skel.h"
#include "uprobe_multi_session_cookie.skel.h"
#include "uprobe_multi_session_recursive.skel.h"
#include "uprobe_multi_session_consumers.skel.h"
#include "bpf/libbpf_internal.h"
#include "testing_helpers.h"
#include "../sdt.h"

static char test_data[] = "test_data";

noinline void uprobe_multi_func_1(void)
{
	asm volatile ("");
}

noinline void uprobe_multi_func_2(void)
{
	asm volatile ("");
}

noinline void uprobe_multi_func_3(void)
{
	asm volatile ("");
}

noinline void usdt_trigger(void)
{
	STAP_PROBE(test, pid_filter_usdt);
}

noinline void uprobe_session_recursive(int i)
{
	if (i)
		uprobe_session_recursive(i - 1);
}

struct child {
	int go[2];
	int c2p[2]; /* child -> parent channel */
	int pid;
	int tid;
	pthread_t thread;
};

static void release_child(struct child *child)
{
	int child_status;

	if (!child)
		return;
	close(child->go[1]);
	close(child->go[0]);
	if (child->thread)
		pthread_join(child->thread, NULL);
	close(child->c2p[0]);
	close(child->c2p[1]);
	if (child->pid > 0)
		waitpid(child->pid, &child_status, 0);
}

static void kick_child(struct child *child)
{
	char c = 1;

	if (child) {
		write(child->go[1], &c, 1);
		release_child(child);
	}
	fflush(NULL);
}

static struct child *spawn_child(void)
{
	static struct child child;
	int err;
	int c;

	/* pipe to notify child to execute the trigger functions */
	if (pipe(child.go))
		return NULL;

	child.pid = child.tid = fork();
	if (child.pid < 0) {
		release_child(&child);
		errno = EINVAL;
		return NULL;
	}

	/* child */
	if (child.pid == 0) {
		close(child.go[1]);

		/* wait for parent's kick */
		err = read(child.go[0], &c, 1);
		if (err != 1)
			exit(err);

		uprobe_multi_func_1();
		uprobe_multi_func_2();
		uprobe_multi_func_3();
		usdt_trigger();

		exit(errno);
	}

	return &child;
}

static void *child_thread(void *ctx)
{
	struct child *child = ctx;
	int c = 0, err;

	child->tid = syscall(SYS_gettid);

	/* let parent know we are ready */
	err = write(child->c2p[1], &c, 1);
	if (err != 1)
		pthread_exit(&err);

	/* wait for parent's kick */
	err = read(child->go[0], &c, 1);
	if (err != 1)
		pthread_exit(&err);

	uprobe_multi_func_1();
	uprobe_multi_func_2();
	uprobe_multi_func_3();
	usdt_trigger();

	err = 0;
	pthread_exit(&err);
}

static struct child *spawn_thread(void)
{
	static struct child child;
	int c, err;

	/* pipe to notify child to execute the trigger functions */
	if (pipe(child.go))
		return NULL;
	/* pipe to notify parent that child thread is ready */
	if (pipe(child.c2p)) {
		close(child.go[0]);
		close(child.go[1]);
		return NULL;
	}

	child.pid = getpid();

	err = pthread_create(&child.thread, NULL, child_thread, &child);
	if (err) {
		err = -errno;
		close(child.go[0]);
		close(child.go[1]);
		close(child.c2p[0]);
		close(child.c2p[1]);
		errno = -err;
		return NULL;
	}

	err = read(child.c2p[0], &c, 1);
	if (!ASSERT_EQ(err, 1, "child_thread_ready"))
		return NULL;

	return &child;
}

static void uprobe_multi_test_run(struct uprobe_multi *skel, struct child *child)
{
	skel->bss->uprobe_multi_func_1_addr = (__u64) uprobe_multi_func_1;
	skel->bss->uprobe_multi_func_2_addr = (__u64) uprobe_multi_func_2;
	skel->bss->uprobe_multi_func_3_addr = (__u64) uprobe_multi_func_3;

	skel->bss->user_ptr = test_data;

	/*
	 * Disable pid check in bpf program if we are pid filter test,
	 * because the probe should be executed only by child->pid
	 * passed at the probe attach.
	 */
	skel->bss->pid = child ? 0 : getpid();
	skel->bss->expect_pid = child ? child->pid : 0;

	/* trigger all probes, if we are testing child *process*, just to make
	 * sure that PID filtering doesn't let through activations from wrong
	 * PIDs; when we test child *thread*, we don't want to do this to
	 * avoid double counting number of triggering events
	 */
	if (!child || !child->thread) {
		uprobe_multi_func_1();
		uprobe_multi_func_2();
		uprobe_multi_func_3();
		usdt_trigger();
	}

	if (child)
		kick_child(child);

	/*
	 * There are 2 entry and 2 exit probe called for each uprobe_multi_func_[123]
	 * function and each slepable probe (6) increments uprobe_multi_sleep_result.
	 */
	ASSERT_EQ(skel->bss->uprobe_multi_func_1_result, 2, "uprobe_multi_func_1_result");
	ASSERT_EQ(skel->bss->uprobe_multi_func_2_result, 2, "uprobe_multi_func_2_result");
	ASSERT_EQ(skel->bss->uprobe_multi_func_3_result, 2, "uprobe_multi_func_3_result");

	ASSERT_EQ(skel->bss->uretprobe_multi_func_1_result, 2, "uretprobe_multi_func_1_result");
	ASSERT_EQ(skel->bss->uretprobe_multi_func_2_result, 2, "uretprobe_multi_func_2_result");
	ASSERT_EQ(skel->bss->uretprobe_multi_func_3_result, 2, "uretprobe_multi_func_3_result");

	ASSERT_EQ(skel->bss->uprobe_multi_sleep_result, 6, "uprobe_multi_sleep_result");

	ASSERT_FALSE(skel->bss->bad_pid_seen, "bad_pid_seen");

	if (child) {
		ASSERT_EQ(skel->bss->child_pid, child->pid, "uprobe_multi_child_pid");
		ASSERT_EQ(skel->bss->child_tid, child->tid, "uprobe_multi_child_tid");
	}
}

static void test_skel_api(void)
{
	struct uprobe_multi *skel = NULL;
	int err;

	skel = uprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi__open_and_load"))
		goto cleanup;

	err = uprobe_multi__attach(skel);
	if (!ASSERT_OK(err, "uprobe_multi__attach"))
		goto cleanup;

	uprobe_multi_test_run(skel, NULL);

cleanup:
	uprobe_multi__destroy(skel);
}

static void
__test_attach_api(const char *binary, const char *pattern, struct bpf_uprobe_multi_opts *opts,
		  struct child *child)
{
	pid_t pid = child ? child->pid : -1;
	struct uprobe_multi *skel = NULL;

	skel = uprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi__open_and_load"))
		goto cleanup;

	opts->retprobe = false;
	skel->links.uprobe = bpf_program__attach_uprobe_multi(skel->progs.uprobe, pid,
							      binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uprobe, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	opts->retprobe = true;
	skel->links.uretprobe = bpf_program__attach_uprobe_multi(skel->progs.uretprobe, pid,
								 binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uretprobe, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	opts->retprobe = false;
	skel->links.uprobe_sleep = bpf_program__attach_uprobe_multi(skel->progs.uprobe_sleep, pid,
								    binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uprobe_sleep, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	opts->retprobe = true;
	skel->links.uretprobe_sleep = bpf_program__attach_uprobe_multi(skel->progs.uretprobe_sleep,
								       pid, binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uretprobe_sleep, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	opts->retprobe = false;
	skel->links.uprobe_extra = bpf_program__attach_uprobe_multi(skel->progs.uprobe_extra, -1,
								    binary, pattern, opts);
	if (!ASSERT_OK_PTR(skel->links.uprobe_extra, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	/* Attach (uprobe-backed) USDTs */
	skel->links.usdt_pid = bpf_program__attach_usdt(skel->progs.usdt_pid, pid, binary,
							"test", "pid_filter_usdt", NULL);
	if (!ASSERT_OK_PTR(skel->links.usdt_pid, "attach_usdt_pid"))
		goto cleanup;

	skel->links.usdt_extra = bpf_program__attach_usdt(skel->progs.usdt_extra, -1, binary,
							  "test", "pid_filter_usdt", NULL);
	if (!ASSERT_OK_PTR(skel->links.usdt_extra, "attach_usdt_extra"))
		goto cleanup;

	uprobe_multi_test_run(skel, child);

	ASSERT_FALSE(skel->bss->bad_pid_seen_usdt, "bad_pid_seen_usdt");
	if (child) {
		ASSERT_EQ(skel->bss->child_pid_usdt, child->pid, "usdt_multi_child_pid");
		ASSERT_EQ(skel->bss->child_tid_usdt, child->tid, "usdt_multi_child_tid");
	}
cleanup:
	uprobe_multi__destroy(skel);
}

static void
test_attach_api(const char *binary, const char *pattern, struct bpf_uprobe_multi_opts *opts)
{
	struct child *child;

	/* no pid filter */
	__test_attach_api(binary, pattern, opts, NULL);

	/* pid filter */
	child = spawn_child();
	if (!ASSERT_OK_PTR(child, "spawn_child"))
		return;

	__test_attach_api(binary, pattern, opts, child);

	/* pid filter (thread) */
	child = spawn_thread();
	if (!ASSERT_OK_PTR(child, "spawn_thread"))
		return;

	__test_attach_api(binary, pattern, opts, child);
}

static void test_attach_api_pattern(void)
{
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);

	test_attach_api("/proc/self/exe", "uprobe_multi_func_*", &opts);
	test_attach_api("/proc/self/exe", "uprobe_multi_func_?", &opts);
}

static void test_attach_api_syms(void)
{
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);
	const char *syms[3] = {
		"uprobe_multi_func_1",
		"uprobe_multi_func_2",
		"uprobe_multi_func_3",
	};

	opts.syms = syms;
	opts.cnt = ARRAY_SIZE(syms);
	test_attach_api("/proc/self/exe", NULL, &opts);
}

static void test_attach_api_fails(void)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	const char *path = "/proc/self/exe";
	struct uprobe_multi *skel = NULL;
	int prog_fd, link_fd = -1;
	unsigned long offset = 0;

	skel = uprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi__open_and_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.uprobe_extra);

	/* abnormal cnt */
	opts.uprobe_multi.path = path;
	opts.uprobe_multi.offsets = &offset;
	opts.uprobe_multi.cnt = INT_MAX;
	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -E2BIG, "big cnt"))
		goto cleanup;

	/* cnt is 0 */
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.path = path,
		.uprobe_multi.offsets = (unsigned long *) &offset,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EINVAL, "cnt_is_zero"))
		goto cleanup;

	/* negative offset */
	offset = -1;
	opts.uprobe_multi.path = path;
	opts.uprobe_multi.offsets = (unsigned long *) &offset;
	opts.uprobe_multi.cnt = 1;

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EINVAL, "offset_is_negative"))
		goto cleanup;

	/* offsets is NULL */
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.path = path,
		.uprobe_multi.cnt = 1,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EINVAL, "offsets_is_null"))
		goto cleanup;

	/* wrong offsets pointer */
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.path = path,
		.uprobe_multi.offsets = (unsigned long *) 1,
		.uprobe_multi.cnt = 1,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EFAULT, "offsets_is_wrong"))
		goto cleanup;

	/* path is NULL */
	offset = 1;
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.offsets = (unsigned long *) &offset,
		.uprobe_multi.cnt = 1,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EINVAL, "path_is_null"))
		goto cleanup;

	/* wrong path pointer  */
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.path = (const char *) 1,
		.uprobe_multi.offsets = (unsigned long *) &offset,
		.uprobe_multi.cnt = 1,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EFAULT, "path_is_wrong"))
		goto cleanup;

	/* wrong path type */
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.path = "/",
		.uprobe_multi.offsets = (unsigned long *) &offset,
		.uprobe_multi.cnt = 1,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EBADF, "path_is_wrong_type"))
		goto cleanup;

	/* wrong cookies pointer */
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.path = path,
		.uprobe_multi.offsets = (unsigned long *) &offset,
		.uprobe_multi.cookies = (__u64 *) 1ULL,
		.uprobe_multi.cnt = 1,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EFAULT, "cookies_is_wrong"))
		goto cleanup;

	/* wrong ref_ctr_offsets pointer */
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.path = path,
		.uprobe_multi.offsets = (unsigned long *) &offset,
		.uprobe_multi.cookies = (__u64 *) &offset,
		.uprobe_multi.ref_ctr_offsets = (unsigned long *) 1,
		.uprobe_multi.cnt = 1,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EFAULT, "ref_ctr_offsets_is_wrong"))
		goto cleanup;

	/* wrong flags */
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.flags = 1 << 31,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	if (!ASSERT_EQ(link_fd, -EINVAL, "wrong_flags"))
		goto cleanup;

	/* wrong pid */
	LIBBPF_OPTS_RESET(opts,
		.uprobe_multi.path = path,
		.uprobe_multi.offsets = (unsigned long *) &offset,
		.uprobe_multi.cnt = 1,
		.uprobe_multi.pid = -2,
	);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_ERR(link_fd, "link_fd"))
		goto cleanup;
	ASSERT_EQ(link_fd, -EINVAL, "pid_is_wrong");

cleanup:
	if (link_fd >= 0)
		close(link_fd);
	uprobe_multi__destroy(skel);
}

static void __test_link_api(struct child *child)
{
	int prog_fd, link1_fd = -1, link2_fd = -1, link3_fd = -1, link4_fd = -1;
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	const char *path = "/proc/self/exe";
	struct uprobe_multi *skel = NULL;
	unsigned long *offsets = NULL;
	const char *syms[3] = {
		"uprobe_multi_func_1",
		"uprobe_multi_func_2",
		"uprobe_multi_func_3",
	};
	int link_extra_fd = -1;
	int err;

	err = elf_resolve_syms_offsets(path, 3, syms, (unsigned long **) &offsets, STT_FUNC);
	if (!ASSERT_OK(err, "elf_resolve_syms_offsets"))
		return;

	opts.uprobe_multi.path = path;
	opts.uprobe_multi.offsets = offsets;
	opts.uprobe_multi.cnt = ARRAY_SIZE(syms);
	opts.uprobe_multi.pid = child ? child->pid : 0;

	skel = uprobe_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi__open_and_load"))
		goto cleanup;

	opts.kprobe_multi.flags = 0;
	prog_fd = bpf_program__fd(skel->progs.uprobe);
	link1_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_GE(link1_fd, 0, "link1_fd"))
		goto cleanup;

	opts.kprobe_multi.flags = BPF_F_UPROBE_MULTI_RETURN;
	prog_fd = bpf_program__fd(skel->progs.uretprobe);
	link2_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_GE(link2_fd, 0, "link2_fd"))
		goto cleanup;

	opts.kprobe_multi.flags = 0;
	prog_fd = bpf_program__fd(skel->progs.uprobe_sleep);
	link3_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_GE(link3_fd, 0, "link3_fd"))
		goto cleanup;

	opts.kprobe_multi.flags = BPF_F_UPROBE_MULTI_RETURN;
	prog_fd = bpf_program__fd(skel->progs.uretprobe_sleep);
	link4_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_GE(link4_fd, 0, "link4_fd"))
		goto cleanup;

	opts.kprobe_multi.flags = 0;
	opts.uprobe_multi.pid = 0;
	prog_fd = bpf_program__fd(skel->progs.uprobe_extra);
	link_extra_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_UPROBE_MULTI, &opts);
	if (!ASSERT_GE(link_extra_fd, 0, "link_extra_fd"))
		goto cleanup;

	uprobe_multi_test_run(skel, child);

cleanup:
	if (link1_fd >= 0)
		close(link1_fd);
	if (link2_fd >= 0)
		close(link2_fd);
	if (link3_fd >= 0)
		close(link3_fd);
	if (link4_fd >= 0)
		close(link4_fd);
	if (link_extra_fd >= 0)
		close(link_extra_fd);

	uprobe_multi__destroy(skel);
	free(offsets);
}

static void test_link_api(void)
{
	struct child *child;

	/* no pid filter */
	__test_link_api(NULL);

	/* pid filter */
	child = spawn_child();
	if (!ASSERT_OK_PTR(child, "spawn_child"))
		return;

	__test_link_api(child);

	/* pid filter (thread) */
	child = spawn_thread();
	if (!ASSERT_OK_PTR(child, "spawn_thread"))
		return;

	__test_link_api(child);
}

static void test_session_skel_api(void)
{
	struct uprobe_multi_session *skel = NULL;
	LIBBPF_OPTS(bpf_kprobe_multi_opts, opts);
	struct bpf_link *link = NULL;
	int err;

	skel = uprobe_multi_session__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		goto cleanup;

	skel->bss->pid = getpid();

	err = uprobe_multi_session__attach(skel);
	if (!ASSERT_OK(err, " uprobe_multi_session__attach"))
		goto cleanup;

	/* trigger all probes */
	skel->bss->uprobe_multi_func_1_addr = (__u64) uprobe_multi_func_1;
	skel->bss->uprobe_multi_func_2_addr = (__u64) uprobe_multi_func_2;
	skel->bss->uprobe_multi_func_3_addr = (__u64) uprobe_multi_func_3;

	uprobe_multi_func_1();
	uprobe_multi_func_2();
	uprobe_multi_func_3();

	/*
	 * We expect 2 for uprobe_multi_func_2 because it runs both entry/return probe,
	 * uprobe_multi_func_[13] run just the entry probe.
	 */
	ASSERT_EQ(skel->bss->uprobe_session_result[0], 1, "uprobe_multi_func_1_result");
	ASSERT_EQ(skel->bss->uprobe_session_result[1], 2, "uprobe_multi_func_2_result");
	ASSERT_EQ(skel->bss->uprobe_session_result[2], 1, "uprobe_multi_func_3_result");

cleanup:
	bpf_link__destroy(link);
	uprobe_multi_session__destroy(skel);
}

static void test_session_cookie_skel_api(void)
{
	struct uprobe_multi_session_cookie *skel = NULL;
	int err;

	skel = uprobe_multi_session_cookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "fentry_raw_skel_load"))
		goto cleanup;

	skel->bss->pid = getpid();

	err = uprobe_multi_session_cookie__attach(skel);
	if (!ASSERT_OK(err, " kprobe_multi_session__attach"))
		goto cleanup;

	/* trigger all probes */
	uprobe_multi_func_1();
	uprobe_multi_func_2();
	uprobe_multi_func_3();

	ASSERT_EQ(skel->bss->test_uprobe_1_result, 1, "test_uprobe_1_result");
	ASSERT_EQ(skel->bss->test_uprobe_2_result, 2, "test_uprobe_2_result");
	ASSERT_EQ(skel->bss->test_uprobe_3_result, 3, "test_uprobe_3_result");

cleanup:
	uprobe_multi_session_cookie__destroy(skel);
}

static void test_session_recursive_skel_api(void)
{
	struct uprobe_multi_session_recursive *skel = NULL;
	int i, err;

	skel = uprobe_multi_session_recursive__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi_session_recursive__open_and_load"))
		goto cleanup;

	skel->bss->pid = getpid();

	err = uprobe_multi_session_recursive__attach(skel);
	if (!ASSERT_OK(err, "uprobe_multi_session_recursive__attach"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(skel->bss->test_uprobe_cookie_entry); i++)
		skel->bss->test_uprobe_cookie_entry[i] = i + 1;

	uprobe_session_recursive(5);

	/*
	 *                                         entry uprobe:
	 * uprobe_session_recursive(5) {             *cookie = 1, return 0
	 *   uprobe_session_recursive(4) {           *cookie = 2, return 1
	 *     uprobe_session_recursive(3) {         *cookie = 3, return 0
	 *       uprobe_session_recursive(2) {       *cookie = 4, return 1
	 *         uprobe_session_recursive(1) {     *cookie = 5, return 0
	 *           uprobe_session_recursive(0) {   *cookie = 6, return 1
	 *                                          return uprobe:
	 *           } i = 0                          not executed
	 *         } i = 1                            test_uprobe_cookie_return[0] = 5
	 *       } i = 2                              not executed
	 *     } i = 3                                test_uprobe_cookie_return[1] = 3
	 *   } i = 4                                  not executed
	 * } i = 5                                    test_uprobe_cookie_return[2] = 1
	 */

	ASSERT_EQ(skel->bss->idx_entry, 6, "idx_entry");
	ASSERT_EQ(skel->bss->idx_return, 3, "idx_return");

	ASSERT_EQ(skel->bss->test_uprobe_cookie_return[0], 5, "test_uprobe_cookie_return[0]");
	ASSERT_EQ(skel->bss->test_uprobe_cookie_return[1], 3, "test_uprobe_cookie_return[1]");
	ASSERT_EQ(skel->bss->test_uprobe_cookie_return[2], 1, "test_uprobe_cookie_return[2]");

cleanup:
	uprobe_multi_session_recursive__destroy(skel);
}

static int uprobe_attach(struct uprobe_multi_session_consumers *skel, int bit)
{
	struct bpf_program **prog = &skel->progs.uprobe_0 + bit;
	struct bpf_link **link = &skel->links.uprobe_0 + bit;
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);

	/*
	 * bit: 0,1 uprobe session
	 * bit: 2,3 uprobe entry
	 * bit: 4,5 uprobe return
	 */
	opts.session = bit < 2;
	opts.retprobe = bit == 4 || bit == 5;

	*link = bpf_program__attach_uprobe_multi(*prog, 0, "/proc/self/exe",
						 "uprobe_session_consumer_test",
						 &opts);
	if (!ASSERT_OK_PTR(*link, "bpf_program__attach_uprobe_multi"))
		return -1;
	return 0;
}

static void uprobe_detach(struct uprobe_multi_session_consumers *skel, int bit)
{
	struct bpf_link **link = &skel->links.uprobe_0 + bit;

	bpf_link__destroy(*link);
	*link = NULL;
}

static bool test_bit(int bit, unsigned long val)
{
	return val & (1 << bit);
}

noinline int
uprobe_session_consumer_test(struct uprobe_multi_session_consumers *skel,
			     unsigned long before, unsigned long after)
{
	int bit;

	/* detach uprobe for each unset bit in 'before' state ... */
	for (bit = 0; bit < 6; bit++) {
		if (test_bit(bit, before) && !test_bit(bit, after))
			uprobe_detach(skel, bit);
	}

	/* ... and attach all new bits in 'after' state */
	for (bit = 0; bit < 6; bit++) {
		if (!test_bit(bit, before) && test_bit(bit, after)) {
			if (!ASSERT_OK(uprobe_attach(skel, bit), "uprobe_attach_after"))
				return -1;
		}
	}
	return 0;
}

static void session_consumer_test(struct uprobe_multi_session_consumers *skel,
				  unsigned long before, unsigned long after)
{
	int err, bit;

	/* 'before' is each, we attach uprobe for every set bit */
	for (bit = 0; bit < 6; bit++) {
		if (test_bit(bit, before)) {
			if (!ASSERT_OK(uprobe_attach(skel, bit), "uprobe_attach_before"))
				goto cleanup;
		}
	}

	err = uprobe_session_consumer_test(skel, before, after);
	if (!ASSERT_EQ(err, 0, "uprobe_session_consumer_test"))
		goto cleanup;

	for (bit = 0; bit < 6; bit++) {
		const char *fmt = "BUG";
		__u64 val = 0;

		if (bit == 0) {
			/*
			 * session with return
			 *  +1 if defined in 'before'
			 *  +1 if defined in 'after'
			 */
			if (test_bit(bit, before)) {
				val++;
				if (test_bit(bit, after))
					val++;
			}
			fmt = "bit 0  : session with return";
		} else if (bit == 1) {
			/*
			 * session without return
			 *   +1 if defined in 'before'
			 */
			if (test_bit(bit, before))
				val++;
			fmt = "bit 1  : session with NO return";
		} else if (bit < 4) {
			/*
			 * uprobe entry
			 *   +1 if define in 'before'
			 */
			if (test_bit(bit, before))
				val++;
			fmt = "bit 3/4: uprobe";
		} else {
			/* uprobe return is tricky ;-)
			 *
			 * to trigger uretprobe consumer, the uretprobe needs to be installed,
			 * which means one of the 'return' uprobes was alive when probe was hit:
			 *
			 *   bits: 0 (session with return) 4/5 uprobe return in 'installed' mask
			 *
			 * in addition if 'after' state removes everything that was installed in
			 * 'before' state, then uprobe kernel object goes away and return uprobe
			 * is not installed and we won't hit it even if it's in 'after' state.
			 */
			unsigned long installed = before & 0b110001; // is uretprobe installed
			unsigned long exists    = before & after;    // did uprobe go away

			if (installed && exists && test_bit(bit, after))
				val++;
			fmt = "bit 5/6: uretprobe";
		}

		ASSERT_EQ(skel->bss->uprobe_result[bit], val, fmt);
		skel->bss->uprobe_result[bit] = 0;
	}

cleanup:
	for (bit = 0; bit < 6; bit++) {
		struct bpf_link **link = &skel->links.uprobe_0 + bit;

		if (*link)
			uprobe_detach(skel, bit);
	}
}

static void test_session_consumers(void)
{
	struct uprobe_multi_session_consumers *skel;
	int before, after;

	skel = uprobe_multi_session_consumers__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi_session_consumers__open_and_load"))
		return;

	/*
	 * The idea of this test is to try all possible combinations of
	 * uprobes consumers attached on single function.
	 *
	 *  - 1 uprobe session with return handler called
	 *  - 1 uprobe session without return handler called
	 *  - 2 uprobe entry consumer
	 *  - 2 uprobe exit consumers
	 *
	 * The test uses 6 uprobes attached on single function, but that
	 * translates into single uprobe with 6 consumers in kernel.
	 *
	 * The before/after values present the state of attached consumers
	 * before and after the probed function:
	 *
	 *  bit 0   : uprobe session with return
	 *  bit 1   : uprobe session with no return
	 *  bit 2,3 : uprobe entry
	 *  bit 4,5 : uprobe return
	 *
	 * For example for:
	 *
	 *   before = 0b10101
	 *   after  = 0b00110
	 *
	 * it means that before we call 'uprobe_session_consumer_test' we
	 * attach uprobes defined in 'before' value:
	 *
	 *   - bit 0: uprobe session with return
	 *   - bit 2: uprobe entry
	 *   - bit 4: uprobe return
	 *
	 * uprobe_session_consumer_test is called and inside it we attach
	 * and detach * uprobes based on 'after' value:
	 *
	 *   - bit 0: uprobe session with return is detached
	 *   - bit 1: uprobe session without return is attached
	 *   - bit 2: stays untouched
	 *   - bit 4: uprobe return is detached
	 *
	 * uprobe_session_consumer_test returs and we check counters values
	 * increased by bpf programs on each uprobe to match the expected
	 * count based on before/after bits.
	 */
	for (before = 0; before < 64; before++) {
		for (after = 0; after < 64; after++)
			session_consumer_test(skel, before, after);
	}

	uprobe_multi_session_consumers__destroy(skel);
}

static void test_bench_attach_uprobe(void)
{
	long attach_start_ns = 0, attach_end_ns = 0;
	struct uprobe_multi_bench *skel = NULL;
	long detach_start_ns, detach_end_ns;
	double attach_delta, detach_delta;
	int err;

	skel = uprobe_multi_bench__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi_bench__open_and_load"))
		goto cleanup;

	attach_start_ns = get_time_ns();

	err = uprobe_multi_bench__attach(skel);
	if (!ASSERT_OK(err, "uprobe_multi_bench__attach"))
		goto cleanup;

	attach_end_ns = get_time_ns();

	system("./uprobe_multi bench");

	ASSERT_EQ(skel->bss->count, 50000, "uprobes_count");

cleanup:
	detach_start_ns = get_time_ns();
	uprobe_multi_bench__destroy(skel);
	detach_end_ns = get_time_ns();

	attach_delta = (attach_end_ns - attach_start_ns) / 1000000000.0;
	detach_delta = (detach_end_ns - detach_start_ns) / 1000000000.0;

	printf("%s: attached in %7.3lfs\n", __func__, attach_delta);
	printf("%s: detached in %7.3lfs\n", __func__, detach_delta);
}

static void test_bench_attach_usdt(void)
{
	long attach_start_ns = 0, attach_end_ns = 0;
	struct uprobe_multi_usdt *skel = NULL;
	long detach_start_ns, detach_end_ns;
	double attach_delta, detach_delta;

	skel = uprobe_multi_usdt__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_multi__open"))
		goto cleanup;

	attach_start_ns = get_time_ns();

	skel->links.usdt0 = bpf_program__attach_usdt(skel->progs.usdt0, -1, "./uprobe_multi",
						     "test", "usdt", NULL);
	if (!ASSERT_OK_PTR(skel->links.usdt0, "bpf_program__attach_usdt"))
		goto cleanup;

	attach_end_ns = get_time_ns();

	system("./uprobe_multi usdt");

	ASSERT_EQ(skel->bss->count, 50000, "usdt_count");

cleanup:
	detach_start_ns = get_time_ns();
	uprobe_multi_usdt__destroy(skel);
	detach_end_ns = get_time_ns();

	attach_delta = (attach_end_ns - attach_start_ns) / 1000000000.0;
	detach_delta = (detach_end_ns - detach_start_ns) / 1000000000.0;

	printf("%s: attached in %7.3lfs\n", __func__, attach_delta);
	printf("%s: detached in %7.3lfs\n", __func__, detach_delta);
}

void test_uprobe_multi_test(void)
{
	if (test__start_subtest("skel_api"))
		test_skel_api();
	if (test__start_subtest("attach_api_pattern"))
		test_attach_api_pattern();
	if (test__start_subtest("attach_api_syms"))
		test_attach_api_syms();
	if (test__start_subtest("link_api"))
		test_link_api();
	if (test__start_subtest("bench_uprobe"))
		test_bench_attach_uprobe();
	if (test__start_subtest("bench_usdt"))
		test_bench_attach_usdt();
	if (test__start_subtest("attach_api_fails"))
		test_attach_api_fails();
	if (test__start_subtest("session"))
		test_session_skel_api();
	if (test__start_subtest("session_cookie"))
		test_session_cookie_skel_api();
	if (test__start_subtest("session_cookie_recursive"))
		test_session_recursive_skel_api();
	if (test__start_subtest("session/consumers"))
		test_session_consumers();
}
