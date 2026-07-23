// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "wq_iter.skel.h"
#include "wq_iter_fail.skel.h"

static void subtest_open_coded(struct wq_iter *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.count_workqueues),
				     &opts);
	if (!ASSERT_OK(err, "run count_workqueues"))
		return;
	/* There are always several system workqueues (events, ...). */
	ASSERT_GT(skel->bss->nr_workqueues, 0, "nr_workqueues");

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.count_worker_pools),
				     &opts);
	if (!ASSERT_OK(err, "run count_worker_pools"))
		return;
	/* At least the per-CPU normal/highpri pools exist. */
	ASSERT_GT(skel->bss->nr_worker_pools, 0, "nr_worker_pools");
	ASSERT_GT(skel->bss->nr_percpu_pools, 0, "nr_percpu_pools");
}

static void drain_iter(struct bpf_program *prog, const char *name)
{
	struct bpf_link *link;
	char buf[512];
	int iter_fd;
	ssize_t n;

	link = bpf_program__attach_iter(prog, NULL);
	if (!ASSERT_OK_PTR(link, name))
		return;
	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "iter_create"))
		goto out;
	while ((n = read(iter_fd, buf, sizeof(buf))) > 0)
		;
	ASSERT_GE(n, 0, "read iter");
	close(iter_fd);
out:
	bpf_link__destroy(link);
}

static void subtest_seq(struct wq_iter *skel)
{
	/* seq forms are backed by the same open-coded next(). */
	drain_iter(skel->progs.dump_workqueues, "attach workqueue iter");
	ASSERT_GT(skel->bss->nr_wq_seq, 0, "nr_wq_seq");

	drain_iter(skel->progs.dump_worker_pools, "attach worker_pool iter");
	ASSERT_GT(skel->bss->nr_pool_seq, 0, "nr_pool_seq");

	/*
	 * worklists are usually empty on an idle system; this drives the whole
	 * per-pool snapshot path and verifies it drains cleanly.
	 */
	drain_iter(skel->progs.dump_pending, "attach pending_work iter");
}

void test_wq_iter(void)
{
	struct wq_iter *skel;

	skel = wq_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "wq_iter__open_and_load"))
		return;

	if (test__start_subtest("open_coded"))
		subtest_open_coded(skel);
	if (test__start_subtest("seq"))
		subtest_seq(skel);

	wq_iter__destroy(skel);

	RUN_TESTS(wq_iter_fail);
}
