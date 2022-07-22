// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Google */

#include <test_progs.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include "cgroup_iter.skel.h"
#include "cgroup_helpers.h"

#define ROOT		0
#define PARENT		1
#define CHILD1		2
#define CHILD2		3
#define NUM_CGROUPS	4

#define PROLOGUE	"prologue\n"
#define EPILOGUE	"epilogue\n"

#define format_expected_output1(cg_id1) \
	snprintf(expected_output, sizeof(expected_output), \
		 PROLOGUE "%8llu\n" EPILOGUE, (cg_id1))

#define format_expected_output2(cg_id1, cg_id2) \
	snprintf(expected_output, sizeof(expected_output), \
		 PROLOGUE "%8llu\n%8llu\n" EPILOGUE, \
		 (cg_id1), (cg_id2))

#define format_expected_output3(cg_id1, cg_id2, cg_id3) \
	snprintf(expected_output, sizeof(expected_output), \
		 PROLOGUE "%8llu\n%8llu\n%8llu\n" EPILOGUE, \
		 (cg_id1), (cg_id2), (cg_id3))

const char *cg_path[] = {
	"/", "/parent", "/parent/child1", "/parent/child2"
};

static int cg_fd[] = {-1, -1, -1, -1};
static unsigned long long cg_id[] = {0, 0, 0, 0};
static char expected_output[64];

int setup_cgroups(void)
{
	int fd, i = 0;

	for (i = 0; i < NUM_CGROUPS; i++) {
		fd = create_and_get_cgroup(cg_path[i]);
		if (fd < 0)
			return fd;

		cg_fd[i] = fd;
		cg_id[i] = get_cgroup_id(cg_path[i]);
	}
	return 0;
}

void cleanup_cgroups(void)
{
	int i;

	for (i = 0; i < NUM_CGROUPS; i++)
		close(cg_fd[i]);
}

static void read_from_cgroup_iter(struct bpf_program *prog, int cgroup_fd,
				  int order, const char *testname)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	struct bpf_link *link;
	int len, iter_fd;
	static char buf[64];

	memset(&linfo, 0, sizeof(linfo));
	linfo.cgroup.cgroup_fd = cgroup_fd;
	linfo.cgroup.traversal_order = order;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(prog, &opts);
	if (!ASSERT_OK_PTR(link, "attach_iter"))
		return;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (iter_fd < 0)
		goto free_link;

	memset(buf, 0, sizeof(buf));
	while ((len = read(iter_fd, buf, sizeof(buf))) > 0)
		;

	ASSERT_STREQ(buf, expected_output, testname);

	close(iter_fd);
free_link:
	bpf_link__destroy(link);
}

/* Invalid cgroup. */
static void test_invalid_cgroup(struct cgroup_iter *skel)
{

	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	struct bpf_link *link;

	memset(&linfo, 0, sizeof(linfo));
	linfo.cgroup.cgroup_fd = (__u32)-1;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);

	link = bpf_program__attach_iter(skel->progs.cgroup_id_printer, &opts);
	if (!ASSERT_ERR_PTR(link, "attach_iter"))
		bpf_link__destroy(link);
}

/* Preorder walk prints parent and child in order. */
static void test_walk_preorder(struct cgroup_iter *skel)
{
	format_expected_output3(cg_id[PARENT], cg_id[CHILD1], cg_id[CHILD2]);

	read_from_cgroup_iter(skel->progs.cgroup_id_printer, cg_fd[PARENT],
			      BPF_ITER_CGROUP_PRE, "preorder");
}

/* Postorder walk prints child and parent in order. */
static void test_walk_postorder(struct cgroup_iter *skel)
{
	format_expected_output3(cg_id[CHILD1], cg_id[CHILD2], cg_id[PARENT]);

	read_from_cgroup_iter(skel->progs.cgroup_id_printer, cg_fd[PARENT],
			      BPF_ITER_CGROUP_POST, "postorder");
}

/* Walking parents prints parent and then root. */
static void test_walk_parent_up(struct cgroup_iter *skel)
{
	/* terminate the walk when ROOT is met. */
	skel->bss->terminal_cgroup = cg_id[ROOT];

	format_expected_output2(cg_id[PARENT], cg_id[ROOT]);

	read_from_cgroup_iter(skel->progs.cgroup_id_printer, cg_fd[PARENT],
			      BPF_ITER_CGROUP_PARENT_UP, "parent_up");

	skel->bss->terminal_cgroup = 0;
}

/* Early termination prints parent only. */
static void test_early_termination(struct cgroup_iter *skel)
{
	/* terminate the walk after the first element is processed. */
	skel->bss->terminate_early = 1;

	format_expected_output1(cg_id[PARENT]);

	read_from_cgroup_iter(skel->progs.cgroup_id_printer, cg_fd[PARENT],
			      BPF_ITER_CGROUP_PRE, "early_termination");

	skel->bss->terminate_early = 0;
}

void test_cgroup_iter(void)
{
	struct cgroup_iter *skel = NULL;

	if (setup_cgroup_environment() < 0)
		return;

	if (setup_cgroups() < 0)
		goto out;

	skel = cgroup_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "cgroup_iter__open_and_load"))
		goto out;

	if (test__start_subtest("cgroup_iter__invalid_cgroup"))
		test_invalid_cgroup(skel);
	if (test__start_subtest("cgroup_iter__preorder"))
		test_walk_preorder(skel);
	if (test__start_subtest("cgroup_iter__postorder"))
		test_walk_postorder(skel);
	if (test__start_subtest("cgroup_iter__parent_up_walk"))
		test_walk_parent_up(skel);
	if (test__start_subtest("cgroup_iter__early_termination"))
		test_early_termination(skel);
out:
	cgroup_iter__destroy(skel);
	cleanup_cgroups();
	cleanup_cgroup_environment();
}
