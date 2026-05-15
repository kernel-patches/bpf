// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Google LLC */
#include <linux/bpf.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <test_progs.h>
#include "test_tc_link.skel.h"
#include "tc_helpers.h"

#define OLD_QUERY_SIZE		offsetofend(union bpf_attr, query.prog_cnt)
#define FULL_QUERY_SIZE		offsetofend(union bpf_attr, query.revision)
#define SHORT_QUERY_SIZE	offsetofend(union bpf_attr, query.attach_type)

static void test_query_size_boundaries(void)
{
	LIBBPF_OPTS(bpf_prog_attach_opts, opta);
	LIBBPF_OPTS(bpf_prog_detach_opts, optd);
	struct test_tc_link *skel;
	union bpf_attr attr;
	int fd, err;

	skel = test_tc_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_load"))
		return;

	fd = bpf_program__fd(skel->progs.tc1);

	err = bpf_prog_attach_opts(fd, loopback, BPF_TCX_INGRESS, &opta);
	if (!ASSERT_OK(err, "prog_attach"))
		goto cleanup;

	/* 1. Old size: revision must not be written */
	memset(&attr, 0, sizeof(attr));
	attr.query.target_ifindex = loopback;
	attr.query.attach_type = BPF_TCX_INGRESS;

	err = syscall(__NR_bpf, BPF_PROG_QUERY, &attr, OLD_QUERY_SIZE);
	if (!ASSERT_OK(err, "query_old_size"))
		goto detach;

	ASSERT_EQ(attr.query.prog_cnt, 1, "prog_cnt_written");
	ASSERT_EQ(attr.query.revision, 0, "revision_not_written");

	/* 2. Full size: revision must be written normally */
	memset(&attr, 0, sizeof(attr));
	attr.query.target_ifindex = loopback;
	attr.query.attach_type = BPF_TCX_INGRESS;

	err = syscall(__NR_bpf, BPF_PROG_QUERY, &attr, FULL_QUERY_SIZE);
	if (!ASSERT_OK(err, "query_full_size"))
		goto detach;

	ASSERT_EQ(attr.query.prog_cnt, 1, "prog_cnt_written");
	ASSERT_GT(attr.query.revision, 0, "revision_written");

detach:
	err = bpf_prog_detach_opts(fd, loopback, BPF_TCX_INGRESS, &optd);
	ASSERT_OK(err, "prog_detach");
cleanup:
	test_tc_link__destroy(skel);
}

static void test_query_mandatory_too_short_einval(void)
{
	union bpf_attr attr;
	int err;

	/* Below minimum size: must return -EINVAL */
	memset(&attr, 0, sizeof(attr));
	attr.query.target_ifindex = loopback;
	attr.query.attach_type = BPF_TCX_INGRESS;

	err = syscall(__NR_bpf, BPF_PROG_QUERY, &attr, SHORT_QUERY_SIZE);
	ASSERT_EQ(err, -1, "query_too_short_fails");
	ASSERT_EQ(errno, EINVAL, "query_too_short_einval");
}

void test_bpf_attr_size(void)
{
	if (test__start_subtest("query_size_boundaries"))
		test_query_size_boundaries();
	if (test__start_subtest("query_mandatory_too_short_einval"))
		test_query_mandatory_too_short_einval();
}
