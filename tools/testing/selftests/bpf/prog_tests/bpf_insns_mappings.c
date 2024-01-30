// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Isovalent */

#include <test_progs.h>
#include "bpf_insns_mappings.skel.h"

#define MAX_INSNS 4096

static struct bpf_prog_info *prog_info_and_mappings(int prog_fd)
{
	static __thread struct bpf_prog_info prog_info;
	static __thread char xlated_insns[MAX_INSNS];
	static __thread __u32 orig_idx[MAX_INSNS];
	__u32 prog_info_len;
	__u32 orig_idx_len;
	int err;

	prog_info_len = sizeof(prog_info);

	memset(&prog_info, 0, sizeof(prog_info));
	err = bpf_prog_get_info_by_fd(prog_fd, &prog_info, &prog_info_len);
	if (!ASSERT_GE(err, 0, "bpf_prog_get_info_by_fd"))
		return NULL;

	orig_idx_len = prog_info.orig_idx_len;
	memset(&prog_info, 0, sizeof(prog_info));

	if (orig_idx_len) {
		prog_info.orig_idx_len = orig_idx_len;
		prog_info.orig_idx = ptr_to_u64(orig_idx);
	}

	prog_info.xlated_prog_insns = ptr_to_u64(xlated_insns);
	prog_info.xlated_prog_len = sizeof(xlated_insns);

	err = bpf_prog_get_info_by_fd(prog_fd, &prog_info, &prog_info_len);
	if (!ASSERT_GE(err, 0, "bpf_prog_get_info_by_fd"))
		return NULL;

	return &prog_info;
}

static int beef_search_original(const struct bpf_insn *insns, int n_insns, int *idx, int n_max)
{
	int i, n_found = 0;

	for (i = 0; i < n_insns; i++) {
		if (insns[i].imm == 0xbeef) {
			if (!ASSERT_LT(n_found, n_max, "beef"))
				return -1;
			idx[n_found++] = i;
		}
	}

	return n_found;
}

static int beef_search_xlated(struct bpf_prog_info *info, int *idx, int len)
{
	struct bpf_insn *insns = u64_to_ptr(info->xlated_prog_insns);
	int tot = info->xlated_prog_len / 8;
	int i, n = 0;

	for (i = 0; i < tot; i++) {
		if (insns[i].imm == 0xbeef) {
			if (!ASSERT_LT(n, len, "beef"))
				return -1;
			idx[n++] = ((__u32 *)u64_to_ptr(info->orig_idx))[i];
		}
	}

	return n;
}

static void beef_check(const struct bpf_program *prog, int n_expected)
{
	struct bpf_prog_info *prog_info;
	int idx_expected[MAX_INSNS];
	int idx[MAX_INSNS];
	int prog_fd;
	int n, i;

	/*
	 * Find all beef instructions in the original program
	 */

	n = beef_search_original(bpf_program__insns(prog),
				 bpf_program__insn_cnt(prog),
				 idx_expected, MAX_INSNS);
	if (!ASSERT_EQ(n, n_expected, "search original insns"))
		return;

	/*
	 * Now find all the beef instructions in the xlated program and extract
	 * corresponding orig_idx mappings
	 */
	prog_fd = bpf_program__fd(prog);
	if (!ASSERT_GE(prog_fd, 0, "bpf_program__fd"))
		return;

	prog_info = prog_info_and_mappings(prog_fd);
	if (!ASSERT_OK_PTR(prog_info, "prog_info_and_mappings"))
		return;

	if (!ASSERT_EQ(beef_search_xlated(prog_info, idx, n), n, "total # of beef"))
		return;

	/*
	 * Check that the orig_idx points to the correct original indexes
	 */
	for (i = 0; i < n; i++)
		ASSERT_EQ(idx[i], idx_expected[i], "beef index");
}

static void check_prog(const struct bpf_program *prog, int n_expected)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	beef_check(prog, n_expected);

	bpf_link__destroy(link);
}

void test_bpf_insns_mappings(void)
{
	struct bpf_insns_mappings *skel;

	skel = bpf_insns_mappings__open();
	if (!ASSERT_OK_PTR(skel, "bpf_insns_mappings__open"))
		return;

	if (!ASSERT_OK(bpf_insns_mappings__load(skel),
		  "bpf_insns_mappings__load"))
		return;

	if (test__start_subtest("check_trivial_prog"))
		check_prog(skel->progs.check_trivial_prog, 3);

	if (test__start_subtest("check_simple_prog"))
		check_prog(skel->progs.check_simple_prog, 3);

	if (test__start_subtest("check_bpf_to_bpf"))
		check_prog(skel->progs.check_bpf_to_bpf, 6);

	if (test__start_subtest("check_prog_dead_code"))
		check_prog(skel->progs.check_prog_dead_code, 13);

	if (test__start_subtest("check_prog_dead_code_bpf_to_bpf"))
		check_prog(skel->progs.check_prog_dead_code_bpf_to_bpf, 26);

	bpf_insns_mappings__destroy(skel);
}
