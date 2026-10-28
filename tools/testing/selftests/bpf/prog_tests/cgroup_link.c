// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "testing_helpers.h"
#include "test_cgroup_link.skel.h"

static __u32 duration = 0;
#define PING_CMD	"ping -q -c1 -w1 127.0.0.1 > /dev/null"

static struct test_cgroup_link *skel = NULL;

int ping_and_check(int exp_calls, int exp_alt_calls)
{
	skel->bss->calls = 0;
	skel->bss->alt_calls = 0;
	CHECK_FAIL(system(PING_CMD));
	if (CHECK(skel->bss->calls != exp_calls, "call_cnt",
		  "exp %d, got %d\n", exp_calls, skel->bss->calls))
		return -EINVAL;
	if (CHECK(skel->bss->alt_calls != exp_alt_calls, "alt_call_cnt",
		  "exp %d, got %d\n", exp_alt_calls, skel->bss->alt_calls))
		return -EINVAL;
	return 0;
}

void serial_test_cgroup_link(void)
{
	struct {
		const char *path;
		int fd;
	} cgs[] = {
		{ "/cg1" },
		{ "/cg1/cg2" },
		{ "/cg1/cg2/cg3" },
		{ "/cg1/cg2/cg3/cg4" },
	};
	int last_cg = ARRAY_SIZE(cgs) - 1, cg_nr = ARRAY_SIZE(cgs);
	DECLARE_LIBBPF_OPTS(bpf_link_update_opts, link_upd_opts);
	struct bpf_link *links[ARRAY_SIZE(cgs)] = {}, *tmp_link;
	__u32 prog_ids[ARRAY_SIZE(cgs)], prog_cnt = 0, attach_flags, prog_id;
	struct bpf_link_info info;
	int i = 0, err, prog_fd;
	bool detach_legacy = false;

	skel = test_cgroup_link__open_and_load();
	if (CHECK(!skel, "skel_open_load", "failed to open/load skeleton\n"))
		return;
	prog_fd = bpf_program__fd(skel->progs.egress);

	err = setup_cgroup_environment();
	if (CHECK(err, "cg_init", "failed: %d\n", err))
		goto cleanup;

	for (i = 0; i < cg_nr; i++) {
		cgs[i].fd = create_and_get_cgroup(cgs[i].path);
		if (!ASSERT_GE(cgs[i].fd, 0, "cg_create"))
			goto cleanup;
	}

	err = join_cgroup(cgs[last_cg].path);
	if (CHECK(err, "cg_join", "fail: %d\n", err))
		goto cleanup;

	for (i = 0; i < cg_nr; i++) {
		links[i] = bpf_program__attach_cgroup(skel->progs.egress,
						      cgs[i].fd);
		if (!ASSERT_OK_PTR(links[i], "cg_attach"))
			goto cleanup;
	}

	ping_and_check(cg_nr, 0);

	/* query the number of attached progs and attach flags in root cg */
	err = bpf_prog_query(cgs[0].fd, BPF_CGROUP_INET_EGRESS,
			     0, &attach_flags, NULL, &prog_cnt);
	CHECK_FAIL(err);
	CHECK_FAIL(attach_flags != BPF_F_ALLOW_MULTI);
	if (CHECK(prog_cnt != 1, "effect_cnt", "exp %d, got %d\n", 1, prog_cnt))
		goto cleanup;

	/* query the number of effective progs in last cg */
	err = bpf_prog_query(cgs[last_cg].fd, BPF_CGROUP_INET_EGRESS,
			     BPF_F_QUERY_EFFECTIVE, NULL, NULL,
			     &prog_cnt);
	CHECK_FAIL(err);
	if (CHECK(prog_cnt != cg_nr, "effect_cnt", "exp %d, got %d\n",
		  cg_nr, prog_cnt))
		goto cleanup;

	/* query the effective prog IDs in last cg */
	err = bpf_prog_query(cgs[last_cg].fd, BPF_CGROUP_INET_EGRESS,
			     BPF_F_QUERY_EFFECTIVE, NULL, prog_ids,
			     &prog_cnt);
	CHECK_FAIL(err);
	if (CHECK(prog_cnt != cg_nr, "effect_cnt", "exp %d, got %d\n",
		  cg_nr, prog_cnt))
		goto cleanup;
	for (i = 1; i < prog_cnt; i++) {
		CHECK(prog_ids[i - 1] != prog_ids[i], "prog_id_check",
		      "idx %d, prev id %d, cur id %d\n",
		      i, prog_ids[i - 1], prog_ids[i]);
	}

	/* detach bottom program and ping again */
	bpf_link__destroy(links[last_cg]);
	links[last_cg] = NULL;

	ping_and_check(cg_nr - 1, 0);

	/* mix in with non link-based multi-attachments */
	err = bpf_prog_attach(prog_fd, cgs[last_cg].fd,
			      BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI);
	if (CHECK(err, "cg_attach_legacy", "errno=%d\n", errno))
		goto cleanup;
	detach_legacy = true;

	links[last_cg] = bpf_program__attach_cgroup(skel->progs.egress,
						    cgs[last_cg].fd);
	if (!ASSERT_OK_PTR(links[last_cg], "cg_attach"))
		goto cleanup;

	ping_and_check(cg_nr + 1, 0);

	/* detach link */
	bpf_link__destroy(links[last_cg]);
	links[last_cg] = NULL;

	/* detach legacy */
	err = bpf_prog_detach2(prog_fd, cgs[last_cg].fd, BPF_CGROUP_INET_EGRESS);
	if (CHECK(err, "cg_detach_legacy", "errno=%d\n", errno))
		goto cleanup;
	detach_legacy = false;

	/* attach legacy exclusive prog attachment */
	err = bpf_prog_attach(prog_fd, cgs[last_cg].fd,
			      BPF_CGROUP_INET_EGRESS, 0);
	if (CHECK(err, "cg_attach_exclusive", "errno=%d\n", errno))
		goto cleanup;
	detach_legacy = true;

	/* attempt to mix in with multi-attach bpf_link */
	tmp_link = bpf_program__attach_cgroup(skel->progs.egress,
					      cgs[last_cg].fd);
	if (!ASSERT_ERR_PTR(tmp_link, "cg_attach_fail")) {
		bpf_link__destroy(tmp_link);
		goto cleanup;
	}

	ping_and_check(cg_nr, 0);

	/* detach */
	err = bpf_prog_detach2(prog_fd, cgs[last_cg].fd, BPF_CGROUP_INET_EGRESS);
	if (CHECK(err, "cg_detach_legacy", "errno=%d\n", errno))
		goto cleanup;
	detach_legacy = false;

	ping_and_check(cg_nr - 1, 0);

	/* attach back link-based one */
	links[last_cg] = bpf_program__attach_cgroup(skel->progs.egress,
						    cgs[last_cg].fd);
	if (!ASSERT_OK_PTR(links[last_cg], "cg_attach"))
		goto cleanup;

	ping_and_check(cg_nr, 0);

	/* check legacy exclusive prog can't be attached */
	err = bpf_prog_attach(prog_fd, cgs[last_cg].fd,
			      BPF_CGROUP_INET_EGRESS, 0);
	if (CHECK(!err, "cg_attach_exclusive", "unexpected success")) {
		bpf_prog_detach2(prog_fd, cgs[last_cg].fd, BPF_CGROUP_INET_EGRESS);
		goto cleanup;
	}

	/* replace BPF programs inside their links for all but first link */
	for (i = 1; i < cg_nr; i++) {
		err = bpf_link__update_program(links[i], skel->progs.egress_alt);
		if (CHECK(err, "prog_upd", "link #%d\n", i))
			goto cleanup;
	}

	ping_and_check(1, cg_nr - 1);

	/* Attempt program update with wrong expected BPF program */
	link_upd_opts.old_prog_fd = bpf_program__fd(skel->progs.egress_alt);
	link_upd_opts.flags = BPF_F_REPLACE;
	err = bpf_link_update(bpf_link__fd(links[0]),
			      bpf_program__fd(skel->progs.egress_alt),
			      &link_upd_opts);
	if (CHECK(err == 0 || errno != EPERM, "prog_cmpxchg1",
		  "unexpectedly succeeded, err %d, errno %d\n", err, -errno))
		goto cleanup;

	/* Compare-exchange single link program from egress to egress_alt */
	link_upd_opts.old_prog_fd = bpf_program__fd(skel->progs.egress);
	link_upd_opts.flags = BPF_F_REPLACE;
	err = bpf_link_update(bpf_link__fd(links[0]),
			      bpf_program__fd(skel->progs.egress_alt),
			      &link_upd_opts);
	if (CHECK(err, "prog_cmpxchg2", "errno %d\n", -errno))
		goto cleanup;

	/* ping */
	ping_and_check(0, cg_nr);

	/* close cgroup FDs before detaching links */
	for (i = 0; i < cg_nr; i++) {
		if (cgs[i].fd > 0) {
			close(cgs[i].fd);
			cgs[i].fd = -1;
		}
	}

	/* BPF programs should still get called */
	ping_and_check(0, cg_nr);

	prog_id = link_info_prog_id(links[0], &info);
	CHECK(prog_id == 0, "link_info", "failed\n");
	CHECK(info.cgroup.cgroup_id == 0, "cgroup_id", "unexpected %llu\n", info.cgroup.cgroup_id);

	err = bpf_link__detach(links[0]);
	if (CHECK(err, "link_detach", "failed %d\n", err))
		goto cleanup;

	/* cgroup_id should be zero in link_info */
	prog_id = link_info_prog_id(links[0], &info);
	CHECK(prog_id == 0, "link_info", "failed\n");
	CHECK(info.cgroup.cgroup_id != 0, "cgroup_id", "unexpected %llu\n", info.cgroup.cgroup_id);

	/* First BPF program shouldn't be called anymore */
	ping_and_check(0, cg_nr - 1);

	/* leave cgroup and remove them, don't detach programs */
	cleanup_cgroup_environment();

	/* BPF programs should have been auto-detached */
	ping_and_check(0, 0);

cleanup:
	if (detach_legacy)
		bpf_prog_detach2(prog_fd, cgs[last_cg].fd,
				 BPF_CGROUP_INET_EGRESS);

	for (i = 0; i < cg_nr; i++) {
		bpf_link__destroy(links[i]);
	}
	test_cgroup_link__destroy(skel);

	for (i = 0; i < cg_nr; i++) {
		if (cgs[i].fd > 0)
			close(cgs[i].fd);
	}
	cleanup_cgroup_environment();
}

static void check_cgroup_link_create_log(int prog_fd, int target_fd,
					 struct bpf_link_create_opts *opts,
					 int err_exp, const char *msg)
{
	char log_buf[128] = {};
	LIBBPF_OPTS(bpf_log_opts, log_opts,
		    .buf = log_buf,
		    .size = sizeof(log_buf),
		    .level = 1,
	);
	int fd;

	opts->log_opts = &log_opts;
	fd = bpf_link_create(prog_fd, target_fd, BPF_CGROUP_INET_EGRESS, opts);
	if (!ASSERT_LT(fd, 0, "bpf_link_create")) {
		close(fd);
		return;
	}

	ASSERT_EQ(fd, err_exp, "err");
	ASSERT_STREQ(log_buf, msg, "log_buf");
	ASSERT_EQ(log_opts.true_size, strlen(msg) + 1, "log_size");
}

static void test_cgroup_link_create_log(int target_fd, __u32 flags, int err_exp, const char *msg)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = flags,
	);
	struct test_cgroup_link *skel;

	skel = test_cgroup_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_cgroup_link__open_and_load"))
		return;

	check_cgroup_link_create_log(bpf_program__fd(skel->progs.egress), target_fd, &opts,
				     err_exp, msg);

	test_cgroup_link__destroy(skel);
}

static void test_log_invalid_flags(void)
{
	const char *msg = "Invalid flags.\n";

	test_cgroup_link_create_log(-1, BPF_F_ALLOW_OVERRIDE, -EINVAL, msg);
}

static void test_log_invalid_target_fd(void)
{
	const char *msg = "Invalid target_fd.\n";

	test_cgroup_link_create_log(-1, 0, -EBADF, msg);
}

static void test_log_cgroup_attach(struct bpf_link_create_opts *opts,
				   int err_exp, const char *msg)
{
	struct test_cgroup_link *skel;
	int cg;

	cg = test__join_cgroup("/cgroup_link_log_attach");
	if (!ASSERT_GE(cg, 0, "join_cgroup"))
		return;

	skel = test_cgroup_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_cgroup_link__open_and_load"))
		goto out;

	check_cgroup_link_create_log(bpf_program__fd(skel->progs.egress), cg, opts, err_exp, msg);
	test_cgroup_link__destroy(skel);

out:
	close(cg);
}

static void test_log_relative_without_order(void)
{
	const char *msg = "Specify exactly one of BPF_F_BEFORE or BPF_F_AFTER.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = BPF_F_LINK,
	);

	test_log_cgroup_attach(&opts, -EINVAL, msg);
}

static void test_log_relative_both_orders(void)
{
	const char *msg = "Specify exactly one of BPF_F_BEFORE or BPF_F_AFTER.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = BPF_F_LINK | BPF_F_BEFORE | BPF_F_AFTER,
	);

	test_log_cgroup_attach(&opts, -EINVAL, msg);
}

static void test_log_relative_type_mismatch(void)
{
	const char *msg = "BPF_F_LINK is required for relative link attachment.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = BPF_F_BEFORE,
		    .cgroup.relative_fd = -1,
	);

	test_log_cgroup_attach(&opts, -EINVAL, msg);
}

static void test_log_invalid_relative_link_fd(void)
{
	const char *msg = "Invalid relative link FD.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = BPF_F_LINK | BPF_F_BEFORE,
		    .cgroup.relative_fd = -1,
	);

	test_log_cgroup_attach(&opts, -EBADF, msg);
}

static void test_log_invalid_relative_link_id(void)
{
	const char *msg = "Invalid relative link ID.\n";
	/* Link ID zero cannot identify a link. */
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = BPF_F_LINK | BPF_F_ID | BPF_F_BEFORE,
	);

	test_log_cgroup_attach(&opts, -ENOENT, msg);
}

static void test_log_relative_anchor(__u32 flags, bool other_cgroup, int err_exp, const char *msg)
{
	int cg, other_cg = -1, anchor_fd = -1, prog_fd;
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = flags,
	);
	struct test_cgroup_link *skel;

	cg = test__join_cgroup("/cgroup_link_log_relative");
	if (!ASSERT_GE(cg, 0, "join_cgroup"))
		return;

	if (other_cgroup) {
		other_cg = test__join_cgroup("/cgroup_link_log_other");
		if (!ASSERT_GE(other_cg, 0, "join_cgroup other"))
			goto cleanup;
	}

	skel = test_cgroup_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_cgroup_link__open_and_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.egress);
	anchor_fd = bpf_link_create(prog_fd, cg, BPF_CGROUP_INET_EGRESS, NULL);
	if (!ASSERT_GE(anchor_fd, 0, "bpf_link_create"))
		goto destroy;

	if (flags & BPF_F_LINK)
		opts.cgroup.relative_fd = anchor_fd;
	check_cgroup_link_create_log(prog_fd, other_cgroup ? other_cg : cg, &opts, err_exp, msg);

	close(anchor_fd);

destroy:
	test_cgroup_link__destroy(skel);
cleanup:
	if (other_cg >= 0)
		close(other_cg);
	close(cg);
}

static void test_log_both_orders(void)
{
	const char *msg = "BPF_F_BEFORE and BPF_F_AFTER are mutually exclusive.\n";

	test_log_relative_anchor(BPF_F_BEFORE | BPF_F_AFTER, false, -EINVAL, msg);
}

static void test_log_relative_preorder_mismatch(void)
{
	const char *msg = "Relative attachment BPF_F_PREORDER mismatch.\n";

	test_log_relative_anchor(BPF_F_LINK | BPF_F_BEFORE | BPF_F_PREORDER, false, -EINVAL, msg);
}

static void test_log_relative_not_in_cgroup(void)
{
	const char *msg = "Relative attachment not found in target cgroup.\n";

	test_log_relative_anchor(BPF_F_LINK | BPF_F_BEFORE, true, -ENOENT, msg);
}

static void test_log_revision_mismatch(void)
{
	const char *msg = "Cgroup revision mismatch: expected 2, actual 1.\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .cgroup.expected_revision = 2,
	);

	test_log_cgroup_attach(&opts, -ESTALE, msg);
}

static void test_log_exclusive_attach(bool child, const char *msg)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	int cg, child_cg = -1, prog_fd, err;
	struct test_cgroup_link *skel;

	cg = test__join_cgroup("/cgroup_link_log_exclusive");
	if (!ASSERT_GE(cg, 0, "join_cgroup"))
		return;

	if (child) {
		child_cg = test__join_cgroup("/cgroup_link_log_exclusive/child");
		if (!ASSERT_GE(child_cg, 0, "join_child_cgroup"))
			goto cleanup;
	}

	skel = test_cgroup_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_cgroup_link__open_and_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.egress);

	err = bpf_prog_attach(prog_fd, cg, BPF_CGROUP_INET_EGRESS, 0);
	if (!ASSERT_OK(err, "bpf_prog_attach"))
		goto destroy;

	check_cgroup_link_create_log(prog_fd, child ? child_cg : cg, &opts, -EPERM, msg);

	err = bpf_prog_detach2(prog_fd, cg, BPF_CGROUP_INET_EGRESS);
	ASSERT_OK(err, "bpf_prog_detach2");

destroy:
	test_cgroup_link__destroy(skel);
cleanup:
	if (child_cg >= 0)
		close(child_cg);
	close(cg);
}

static void test_log_attachment_flags_conflict(void)
{
	const char *msg = "Attachment flags conflict with existing flags.\n";

	test_log_exclusive_attach(false, msg);
}

static void test_log_hierarchy_disallows_attach(void)
{
	const char *msg = "Cgroup hierarchy does not allow attachment.\n";

	test_log_exclusive_attach(true, msg);
}

#define BPF_CGROUP_MAX_PROGS 64

static void test_log_too_many_programs(void)
{
	const char *msg = "Too many programs attached to cgroup (limit 64).\n";
	LIBBPF_OPTS(bpf_link_create_opts, opts);
	int cg, prog_fd, err, i, nr_links = 0;
	int link_fds[BPF_CGROUP_MAX_PROGS];
	struct test_cgroup_link *skel;

	cg = test__join_cgroup("/cgroup_link_log_limit");
	if (!ASSERT_GE(cg, 0, "join_cgroup"))
		return;

	skel = test_cgroup_link__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_cgroup_link__open_and_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.egress);

	for (i = 0; i < ARRAY_SIZE(link_fds); i++) {
		err = bpf_link_create(prog_fd, cg, BPF_CGROUP_INET_EGRESS, NULL);
		if (!ASSERT_GE(err, 0, "bpf_link_create"))
			goto destroy;

		link_fds[nr_links++] = err;
	}

	check_cgroup_link_create_log(prog_fd, cg, &opts, -E2BIG, msg);

destroy:
	for (i = 0; i < nr_links; i++)
		close(link_fds[i]);
	test_cgroup_link__destroy(skel);
cleanup:
	close(cg);
}

void test_cgroup_link_log(void)
{
	if (test__start_subtest("invalid_flags"))
		test_log_invalid_flags();
	if (test__start_subtest("invalid_target_fd"))
		test_log_invalid_target_fd();
	if (test__start_subtest("relative_without_order"))
		test_log_relative_without_order();
	if (test__start_subtest("relative_both_orders"))
		test_log_relative_both_orders();
	if (test__start_subtest("relative_type_mismatch"))
		test_log_relative_type_mismatch();
	if (test__start_subtest("invalid_relative_link_fd"))
		test_log_invalid_relative_link_fd();
	if (test__start_subtest("invalid_relative_link_id"))
		test_log_invalid_relative_link_id();
	if (test__start_subtest("both_orders"))
		test_log_both_orders();
	if (test__start_subtest("relative_preorder_mismatch"))
		test_log_relative_preorder_mismatch();
	if (test__start_subtest("relative_not_in_cgroup"))
		test_log_relative_not_in_cgroup();
	if (test__start_subtest("revision_mismatch"))
		test_log_revision_mismatch();
	if (test__start_subtest("attachment_flags_conflict"))
		test_log_attachment_flags_conflict();
	if (test__start_subtest("hierarchy_disallows_attach"))
		test_log_hierarchy_disallows_attach();
	if (test__start_subtest("too_many_programs"))
		test_log_too_many_programs();
}
