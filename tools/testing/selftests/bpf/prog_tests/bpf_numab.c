// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "bpf_numab.skel.h"

#define CGROUP_PATH	"/bpf_numab"
#define CHILD_PATH	CGROUP_PATH "/child"
#define HIER_PATH	"/bpf_numab_hier"
#define HIER_CHILD_PATH	HIER_PATH "/child"
#define NOMEM_PATH	"/bpf_numab_nomem"
#define NOMEM_CHILD_PATH NOMEM_PATH "/child"

/* The per-cgroup request domain, mirroring the kernel constants. */
#define NUMAB_FOLLOW_SYSTEM	(-1)
#define NUMAB_DISABLED		0
#define NUMAB_NORMAL		1
#define NUMAB_TIERING		2
#define NUMAB_NORMAL_TIERING	3

static int numab_set(struct bpf_numab *skel, u64 cgid,
		     long mode)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int ret;

	skel->bss->set_cgid = cgid;
	skel->bss->set_mode = mode;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.numab_set),
				     &opts);
	if (!ASSERT_OK(ret, "set run"))
		return -1;
	return skel->bss->set_ret;
}

static long numab_get(struct bpf_numab *skel, u64 cgid)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int ret;

	skel->bss->get_cgid = cgid;
	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.numab_get),
				     &opts);
	if (!ASSERT_OK(ret, "get run"))
		return -EIO;
	return skel->bss->get_mode;
}

static void test_set_get(void)
{
	struct bpf_numab *skel;
	int cgroup_fd;
	u64 cgid;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = bpf_numab__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	cgid = get_cgroup_id(CGROUP_PATH);
	if (!ASSERT_GT(cgid, 0, "get_cgroup_id"))
		goto cleanup;

	ASSERT_EQ(numab_set(skel, cgid, NUMAB_NORMAL), 0, "set normal");
	ASSERT_EQ(numab_get(skel, cgid), NUMAB_NORMAL, "get normal");

	ASSERT_EQ(numab_set(skel, cgid, NUMAB_TIERING), 0, "set tiering");
	ASSERT_EQ(numab_get(skel, cgid), NUMAB_TIERING, "get tiering");

	ASSERT_EQ(numab_set(skel, cgid, NUMAB_NORMAL_TIERING), 0, "set both");
	ASSERT_EQ(numab_get(skel, cgid), NUMAB_NORMAL_TIERING, "get both");

	ASSERT_EQ(numab_set(skel, cgid, NUMAB_DISABLED), 0, "set disabled");
	ASSERT_EQ(numab_get(skel, cgid), NUMAB_DISABLED, "get disabled");

	/* Back to the system setting. */
	ASSERT_EQ(numab_set(skel, cgid, NUMAB_FOLLOW_SYSTEM), 0, "unset");
	ASSERT_EQ(numab_get(skel, cgid), NUMAB_FOLLOW_SYSTEM, "get unset");

cleanup:
	bpf_numab__destroy(skel);
	close(cgroup_fd);
}

static void test_invalid_mode(void)
{
	struct bpf_numab *skel;
	int cgroup_fd;
	u64 cgid;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = bpf_numab__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	cgid = get_cgroup_id(CGROUP_PATH);
	if (!ASSERT_GT(cgid, 0, "get_cgroup_id"))
		goto cleanup;

	ASSERT_EQ(numab_set(skel, cgid, -2), -EINVAL, "set below domain");
	ASSERT_EQ(numab_set(skel, cgid, 4), -EINVAL, "set above domain");
	ASSERT_EQ(numab_set(skel, cgid, 0x1000), -EINVAL, "set far above");

	/* The rejected requests must not have stuck. */
	ASSERT_EQ(numab_get(skel, cgid), NUMAB_FOLLOW_SYSTEM, "get unchanged");

cleanup:
	bpf_numab__destroy(skel);
	close(cgroup_fd);
}

static void test_bad_cgid(void)
{
	struct bpf_numab *skel;

	skel = bpf_numab__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	ASSERT_EQ(numab_set(skel, 0, NUMAB_NORMAL), -ENOENT, "set cgid 0");
	ASSERT_EQ(numab_get(skel, 0), -ENOENT, "get cgid 0");
	ASSERT_EQ(numab_set(skel, 0xdeadbeef, NUMAB_NORMAL), -ENOENT,
		  "set bad cgid");
	ASSERT_EQ(numab_get(skel, 0xdeadbeef), -ENOENT, "get bad cgid");

	bpf_numab__destroy(skel);
}

static void test_hierarchy(void)
{
	u64 parent_cgid, child_cgid;
	int runner_fd, parent_fd, child_fd;
	struct bpf_numab *skel;

	runner_fd = test__join_cgroup("/bpf_numab_runner");
	if (!ASSERT_GE(runner_fd, 0, "join_runner_cgroup"))
		return;

	parent_fd = create_and_get_cgroup(HIER_PATH);
	if (!ASSERT_GE(parent_fd, 0, "create_parent_cgroup"))
		goto cleanup_runner;

	if (!ASSERT_OK(enable_controllers(HIER_PATH, "memory"),
		       "enable_memory_controller"))
		goto cleanup_parent;

	child_fd = create_and_get_cgroup(HIER_CHILD_PATH);
	if (!ASSERT_GE(child_fd, 0, "create_child_cgroup"))
		goto cleanup_parent;

	skel = bpf_numab__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	parent_cgid = get_cgroup_id(HIER_PATH);
	child_cgid = get_cgroup_id(HIER_CHILD_PATH);
	if (!ASSERT_GT(parent_cgid, 0, "get_parent_cgid") ||
	    !ASSERT_GT(child_cgid, 0, "get_child_cgid"))
		goto cleanup;

	/* The child inherits an ancestor's request untouched. */
	ASSERT_EQ(numab_set(skel, parent_cgid, NUMAB_TIERING), 0,
		  "set parent tiering");
	ASSERT_EQ(numab_get(skel, child_cgid), NUMAB_TIERING,
		  "child inherits");

	/* A request ORs with the ancestor's; NORMAL does not undo TIERING. */
	ASSERT_EQ(numab_set(skel, child_cgid, NUMAB_NORMAL), 0,
		  "set child normal");
	ASSERT_EQ(numab_get(skel, child_cgid), NUMAB_NORMAL_TIERING,
		  "or both");

	/* The child's own opt-out wins. */
	ASSERT_EQ(numab_set(skel, child_cgid, NUMAB_DISABLED), 0,
		  "set child disabled");
	ASSERT_EQ(numab_get(skel, child_cgid), NUMAB_DISABLED,
		  "own opt-out wins");

	/* So does an ancestor's: a task is never forced into balancing. */
	ASSERT_EQ(numab_set(skel, child_cgid, NUMAB_TIERING), 0,
		  "set child tiering");
	ASSERT_EQ(numab_set(skel, parent_cgid, NUMAB_DISABLED), 0,
		  "set parent disabled");
	ASSERT_EQ(numab_get(skel, child_cgid), NUMAB_DISABLED,
		  "ancestor opt-out wins");

	/* Unsetting the parent re-exposes the child's own request. */
	ASSERT_EQ(numab_set(skel, parent_cgid, NUMAB_FOLLOW_SYSTEM), 0,
		  "unset parent");
	ASSERT_EQ(numab_get(skel, child_cgid), NUMAB_TIERING,
		  "child request again");

	/* Unsetting the child leaves the chain with no request. */
	ASSERT_EQ(numab_set(skel, child_cgid, NUMAB_FOLLOW_SYSTEM), 0,
		  "unset child");
	ASSERT_EQ(numab_get(skel, child_cgid), NUMAB_FOLLOW_SYSTEM,
		  "no request");

cleanup:
	bpf_numab__destroy(skel);
	close(child_fd);
	remove_cgroup(HIER_CHILD_PATH);
cleanup_parent:
	close(parent_fd);
	remove_cgroup(HIER_PATH);
cleanup_runner:
	close(runner_fd);
}

static void test_no_memcg(void)
{
	struct bpf_numab *skel;
	int parent_fd, child_fd;
	u64 parent_cgid, child_cgid;

	parent_fd = test__join_cgroup(NOMEM_PATH);
	if (!ASSERT_GE(parent_fd, 0, "join_nomem_parent"))
		return;

	child_fd = create_and_get_cgroup(NOMEM_CHILD_PATH);
	if (!ASSERT_GE(child_fd, 0, "create_nomem_child"))
		goto cleanup_parent;

	skel = bpf_numab__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	parent_cgid = get_cgroup_id(NOMEM_PATH);
	child_cgid = get_cgroup_id(NOMEM_CHILD_PATH);
	if (!ASSERT_GT(parent_cgid, 0, "get_nomem_parent_cgid") ||
	    !ASSERT_GT(child_cgid, 0, "get_nomem_child_cgid"))
		goto cleanup;

	/*
	 * The parent has a memcg; the child was created without enabling
	 * the memory controller in the parent's subtree, so it has none.
	 */
	ASSERT_EQ(numab_set(skel, parent_cgid, NUMAB_NORMAL), 0,
		  "set parent normal");
	ASSERT_EQ(numab_get(skel, child_cgid), NUMAB_NORMAL,
		  "child resolves to parent memcg");
	ASSERT_EQ(numab_set(skel, child_cgid, NUMAB_TIERING), -EOPNOTSUPP,
		  "child set rejected");
	ASSERT_EQ(numab_get(skel, child_cgid), NUMAB_NORMAL,
		  "child get unchanged");

cleanup:
	bpf_numab__destroy(skel);
	close(child_fd);
	remove_cgroup(NOMEM_CHILD_PATH);
cleanup_parent:
	close(parent_fd);
}

void test_bpf_numab(void)
{
	if (test__start_subtest("set_get"))
		test_set_get();
	if (test__start_subtest("invalid_mode"))
		test_invalid_mode();
	if (test__start_subtest("bad_cgid"))
		test_bad_cgid();
	if (test__start_subtest("hierarchy"))
		test_hierarchy();
	if (test__start_subtest("no_memcg"))
		test_no_memcg();
}
