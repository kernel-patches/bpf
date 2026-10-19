// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "cgroup_helpers.h"
#include "bpf_numab.skel.h"

#define CGROUP_PATH	"/bpf_numab"
#define CHILD_PATH	CGROUP_PATH "/child"

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
		return -1;
	return skel->bss->get_mode;
}

/*
 * Roundtrip through the combined view: the test cgroup has no ancestor
 * making a request, so the combined mode is the stored one.
 */
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

/*
 * The mode domain: NUMAB_FOLLOW_SYSTEM and the NUMA_BALANCING_* bitmasks
 * are accepted, anything else is rejected with -EINVAL.
 */
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

/*
 * An id that resolves to no cgroup is rejected with -ENOENT.
 */
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

/*
 * The requests of a cgroup and of every ancestor combine: an opt-out
 * wins over every request in the chain, otherwise the requested bits OR
 * together, and an unset cgroup inherits what its ancestors ask for.
 */
static void test_hierarchy(void)
{
	u64 parent_cgid, child_cgid;
	int parent_fd, child_fd;
	struct bpf_numab *skel;

	parent_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(parent_fd, 0, "join_parent_cgroup"))
		return;

	child_fd = create_and_get_cgroup(CHILD_PATH);
	if (!ASSERT_GE(child_fd, 0, "create_child_cgroup"))
		goto cleanup_parent;

	skel = bpf_numab__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	parent_cgid = get_cgroup_id(CGROUP_PATH);
	child_cgid = get_cgroup_id(CHILD_PATH);
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
	remove_cgroup(CHILD_PATH);
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
}
