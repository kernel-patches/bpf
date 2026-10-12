// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <time.h>
#include "cgroup_helpers.h"
#include "bpf_numab_ops.skel.h"

#define CGROUP_PATH	"/bpf_numab_ops"
#define CHILD_PATH	CGROUP_PATH "/child"

/*
 * task_tick_fair() consults the per-cgroup NUMA balancing policy on every
 * tick of a running task, so a short busy loop is enough to prove that the
 * hook runs. This works regardless of the global numa_balancing sysctl
 * state and regardless of the machine's NUMA topology: both the enabled
 * and disabled code paths end up calling every attached policy.
 */
static void burn_cpu_ms(int ms)
{
	struct timespec now;
	u64 deadline;

	clock_gettime(CLOCK_MONOTONIC, &now);
	deadline = now.tv_sec * 1000ULL + now.tv_nsec / 1000000ULL + ms;

	do {
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (now.tv_sec * 1000ULL + now.tv_nsec / 1000000ULL < deadline);
}

static void test_attach_detach(void)
{
	struct bpf_numab_ops *skel;
	struct bpf_link *link = NULL;
	int cgroup_fd, before;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = bpf_numab_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	link = bpf_map__attach_cgroup_opts(skel->maps.numab_enable_ops,
					   cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(link, "attach_enable_ops"))
		goto cleanup;

	skel->bss->enable_cnt = 0;
	burn_cpu_ms(300);
	ASSERT_GT(skel->bss->enable_cnt, 0, "enable_cnt");

	/*
	 * Detach and let a grace period pass so that no reader is still
	 * walking the old effective array, then verify the hook stopped
	 * running.
	 */
	before = skel->bss->enable_cnt;
	bpf_link__destroy(link);
	link = NULL;
	sleep(1);
	burn_cpu_ms(300);
	ASSERT_EQ(skel->bss->enable_cnt, before, "enable_cnt_after_detach");

cleanup:
	bpf_link__destroy(link);
	bpf_numab_ops__destroy(skel);
	close(cgroup_fd);
}

/*
 * Attach to the parent cgroup while the task lives in the child: the
 * child's effective array must aggregate the parent's policy.
 */
static void test_hierarchy(void)
{
	struct bpf_numab_ops *skel;
	struct bpf_link *plink = NULL;
	int parent_fd, child_fd = -1;

	parent_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(parent_fd, 0, "join_parent_cgroup"))
		return;

	child_fd = create_and_get_cgroup(CHILD_PATH);
	if (!ASSERT_GE(child_fd, 0, "create_child_cgroup"))
		goto cleanup;

	if (!ASSERT_OK(join_cgroup(CHILD_PATH), "join_child_cgroup"))
		goto cleanup;

	skel = bpf_numab_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	plink = bpf_map__attach_cgroup_opts(skel->maps.numab_enable_ops,
					    parent_fd, NULL);
	if (!ASSERT_OK_PTR(plink, "attach_to_parent"))
		goto cleanup;

	skel->bss->enable_cnt = 0;
	burn_cpu_ms(300);
	ASSERT_GT(skel->bss->enable_cnt, 0, "enable_cnt_from_parent_policy");

cleanup:
	bpf_link__destroy(plink);
	bpf_numab_ops__destroy(skel);
	if (child_fd >= 0) {
		close(child_fd);
		join_cgroup(CGROUP_PATH);
		remove_cgroup(CHILD_PATH);
	}
	close(parent_fd);
}

/*
 * Attach two policies to the same cgroup. Both must run: the kernel
 * combines what they return.
 */
static void test_multi(void)
{
	struct bpf_numab_ops *skel;
	struct bpf_link *link1 = NULL, *link2 = NULL;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = bpf_numab_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	link1 = bpf_map__attach_cgroup_opts(skel->maps.numab_enable_ops,
					    cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(link1, "attach_enable_ops"))
		goto cleanup;

	link2 = bpf_map__attach_cgroup_opts(skel->maps.numab_disable_ops,
					    cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(link2, "attach_disable_ops"))
		goto cleanup;

	skel->bss->enable_cnt = 0;
	skel->bss->disable_cnt = 0;
	burn_cpu_ms(300);
	ASSERT_GT(skel->bss->enable_cnt, 0, "enable_cnt");
	ASSERT_GT(skel->bss->disable_cnt, 0, "disable_cnt");

cleanup:
	bpf_link__destroy(link2);
	bpf_link__destroy(link1);
	bpf_numab_ops__destroy(skel);
	close(cgroup_fd);
}

/*
 * Attach to the parent first, then create and join the child cgroup. The
 * child must inherit the parent's effective array via cgroup_bpf_inherit().
 */
static void test_inherit(void)
{
	struct bpf_numab_ops *skel;
	struct bpf_link *plink = NULL;
	int parent_fd, child_fd = -1;

	parent_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(parent_fd, 0, "join_parent_cgroup"))
		return;

	skel = bpf_numab_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	plink = bpf_map__attach_cgroup_opts(skel->maps.numab_enable_ops,
					    parent_fd, NULL);
	if (!ASSERT_OK_PTR(plink, "attach_to_parent"))
		goto cleanup;

	child_fd = create_and_get_cgroup(CHILD_PATH);
	if (!ASSERT_GE(child_fd, 0, "create_child_cgroup"))
		goto cleanup;

	if (!ASSERT_OK(join_cgroup(CHILD_PATH), "join_child_cgroup"))
		goto cleanup;

	skel->bss->enable_cnt = 0;
	burn_cpu_ms(300);
	ASSERT_GT(skel->bss->enable_cnt, 0, "enable_cnt_inherited");

cleanup:
	bpf_link__destroy(plink);
	bpf_numab_ops__destroy(skel);
	if (child_fd >= 0) {
		close(child_fd);
		join_cgroup(CGROUP_PATH);
		remove_cgroup(CHILD_PATH);
	}
	close(parent_fd);
}

/*
 * A surface-dispatching policy must load, attach and run from the task
 * surface.  The folio surface runs from the scanner and fault paths,
 * which need a scan pass and foreign-node folios to consult, so folio_cnt
 * is left for debugging rather than asserted here.
 */
static void test_mixed(void)
{
	struct bpf_numab_ops *skel;
	struct bpf_link *link = NULL;
	int cgroup_fd;

	cgroup_fd = test__join_cgroup(CGROUP_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = bpf_numab_ops__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	link = bpf_map__attach_cgroup_opts(skel->maps.numab_mixed_ops,
					   cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(link, "attach_mixed_ops"))
		goto cleanup;

	skel->bss->task_cnt = 0;
	burn_cpu_ms(300);
	ASSERT_GT(skel->bss->task_cnt, 0, "task_cnt");

cleanup:
	bpf_link__destroy(link);
	bpf_numab_ops__destroy(skel);
	close(cgroup_fd);
}

void serial_test_bpf_numab_ops(void)
{
	if (test__start_subtest("attach_detach"))
		test_attach_detach();
	if (test__start_subtest("hierarchy"))
		test_hierarchy();
	if (test__start_subtest("multi"))
		test_multi();
	if (test__start_subtest("mixed"))
		test_mixed();
	if (test__start_subtest("inherit"))
		test_inherit();
}
