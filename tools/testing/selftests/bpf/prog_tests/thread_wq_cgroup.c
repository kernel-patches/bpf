// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <unistd.h>
#include "cgroup_helpers.h"
#include "thread_wq_cgroup.skel.h"

#define TEST_CGROUP "/thread_wq_test"
#define WAIT_TIMEOUT_SECS 30

void test_thread_wq_cgroup(void)
{
	struct thread_wq_cgroup *skel = NULL;
	int err, prog_fd, cg_fd = -1;
	unsigned long long cg_id;
	int waited_secs;

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		return;
	cg_fd = create_and_get_cgroup(TEST_CGROUP);
	if (!ASSERT_GE(cg_fd, 0, "create_and_get_cgroup"))
		goto cleanup;
	cg_id = get_cgroup_id(TEST_CGROUP);
	if (!ASSERT_GT(cg_id, 0ULL, "get_cgroup_id"))
		goto cleanup;

	skel = thread_wq_cgroup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.start_thread_wq);

	/* Run bpf_thread_wq in the specified cgroup. */
	skel->bss->test_key = 0;
	skel->bss->target_cgroup_id = cg_id;
	skel->bss->callback_cgroup_id = 0;
	skel->bss->twq_done = 0;
	if (!ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &topts),
		       "bpf_prog_test_run_opts in cgroup"))
		goto cleanup;
	if (!ASSERT_OK(topts.retval, "retval in cgroup"))
		goto cleanup;
	for (waited_secs = 0; waited_secs < WAIT_TIMEOUT_SECS; waited_secs++) {
		if (skel->bss->twq_done)
			break;
		sleep(1);
	}
	if (!ASSERT_TRUE(skel->bss->twq_done, "twq_done in cgroup"))
		goto cleanup;
	if (!ASSERT_EQ(skel->bss->callback_cgroup_id, cg_id,
		       "callback_cgroup_id in cgroup"))
		goto cleanup;

	/* Run bpf_thread_wq without cgroup attachment (cgroup_id = 0). */
	LIBBPF_OPTS_RESET(topts);
	skel->bss->test_key = 1;
	skel->bss->target_cgroup_id = 0;
	skel->bss->callback_cgroup_id = 0;
	skel->bss->twq_done = 0;
	if (!ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &topts),
		       "bpf_prog_test_run_opts without cgroup"))
		goto cleanup;
	if (!ASSERT_OK(topts.retval, "retval without cgroup"))
		goto cleanup;
	for (waited_secs = 0; waited_secs < WAIT_TIMEOUT_SECS; waited_secs++) {
		if (skel->bss->twq_done)
			break;
		sleep(1);
	}
	if (!ASSERT_TRUE(skel->bss->twq_done, "twq_done without cgroup"))
		goto cleanup;
	if (!ASSERT_NEQ(skel->bss->callback_cgroup_id, cg_id,
			"callback_cgroup_id without cgroup"))
		goto cleanup;

cleanup:
	if (skel) {
		thread_wq_cgroup__destroy(skel);
		/* Wait thread_wq kthread quit. */
		sleep(2);
	}
	if (cg_fd >= 0)
		close(cg_fd);
	cleanup_cgroup_environment();
}
