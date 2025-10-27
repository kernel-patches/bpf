// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>

#include "cgroup_helpers.h"
#include "test_psi.skel.h"

enum psi_res {
	PSI_IO,
	PSI_MEM,
	PSI_CPU,
	PSI_IRQ,
	NR_PSI_RESOURCES,
};

struct cgroup_desc {
	const char *path;
	unsigned long long id;
	int pid;
	int fd;
	size_t target;
	size_t high;
	bool victim;
};

#define MB (1024 * 1024)

static struct cgroup_desc cgroups[] = {
	{ .path = "/psi_test" },
	{ .path = "/psi_test/cg1" },
	{ .path = "/psi_test/cg2", .target = 500 * MB,
	  .high = 40 * MB, .victim = true },
};

static int spawn_task(struct cgroup_desc *desc)
{
	char *ptr;
	int pid;

	pid = fork();
	if (pid < 0)
		return pid;

	if (pid > 0) {
		/* parent */
		desc->pid = pid;
		return 0;
	}

	/* child */
	ptr = (char *)malloc(desc->target);
	if (!ptr)
		return -ENOMEM;

	memset(ptr, 'a', desc->target);

	while (1)
		sleep(1000);

	return 0;
}

static void setup_environment(void)
{
	int i, err;

	err = setup_cgroup_environment();
	if (!ASSERT_OK(err, "setup_cgroup_environment"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(cgroups); i++) {
		cgroups[i].fd = create_and_get_cgroup(cgroups[i].path);
		if (!ASSERT_GE(cgroups[i].fd, 0, "create_and_get_cgroup"))
			goto cleanup;

		cgroups[i].id = get_cgroup_id(cgroups[i].path);
		if (!ASSERT_GT(cgroups[i].id, 0, "get_cgroup_id"))
			goto cleanup;

		/* Freeze the top-level cgroup and enable the memory controller */
		if (i == 0) {
			err = write_cgroup_file(cgroups[i].path, "cgroup.freeze", "1");
			if (!ASSERT_OK(err, "freeze cgroup"))
				goto cleanup;

			err = write_cgroup_file(cgroups[i].path, "cgroup.subtree_control",
						"+memory");
			if (!ASSERT_OK(err, "enable memory controller"))
				goto cleanup;
		}

		/* Set memory.high */
		if (cgroups[i].high) {
			char buf[256];

			snprintf(buf, sizeof(buf), "%lu", cgroups[i].high);
			err = write_cgroup_file(cgroups[i].path, "memory.high", buf);
			if (!ASSERT_OK(err, "set memory.high"))
				goto cleanup;

			snprintf(buf, sizeof(buf), "0");
			write_cgroup_file(cgroups[i].path, "memory.swap.max", buf);
		}

		/* Spawn tasks creating memory pressure */
		if (cgroups[i].target) {
			char buf[256];

			err = spawn_task(&cgroups[i]);
			if (!ASSERT_OK(err, "spawn task"))
				goto cleanup;

			snprintf(buf, sizeof(buf), "%d", cgroups[i].pid);
			err = write_cgroup_file(cgroups[i].path, "cgroup.procs", buf);
			if (!ASSERT_OK(err, "put child into a cgroup"))
				goto cleanup;
		}
	}

	return;

cleanup:
	cleanup_cgroup_environment();
}

static int run_and_wait_for_oom(void)
{
	int ret = -1;
	bool first = true;
	char buf[4096] = {};
	size_t size;

	/* Unfreeze the top-level cgroup */
	ret = write_cgroup_file(cgroups[0].path, "cgroup.freeze", "0");
	if (!ASSERT_OK(ret, "unfreeze cgroup"))
		return -1;

	for (;;) {
		int i, status;
		pid_t pid = wait(&status);

		if (pid == -1) {
			if (errno == EINTR)
				continue;
			/* ECHILD */
			break;
		}

		if (!first)
			continue;
		first = false;

		/* Check which process was terminated first */
		for (i = 0; i < ARRAY_SIZE(cgroups); i++) {
			if (!ASSERT_OK(cgroups[i].victim !=
				       (pid == cgroups[i].pid),
				       "correct process was killed")) {
				ret = -1;
				break;
			}

			if (!cgroups[i].victim)
				continue;

			/* Check the memcg oom counter */
			size = read_cgroup_file(cgroups[i].path, "memory.events",
						buf, sizeof(buf));
			if (!ASSERT_OK(size <= 0, "read memory.events")) {
				ret = -1;
				break;
			}

			if (!ASSERT_OK(strstr(buf, "oom_kill 1") == NULL,
				       "oom_kill count check")) {
				ret = -1;
				break;
			}
		}

		/* Kill all remaining tasks */
		for (i = 0; i < ARRAY_SIZE(cgroups); i++)
			if (cgroups[i].pid && cgroups[i].pid != pid)
				kill(cgroups[i].pid, SIGKILL);
	}

	return ret;
}

void test_psi(void)
{
	struct test_psi *skel;
	u64 deleted_cgroup_id;
	int new_cgroup_fd;
	u64 new_cgroup_id;
	int err;

	setup_environment();

	skel = test_psi__open_and_load();
	err = libbpf_get_error(skel);
	if (CHECK_FAIL(err))
		goto cleanup;

	skel->bss->deleted_cgroup_id = cgroups[1].id;
	skel->bss->high_pressure_cgroup_id = cgroups[2].id;

	err = test_psi__attach(skel);
	if (CHECK_FAIL(err))
		goto cleanup;

	/* Delete the first cgroup, it should trigger handle_cgroup_offline() */
	remove_cgroup(cgroups[1].path);

	new_cgroup_fd = create_and_get_cgroup("/psi_test_new");
	if (!ASSERT_GE(new_cgroup_fd, 0, "create_and_get_cgroup"))
		goto cleanup;

	new_cgroup_id = get_cgroup_id("/psi_test_new");
	if (!ASSERT_GT(new_cgroup_id, 0, "get_cgroup_id"))
		goto cleanup;

	/* Unfreeze all child tasks and create the memory pressure */
	err = run_and_wait_for_oom();
	CHECK_FAIL(err);

	/* Check the result of the handle_cgroup_offline() handler */
	deleted_cgroup_id = skel->bss->deleted_cgroup_id;
	ASSERT_EQ(deleted_cgroup_id, cgroups[1].id, "deleted cgroup id");

	/* Check the result of the handle_cgroup_online() handler */
	ASSERT_EQ(skel->bss->new_cgroup_id, new_cgroup_id,
		  "new cgroup id");

cleanup:
	cleanup_cgroup_environment();
	test_psi__destroy(skel);
}
