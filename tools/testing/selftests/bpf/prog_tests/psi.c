// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <test_progs.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>

#include "cgroup_helpers.h"
#include "test_psi.skel.h"

struct cgroup_desc {
	const char *path;
	int fd;
	unsigned long long id;
	int pid;
	size_t target;
	size_t high;
	bool victim;
	bool psi;
};

#define MB (1024 * 1024)

static struct cgroup_desc cgroups[] = {
	{ .path = "/oom_test" },
	{ .path = "/oom_test/cg1", .target = 100 * MB },
	{ .path = "/oom_test/cg2", .target = 500 * MB,
	  .high = 40 * MB, .psi = true, .victim = true },
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

static int setup_psi_alert(struct cgroup_desc *desc)
{
	const char *trig = "some 100000 1000000";
	int fd;

	fd = open_cgroup_file(desc->path, "memory.pressure", O_RDWR);
	if (fd < 0) {
		printf("memory.pressure open error: %s\n", strerror(errno));
		return 1;
	}

	if (write(fd, trig, strlen(trig) + 1) < 0) {
		printf("memory.pressure write error: %s\n", strerror(errno));
		return 1;
	}

	/* keep fd open, otherwise the psi trigger will be deleted */
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

		if (i == 0) {
			/* Freeze the top-level cgroup */
			err = write_cgroup_file(cgroups[i].path, "cgroup.freeze", "1");
			if (!ASSERT_OK(err, "freeze cgroup"))
				goto cleanup;
		}

		if (!cgroups[i].target) {
			/* Recursively enable the memory controller */
			err = write_cgroup_file(cgroups[i].path, "cgroup.subtree_control",
						"+memory");
			if (!ASSERT_OK(err, "enable memory controller"))
				goto cleanup;
		}

		if (cgroups[i].high) {
			char buf[256];

			snprintf(buf, sizeof(buf), "%lu", cgroups[i].high);
			err = write_cgroup_file(cgroups[i].path, "memory.high", buf);
			if (!ASSERT_OK(err, "set memory.high"))
				goto cleanup;

			snprintf(buf, sizeof(buf), "0");
			write_cgroup_file(cgroups[i].path, "memory.swap.max", buf);
		}

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

		if (cgroups[i].psi) {
			err = setup_psi_alert(&cgroups[i]);
			if (!ASSERT_OK(err, "create psi trigger"))
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

	ret = write_cgroup_file(cgroups[0].path, "cgroup.freeze", "0");
	if (!ASSERT_OK(ret, "freeze cgroup"))
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

		for (i = 0; i < ARRAY_SIZE(cgroups); i++) {
			if (!ASSERT_OK(cgroups[i].victim !=
				       (pid == cgroups[i].pid),
				       "correct process was killed")) {
				ret = -1;
				break;
			}

			if (!cgroups[i].victim)
				continue;

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

		for (i = 0; i < ARRAY_SIZE(cgroups); i++)
			if (cgroups[i].pid && cgroups[i].pid != pid)
				kill(cgroups[i].pid, SIGKILL);
	}

	return ret;
}

void test_psi(void)
{
	struct test_psi *skel;
	int err;

	skel = test_psi__open_and_load();
	err = test_psi__attach(skel);
	if (!ASSERT_OK(err, "test_psi__attach"))
		goto cleanup;

	setup_environment();

	run_and_wait_for_oom();

	cleanup_cgroup_environment();
cleanup:
	test_psi__destroy(skel);
}
