// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>

#include "cgroup_helpers.h"
#include "test_oom.skel.h"

struct cgroup_desc {
	const char *path;
	int fd;
	unsigned long long id;
	int pid;
	size_t target;
	size_t max;
	int oom_score_adj;
	bool victim;
};

#define MB (1024 * 1024)
#define OOM_SCORE_ADJ_MIN	(-1000)
#define OOM_SCORE_ADJ_MAX	1000

static struct cgroup_desc cgroups[] = {
	{ .path = "/oom_test", .max = 80 * MB},
	{ .path = "/oom_test/cg1", .target = 10 * MB,
	  .oom_score_adj = OOM_SCORE_ADJ_MAX },
	{ .path = "/oom_test/cg2", .target = 40 * MB,
	  .oom_score_adj = OOM_SCORE_ADJ_MIN },
	{ .path = "/oom_test/cg3" },
	{ .path = "/oom_test/cg3/cg4", .target = 30 * MB,
	  .victim = true },
	{ .path = "/oom_test/cg3/cg5", .target = 20 * MB },
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
	if (desc->oom_score_adj) {
		char buf[64];
		int fd = open("/proc/self/oom_score_adj", O_WRONLY);

		if (fd < 0)
			return -1;

		snprintf(buf, sizeof(buf), "%d", desc->oom_score_adj);
		write(fd, buf, sizeof(buf));
		close(fd);
	}

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

		/* Freeze the top-level cgroup */
		if (i == 0) {
			/* Freeze the top-level cgroup */
			err = write_cgroup_file(cgroups[i].path, "cgroup.freeze", "1");
			if (!ASSERT_OK(err, "freeze cgroup"))
				goto cleanup;
		}

		/* Recursively enable the memory controller */
		if (!cgroups[i].target) {

			err = write_cgroup_file(cgroups[i].path, "cgroup.subtree_control",
						"+memory");
			if (!ASSERT_OK(err, "enable memory controller"))
				goto cleanup;
		}

		/* Set memory.max */
		if (cgroups[i].max) {
			char buf[256];

			snprintf(buf, sizeof(buf), "%lu", cgroups[i].max);
			err = write_cgroup_file(cgroups[i].path, "memory.max", buf);
			if (!ASSERT_OK(err, "set memory.max"))
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
			size = read_cgroup_file(cgroups[i].path,
						"memory.events",
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

void test_oom(void)
{
	DECLARE_LIBBPF_OPTS(bpf_struct_ops_opts, opts);
	struct test_oom *skel;
	struct bpf_link *link1, *link2;
	int err = 0;

	setup_environment();

	skel = test_oom__open_and_load();
	if (!skel) {
		err = -errno;
		CHECK_FAIL(err);
		goto cleanup;
	}

	opts.relative_fd = cgroups[0].fd;
	link1 = bpf_map__attach_struct_ops_opts(skel->maps.test_bpf_oom, &opts);
	if (!link1) {
		err = -errno;
		CHECK_FAIL(err);
		goto cleanup;
	}

	opts.relative_fd = 0; /* attach system-wide */
	link2 = bpf_map__attach_struct_ops_opts(skel->maps.test_bpf_oom, &opts);
	if (!link2) {
		err = -errno;
		CHECK_FAIL(err);
		goto cleanup;
	}

	/* Unfreeze all child tasks and create the memory pressure */
	err = run_and_wait_for_oom();
	CHECK_FAIL(err);

cleanup:
	cleanup_cgroup_environment();
	test_oom__destroy(skel);
}
