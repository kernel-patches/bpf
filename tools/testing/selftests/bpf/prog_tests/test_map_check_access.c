// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <test_progs.h>

#include "map_check_access.skel.h"

#define PINNED_MAP_PATH "/sys/fs/bpf/test_map_check_access_map"
#define BPFTOOL_PATH "./tools/build/bpftool/bpftool"

enum check_types { CHECK_NONE, CHECK_PINNED, CHECK_METADATA };

static int populate_argv(char *argv[], int max_args, char *cmdline)
{
	char *arg;
	int i = 0;

	argv[i++] = BPFTOOL_PATH;

	while ((arg = strsep(&cmdline, " "))) {
		if (i == max_args - 1)
			break;

		argv[i++] = arg;
	}

	argv[i] = NULL;
	return i;
}

static void restore_cmdline(char *argv[], int num_args)
{
	int i;

	for (i = 1; i < num_args - 1; i++)
		argv[i][strlen(argv[i])] = ' ';
}

static int _run_bpftool(char *cmdline, enum check_types check)
{
	char *argv[20];
	char output[1024];
	int ret, fd[2], num_args, child_pid, child_status;

	num_args = populate_argv(argv, ARRAY_SIZE(argv), cmdline);

	ret = pipe(fd);
	if (ret < 0)
		return ret;

	child_pid = fork();
	if (child_pid == 0) {
		close(fd[0]);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		ret = dup2(fd[1], STDOUT_FILENO);
		if (ret < 0) {
			close(fd[1]);
			exit(errno);
		}

		execv(BPFTOOL_PATH, argv);
		close(fd[1]);
		exit(errno);
	} else if (child_pid > 0) {
		close(fd[1]);

		restore_cmdline(argv, num_args);

		waitpid(child_pid, &child_status, 0);
		if (WEXITSTATUS(child_status)) {
			close(fd[0]);
			return WEXITSTATUS(child_status);
		}

		ret = read(fd[0], output, sizeof(output) - 1);

		close(fd[0]);

		if (ret < 0)
			return ret;

		output[ret] = '\0';
		ret = 0;

		switch (check) {
		case CHECK_PINNED:
			if (!strstr(output, PINNED_MAP_PATH))
				ret = -ENOENT;
			break;
		case CHECK_METADATA:
			if (!strstr(output, "test_var"))
				ret = -ENOENT;
			break;
		default:
			break;
		}

		return ret;
	}

	close(fd[0]);
	close(fd[1]);

	return -EINVAL;
}

void test_test_map_check_access(void)
{
	struct map_check_access *skel;
	struct bpf_map_info info_m = { 0 };
	struct bpf_map *map;
	__u32 len = sizeof(info_m);
	char cmdline[1024];
	int ret, zero = 0, fd, duration = 0;

	skel = map_check_access__open_and_load();
	if (CHECK(!skel, "skel", "open_and_load failed\n"))
		goto close_prog;

	ret = map_check_access__attach(skel);
	if (CHECK(ret < 0, "skel", "attach failed\n"))
		goto close_prog;

	map = bpf_object__find_map_by_name(skel->obj, "data_input");
	if (CHECK(!map, "bpf_object__find_map_by_name", "not found\n"))
		goto close_prog;

	ret = bpf_obj_get_info_by_fd(bpf_map__fd(map), &info_m, &len);
	if (CHECK(ret < 0, "bpf_obj_get_info_by_fd", "error: %d\n", ret))
		goto close_prog;

	fd = bpf_map_get_fd_by_id(info_m.id);
	if (CHECK(fd >= 0, "bpf_map_get_fd_by_id",
		  "should fail (map write-protected)\n"))
		goto close_prog;

	fd = bpf_map_get_fd_by_id_flags(info_m.id, 0);
	if (CHECK(fd >= 0, "bpf_map_get_fd_by_id_flags",
		  "should fail (map write-protected)\n"))
		goto close_prog;

	fd = bpf_map_get_fd_by_id_flags(info_m.id, BPF_F_RDONLY);
	if (CHECK(fd < 0, "bpf_map_get_fd_by_id_flags", "error: %d\n", fd))
		goto close_prog;

	ret = bpf_map_lookup_elem(fd, &zero, &len);
	if (CHECK(ret < 0, "bpf_map_lookup_elem", "error: %d\n", ret)) {
		close(fd);
		goto close_prog;
	}

	ret = bpf_map_update_elem(fd, &zero, &len, BPF_ANY);

	close(fd);

	if (CHECK(!ret, "bpf_map_update_elem",
		  "should fail (read-only permission)\n"))
		goto close_prog;

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &len, BPF_ANY);
	if (CHECK(ret < 0, "bpf_map_update_elem", "error: %d\n", ret))
		goto close_prog;

	ret = bpf_map__pin(map, PINNED_MAP_PATH);
	if (CHECK(ret < 0, "bpf_map__pin", "error: %d\n", ret))
		goto close_prog;

	fd = bpf_obj_get_flags(PINNED_MAP_PATH, BPF_F_RDONLY);
	if (CHECK(fd < 0, "bpf_obj_get_flags", "error: %d\n", fd))
		goto close_prog;

	close(fd);

	fd = bpf_obj_get_flags(PINNED_MAP_PATH, 0);
	if (CHECK(fd >= 0, "bpf_obj_get_flags",
		  "should fail (read-only permission)\n")) {
		close(fd);
		goto close_prog;
	}

	snprintf(cmdline, sizeof(cmdline), "map list");
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline), "map show name data_input");
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline), "map -f show pinned %s",
		 PINNED_MAP_PATH);
	ret = _run_bpftool(cmdline, CHECK_PINNED);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	unlink(PINNED_MAP_PATH);

	snprintf(cmdline, sizeof(cmdline), "map dump name data_input");
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline),
		 "map lookup name data_input key 0 0 0 0");
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline),
		 "map update name data_input key 0 0 0 0 value 0 0 0 0");
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(!ret, "bpftool",
		  "%s - should fail (read-only permission)\n", cmdline))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline),
		 "map update name data_input_w key 0 0 0 0 value 0 0 0 0");
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline), "prog show name check_access");
	ret = _run_bpftool(cmdline, CHECK_METADATA);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline), "btf show");
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline), "btf dump map name data_input");
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline), "map pin name data_input %s",
		 PINNED_MAP_PATH);
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline), "struct_ops show name dummy_2");
	ret = _run_bpftool(cmdline, CHECK_NONE);
	if (CHECK(ret, "bpftool", "%s - error: %d\n", cmdline, ret))
		goto close_prog;

	snprintf(cmdline, sizeof(cmdline), "struct_ops dump name dummy_2");
	ret = _run_bpftool(cmdline, CHECK_NONE);

	CHECK(ret, "_run_bpftool", "%s - error: %d\n", cmdline, ret);

close_prog:
	map_check_access__destroy(skel);
	unlink(PINNED_MAP_PATH);
}
