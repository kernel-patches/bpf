// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <sys/stat.h>
#include <test_progs.h>

#include "test_map_check_access.skel.h"

#define PINNED_MAP_PATH "/sys/fs/bpf/test_map_check_access_map"
#define PINNED_ITER_PATH "/sys/fs/bpf/test_map_check_access_iter"
#define BPFTOOL_PATH "./bpftool_nobootstrap"
#define MAX_CMD_SIZE 1024

enum check_types { CHECK_NONE, CHECK_PINNED, CHECK_METADATA, CHECK_PERF };

struct bpftool_command {
	char str[MAX_CMD_SIZE];
	enum check_types check;
	bool failure;
};

struct bpftool_command bpftool_commands[] = {
	{ .str = BPFTOOL_PATH " map list" },
	{ .str = BPFTOOL_PATH " map show name data_input" },
	{ .str = BPFTOOL_PATH " map -f show pinned " PINNED_MAP_PATH,
	  .check = CHECK_PINNED },
	{ .str = "rm -f " PINNED_MAP_PATH },
	{ .str = BPFTOOL_PATH " map dump name data_input" },
	{ .str = BPFTOOL_PATH " map lookup name data_input key 0 0 0 0" },
	{ .str = BPFTOOL_PATH
	  " map update name data_input key 0 0 0 0 value 0 0 0 0 2> /dev/null",
	  .failure = true },
	{ .str = BPFTOOL_PATH
	  " map update name data_input_mim key 0 0 0 0 value name data_input" },
	{ .str = BPFTOOL_PATH
	  " map update name data_input_w key 0 0 0 0 value 0 0 0 0" },
	{ .str = BPFTOOL_PATH " iter pin test_map_check_access.o "
		 PINNED_ITER_PATH " map name data_input" },
	{ .str = "cat " PINNED_ITER_PATH },
	{ .str = "rm -f " PINNED_ITER_PATH },
	{ .str = BPFTOOL_PATH " prog show name check_access",
	  .check = CHECK_METADATA },
	{ .str = BPFTOOL_PATH " btf show" },
	{ .str = BPFTOOL_PATH " btf dump map name data_input" },
	{ .str = BPFTOOL_PATH " map pin name data_input " PINNED_MAP_PATH },
	{ .str = BPFTOOL_PATH " struct_ops show name dummy_2" },
	{ .str = BPFTOOL_PATH " struct_ops dump name dummy_2" },
	{ .str = BPFTOOL_PATH " map event_pipe name data_input_perf",
	  .check = CHECK_PERF },
};

static int _run_bpftool(struct bpftool_command *command)
{
	char output[1024] = { 0 };
	FILE *fp;
	int ret;

	fp = popen(command->str, "r");
	if (!fp)
		return -errno;

	fread(output, sizeof(output) - 1, sizeof(*output), fp);

	ret = pclose(fp);
	if (WEXITSTATUS(ret) && !command->failure)
		return WEXITSTATUS(ret);

	ret = 0;

	switch (command->check) {
	case CHECK_PINNED:
		if (!strstr(output, PINNED_MAP_PATH))
			ret = -ENOENT;
		break;
	case CHECK_METADATA:
		if (!strstr(output, "test_var"))
			ret = -ENOENT;
		break;
	case CHECK_PERF:
		if (strncmp(output, "==", 2))
			ret = -ENOENT;
		break;
	default:
		break;
	}

	return ret;
}

void test_map_check_access(void)
{
	struct test_map_check_access *skel;
	struct bpf_map_info info_m = { 0 };
	struct bpf_map *map;
	__u32 len = sizeof(info_m);
	int ret, zero = 0, fd, i;

	DECLARE_LIBBPF_OPTS(bpf_get_fd_opts, opts_rdonly,
		.flags = BPF_F_RDONLY,
	);

	skel = test_map_check_access__open();
	if (!ASSERT_OK_PTR(skel, "test_map_check_access__open"))
		return;

	bpf_program__set_autoload(skel->progs.dump_bpf_hash_map, false);

	ret = test_map_check_access__load(skel);
	if (!ASSERT_OK(ret, "test_map_check_access__load"))
		goto close_prog;

	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto close_prog;

	ret = test_map_check_access__attach(skel);
	if (!ASSERT_OK(ret, "test_map_check_access__attach"))
		goto close_prog;

	map = bpf_object__find_map_by_name(skel->obj, "data_input");
	if (!ASSERT_OK_PTR(map, "bpf_object__find_map_by_name"))
		goto close_prog;

	ret = bpf_obj_get_info_by_fd(bpf_map__fd(map), &info_m, &len);
	if (!ASSERT_OK(ret, "bpf_obj_get_info_by_fd"))
		goto close_prog;

	fd = bpf_map_get_fd_by_id(info_m.id);
	if (!ASSERT_LT(fd, 0, "bpf_map_get_fd_by_id"))
		goto close_prog;

	fd = bpf_map_get_fd_by_id_opts(info_m.id, NULL);
	if (!ASSERT_LT(fd, 0, "bpf_map_get_fd_by_id_opts"))
		goto close_prog;

	fd = bpf_map_get_fd_by_id_opts(info_m.id, &opts_rdonly);
	if (!ASSERT_GE(fd, 0, "bpf_map_get_fd_by_id_opts"))
		goto close_prog;

	ret = bpf_map_lookup_elem(fd, &zero, &len);
	if (!ASSERT_OK(ret, "bpf_map_lookup_elem")) {
		close(fd);
		goto close_prog;
	}

	ret = bpf_map_update_elem(fd, &zero, &len, BPF_ANY);

	close(fd);

	if (!ASSERT_LT(ret, 0, "bpf_map_update_elem"))
		goto close_prog;

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &len, BPF_ANY);
	if (!ASSERT_OK(ret, "bpf_map_update_elem"))
		goto close_prog;

	ret = bpf_map__pin(map, PINNED_MAP_PATH);
	if (!ASSERT_OK(ret, "bpf_map__pin"))
		goto close_prog;

	fd = bpf_obj_get_opts(PINNED_MAP_PATH, &opts_rdonly);
	if (!ASSERT_GE(fd, 0, "bpf_obj_get_opts"))
		goto close_prog;

	close(fd);

	fd = bpf_obj_get_opts(PINNED_MAP_PATH, NULL);
	if (!ASSERT_LT(fd, 0, "bpf_obj_get_opts")) {
		close(fd);
		goto close_prog;
	}

	for (i = 0; i < ARRAY_SIZE(bpftool_commands); i++) {
		ret = _run_bpftool(&bpftool_commands[i]);
		if (!ASSERT_OK(ret, bpftool_commands[i].str))
			goto close_prog;
	}

close_prog:
	test_map_check_access__destroy(skel);
	unlink(PINNED_MAP_PATH);
}
