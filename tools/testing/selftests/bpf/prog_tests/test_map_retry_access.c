// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <test_progs.h>

#include "map_retry_access.skel.h"

void test_test_map_retry_access(void)
{
	struct map_retry_access *skel;
	struct bpf_map_info info;
	struct bpf_map *map;
	__u32 len = sizeof(info);
	int ret, zero = 0, fd, duration = 0;

	skel = map_retry_access__open_and_load();
	if (CHECK(!skel, "skel", "open_and_load failed\n"))
		goto close_prog;

	ret = map_retry_access__attach(skel);
	if (CHECK(ret < 0, "skel", "attach failed\n"))
		goto close_prog;

	map = bpf_object__find_map_by_name(skel->obj, "data_input");
	if (CHECK(!map, "bpf_object__find_map_by_name", "not found\n"))
		goto close_prog;

	ret = bpf_obj_get_info_by_fd(bpf_map__fd(map), &info, &len);
	if (CHECK(ret < 0, "bpf_obj_get_info_by_fd", "error: %d\n", ret))
		goto close_prog;

	fd = bpf_map_get_fd_by_id(info.id);
	if (CHECK(fd < 0, "bpf_map_get_fd_by_id", "error: %d\n", fd))
		goto close_prog;

	ret = bpf_map_update_elem(fd, &zero, &len, BPF_ANY);

	close(fd);

	if (CHECK(!ret, "bpf_map_update_elem",
		  "should fail (read-only permission)\n"))
		goto close_prog;

	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &len, BPF_ANY);

	CHECK(ret < 0, "bpf_map_update_elem", "error: %d\n", ret);
close_prog:
	map_retry_access__destroy(skel);
}
