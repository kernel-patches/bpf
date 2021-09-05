/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */

#include <test_progs.h>
#include "test_map_create.skel.h"

void test_map_create(void)
{
	struct test_map_create *skel;
	int err, fd;

	skel = test_map_create__open();
	if (!ASSERT_OK_PTR(skel, "test_map_create__open failed"))
		return;

	err = test_map_create__load(skel);
	if (!ASSERT_OK(err, "test_map_create__load failed"))
		goto cleanup;

	fd = bpf_map__fd(skel->maps.map1);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map2);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map3);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map4);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map5);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map6);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map7);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map8);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map9);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map10);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map11);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map12);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

	fd = bpf_map__fd(skel->maps.map13);
	if (!ASSERT_GT(fd, 0, "bpf_map__fd failed"))
		goto cleanup;
	close(fd);

cleanup:
	test_map_create__destroy(skel);
}
