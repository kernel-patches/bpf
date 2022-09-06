// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <test_progs.h>

#include "test_libbpf_get_fd_opts.skel.h"

void test_libbpf_get_fd_opts(void)
{
	DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	struct test_libbpf_get_fd_opts *skel;
	struct bpf_map_info info_m = { 0 };
	__u32 len = sizeof(info_m), value;
	union bpf_iter_link_info linfo;
	struct bpf_link *link;
	struct bpf_map *map;
	char buf[16];
	int ret, zero = 0, fd = -1, iter_fd;

	DECLARE_LIBBPF_OPTS(bpf_get_fd_opts, fd_opts_rdonly,
		.open_flags = BPF_F_RDONLY,
	);

	skel = test_libbpf_get_fd_opts__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_libbpf_get_fd_opts__open_and_load"))
		return;

	bpf_program__set_autoattach(skel->progs.write_bpf_array_map, false);

	ret = test_libbpf_get_fd_opts__attach(skel);
	if (!ASSERT_OK(ret, "test_libbpf_get_fd_opts__attach"))
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

	fd = bpf_map_get_fd_by_id_opts(info_m.id, &fd_opts_rdonly);
	if (!ASSERT_GE(fd, 0, "bpf_map_get_fd_by_id_opts"))
		goto close_prog;

	/* Map lookup should work with read-only fd. */
	ret = bpf_map_lookup_elem(fd, &zero, &value);
	if (!ASSERT_OK(ret, "bpf_map_lookup_elem"))
		goto close_prog;

	if (!ASSERT_EQ(value, 0, "map value mismatch"))
		goto close_prog;

	/* Map update should not work with read-only fd. */
	ret = bpf_map_update_elem(fd, &zero, &len, BPF_ANY);
	if (!ASSERT_LT(ret, 0, "bpf_map_update_elem"))
		goto close_prog;

	/* Map update through map iterator should not work with read-only fd. */
	memset(&linfo, 0, sizeof(linfo));
	linfo.map.map_fd = fd;
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	link = bpf_program__attach_iter(skel->progs.write_bpf_array_map, &opts);
	if (!ASSERT_ERR_PTR(link, "bpf_program__attach_iter")) {
		/*
		 * Faulty path, this should never happen if fd modes check is
		 * added for map iterators.
		 */
		iter_fd = bpf_iter_create(bpf_link__fd(link));
		bpf_link__destroy(link);

		if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create (faulty path)"))
			goto close_prog;

		read(iter_fd, buf, sizeof(buf));
		close(iter_fd);

		ret = bpf_map_lookup_elem(fd, &zero, &value);
		if (!ASSERT_OK(ret, "bpf_map_lookup_elem (faulty path)"))
			goto close_prog;

		if (!ASSERT_EQ(value, 5,
			       "unauthorized map update (faulty path)"))
			goto close_prog;
	}

	/* Map update should work with read-write fd. */
	ret = bpf_map_update_elem(bpf_map__fd(map), &zero, &len, BPF_ANY);
	if (!ASSERT_OK(ret, "bpf_map_update_elem"))
		goto close_prog;

	/* Map update through map iterator should work with read-write fd. */
	linfo.map.map_fd = bpf_map__fd(map);
	link = bpf_program__attach_iter(skel->progs.write_bpf_array_map, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto close_prog;

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	bpf_link__destroy(link);

	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		goto close_prog;

	read(iter_fd, buf, sizeof(buf));
	close(iter_fd);

	ret = bpf_map_lookup_elem(fd, &zero, &value);
	if (!ASSERT_OK(ret, "bpf_map_lookup_elem"))
		goto close_prog;

	if (!ASSERT_EQ(value, 5, "map value mismatch"))
		goto close_prog;

	/* Prog get fd with opts set should not work (no kernel support). */
	ret = bpf_prog_get_fd_by_id_opts(0, &fd_opts_rdonly);
	if (!ASSERT_EQ(ret, -EINVAL, "bpf_prog_get_fd_by_id_opts"))
		goto close_prog;

	/* Link get fd with opts set should not work (no kernel support). */
	ret = bpf_link_get_fd_by_id_opts(0, &fd_opts_rdonly);
	if (!ASSERT_EQ(ret, -EINVAL, "bpf_link_get_fd_by_id_opts"))
		goto close_prog;

	/* BTF get fd with opts set should not work (no kernel support). */
	ret = bpf_btf_get_fd_by_id_opts(0, &fd_opts_rdonly);
	ASSERT_EQ(ret, -EINVAL, "bpf_btf_get_fd_by_id_opts");

close_prog:
	close(fd);
	test_libbpf_get_fd_opts__destroy(skel);
}
