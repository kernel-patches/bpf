// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <test_progs.h>
#include <bpf/btf.h>

#include "map_excl.skel.h"

static void test_map_exclusive_inner(void)
{
	struct map_excl *skel;
	int err;

	skel = map_excl__open();
	if (!ASSERT_OK_PTR(skel, "map_excl open"))
		return;

	err = bpf_map__make_exclusive(skel->maps.inner_map,
				      skel->progs.should_have_access);
	if (!ASSERT_OK(err, "bpf_map__make_exclusive"))
		goto out;

	err = map_excl__load(skel);
	ASSERT_EQ(err, -EOPNOTSUPP, "map_excl__load");

out:
	map_excl__destroy(skel);
}

static void test_map_exclusive_outer_array(void)
{
	struct map_excl *skel;
	int err;

	skel = map_excl__open();
	if (!ASSERT_OK_PTR(skel, "map_excl open"))
		return;

	err = bpf_map__make_exclusive(skel->maps.outer_array_map,
				      skel->progs.should_have_access);
	if (!ASSERT_OK(err, "bpf_map__make_exclusive"))
		goto out;

	bpf_program__set_autoload(skel->progs.should_have_access, true);
	bpf_program__set_autoload(skel->progs.should_not_have_access, false);

	err = map_excl__load(skel);
	ASSERT_EQ(err, -EOPNOTSUPP, "exclusive maps of maps are not supported\n");
out:
	map_excl__destroy(skel);
}

static void test_map_exclusive_outer_htab(void)
{
	struct map_excl *skel;
	int err;

	skel = map_excl__open();
	if (!ASSERT_OK_PTR(skel, "map_excl open"))
		return;

	err = bpf_map__make_exclusive(skel->maps.outer_htab_map,
				      skel->progs.should_have_access);
	if (!ASSERT_OK(err, "bpf_map__make_exclusive"))
		goto out;

	bpf_program__set_autoload(skel->progs.should_have_access, true);
	bpf_program__set_autoload(skel->progs.should_not_have_access, false);

	err = map_excl__load(skel);
	ASSERT_EQ(err, -EOPNOTSUPP, "exclusive maps of maps are not supported\n");

out:
	map_excl__destroy(skel);
}

static void test_map_excl_allowed(void)
{
	struct map_excl *skel = map_excl__open();
	int err;

	err = bpf_map__make_exclusive(skel->maps.excl_map, skel->progs.should_have_access);
	if (!ASSERT_OK(err, "bpf_map__make_exclusive"))
		goto out;

	bpf_program__set_autoload(skel->progs.should_have_access, true);
	bpf_program__set_autoload(skel->progs.should_not_have_access, false);

	err = map_excl__load(skel);
	ASSERT_OK(err, "map_excl__load");
out:
	map_excl__destroy(skel);
}

static void test_map_excl_denied(void)
{
	struct map_excl *skel = map_excl__open();
	int err;

	err = bpf_map__make_exclusive(skel->maps.excl_map, skel->progs.should_have_access);
	if (!ASSERT_OK(err, "bpf_map__make_exclusive"))
		goto out;

	bpf_program__set_autoload(skel->progs.should_have_access, false);
	bpf_program__set_autoload(skel->progs.should_not_have_access, true);

	err = map_excl__load(skel);
	ASSERT_EQ(err, -EACCES, "exclusive map Paccess not denied\n");
out:
	map_excl__destroy(skel);

}

void test_map_excl(void)
{
	start_libbpf_log_capture();
	if (test__start_subtest("map_excl_allowed"))
		test_map_excl_allowed();
	stop_libbpf_log_capture();
	if (test__start_subtest("map_excl_denied"))
		test_map_excl_denied();
	if (test__start_subtest("map_exclusive_outer_array"))
		test_map_exclusive_outer_array();
	if (test__start_subtest("map_exclusive_outer_htab"))
		test_map_exclusive_outer_htab();
	if (test__start_subtest("map_exclusive_inner"))
		test_map_exclusive_inner();
}
