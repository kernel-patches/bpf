// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <time.h>

#include "struct_ops_module.skel.h"

static void check_map_info(struct bpf_map_info *info)
{
	struct bpf_btf_info btf_info;
	char btf_name[256];
	u32 btf_info_len = sizeof(btf_info);
	int err, fd;

	fd = bpf_btf_get_fd_by_id(info->btf_vmlinux_id);
	if (!ASSERT_GE(fd, 0, "get_value_type_btf_obj_fd"))
		return;

	memset(&btf_info, 0, sizeof(btf_info));
	btf_info.name = ptr_to_u64(btf_name);
	btf_info.name_len = sizeof(btf_name);
	err = bpf_btf_get_info_by_fd(fd, &btf_info, &btf_info_len);
	if (!ASSERT_OK(err, "get_value_type_btf_obj_info"))
		goto cleanup;

	if (!ASSERT_EQ(strcmp(btf_name, "bpf_testmod"), 0, "get_value_type_btf_obj_name"))
		goto cleanup;

cleanup:
	close(fd);
}

static int attach_ops_and_check(struct struct_ops_module *skel,
				struct bpf_map *map,
				int expected_test_2_result)
{
	struct bpf_link *link;

	link = bpf_map__attach_struct_ops(map);
	ASSERT_OK_PTR(link, "attach_test_mod_1");
	if (!link)
		return -1;

	/* test_{1,2}() would be called from bpf_dummy_reg() in bpf_testmod.c */
	ASSERT_EQ(skel->bss->test_1_result, 0xdeadbeef, "test_1_result");
	ASSERT_EQ(skel->bss->test_2_result, expected_test_2_result, "test_2_result");

	bpf_link__destroy(link);
	return 0;
}

static void test_struct_ops_load(void)
{
	struct struct_ops_module *skel;
	struct bpf_map_info info = {};
	int err;
	u32 len;

	skel = struct_ops_module__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		return;

	skel->struct_ops.testmod_1->data = 13;
	skel->struct_ops.testmod_1->test_2 = skel->progs.test_3;
	/* Since test_2() is not being used, it should be disabled from
	 * auto-loading, or it will fail to load.
	 */
	bpf_program__set_autoload(skel->progs.test_2, false);

	err = struct_ops_module__load(skel);
	if (!ASSERT_OK(err, "struct_ops_module_load"))
		goto cleanup;

	len = sizeof(info);
	err = bpf_map_get_info_by_fd(bpf_map__fd(skel->maps.testmod_1), &info,
				     &len);
	if (!ASSERT_OK(err, "bpf_map_get_info_by_fd"))
		goto cleanup;

	check_map_info(&info);
	/* test_3() will be called from bpf_dummy_reg() in bpf_testmod.c
	 *
	 * In bpf_testmod.c it will pass 4 and 13 (the value of data) to
	 * .test_2.  So, the value of test_2_result should be 20 (4 + 13 +
	 * 3).
	 */
	if (!attach_ops_and_check(skel, skel->maps.testmod_1, 20))
		goto cleanup;
	if (!attach_ops_and_check(skel, skel->maps.testmod_2, 12))
		goto cleanup;

cleanup:
	struct_ops_module__destroy(skel);
}

static void test_struct_ops_not_zeroed(void)
{
	struct struct_ops_module *skel;
	int err;

	/* zeroed is 0, and zeroed_op is null */
	skel = struct_ops_module__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open"))
		return;

	err = struct_ops_module__load(skel);
	ASSERT_OK(err, "struct_ops_module_load");

	struct_ops_module__destroy(skel);

	/* zeroed is not 0 */
	skel = struct_ops_module__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open_not_zeroed"))
		return;

	/* libbpf should reject the testmod_zeroed since struct
	 * bpf_testmod_ops in the kernel has no "zeroed" field and the
	 * value of "zeroed" is non-zero.
	 */
	skel->struct_ops.testmod_zeroed->zeroed = 0xdeadbeef;
	err = struct_ops_module__load(skel);
	ASSERT_ERR(err, "struct_ops_module_load_not_zeroed");

	struct_ops_module__destroy(skel);

	/* zeroed_op is not null */
	skel = struct_ops_module__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open_not_zeroed_op"))
		return;

	/* libbpf should reject the testmod_zeroed since the value of its
	 * "zeroed_op" is not null.
	 */
	skel->struct_ops.testmod_zeroed->zeroed_op = skel->progs.test_3;
	err = struct_ops_module__load(skel);
	ASSERT_ERR(err, "struct_ops_module_load_not_zeroed_op");

	struct_ops_module__destroy(skel);
}

/* The signature of an implementation might not match the signature of the
 * function pointer prototype defined in the BPF program. This mismatch
 * should be allowed as long as the behavior of the operator program
 * adheres to the signature in the kernel. Libbpf should not enforce the
 * signature; rather, let the kernel verifier handle the enforcement.
 */
static void test_struct_ops_incompatible(void)
{
	struct struct_ops_module *skel;
	struct bpf_link *link;

	skel = struct_ops_module__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_incompatible);
	if (ASSERT_OK_PTR(link, "attach_struct_ops"))
		bpf_link__destroy(link);

	struct_ops_module__destroy(skel);
}

/* Applications should be able to open a pinned path of a struct_ops link
 * to get a file descriptor of the link and to update the link through the
 * file descriptor.
 */
static void test_struct_ops_pinning_and_open(void)
{
	DECLARE_LIBBPF_OPTS(bpf_link_update_opts, opts);
	struct struct_ops_module *skel;
	int err, link_fd = -1, map_fd;
	struct bpf_link *link;

	/* Create and pin a struct_ops link */
	skel = struct_ops_module__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_1);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		goto cleanup;

	err = bpf_link__pin(link, "/sys/fs/bpf/test_struct_ops_pinning");
	if (!ASSERT_OK(err, "bpf_link__pin"))
		goto cleanup;

	/* Open the pinned path */
	link_fd = open("/sys/fs/bpf/test_struct_ops_pinning", O_RDONLY);
	bpf_link__unpin(link);
	if (!ASSERT_GE(link_fd, 0, "open_pinned"))
		goto cleanup;

	skel->bss->test_1_result = 0;
	skel->bss->test_2_result = 0;

	map_fd = bpf_map__fd(skel->maps.testmod_1);
	if (!ASSERT_GE(map_fd, 0, "map_fd"))
		goto cleanup;

	/* Update the link. test_1 and test_2 should be called again. */
	err = bpf_link_update(link_fd, map_fd, &opts);
	if (!ASSERT_OK(err, "bpf_link_update"))
		goto cleanup;

	/* Check if test_1 and test_2 have been called */
	ASSERT_EQ(skel->bss->test_1_result, 0xdeadbeef,
		  "bpf_link_update_test_1_result");
	ASSERT_EQ(skel->bss->test_2_result, 5,
		  "bpf_link_update_test_2_result");

cleanup:
	close(link_fd);
	bpf_link__destroy(link);
	struct_ops_module__destroy(skel);
}

void serial_test_struct_ops_module(void)
{
	if (test__start_subtest("test_struct_ops_load"))
		test_struct_ops_load();
	if (test__start_subtest("test_struct_ops_not_zeroed"))
		test_struct_ops_not_zeroed();
	if (test__start_subtest("test_struct_ops_incompatible"))
		test_struct_ops_incompatible();
	if (test__start_subtest("test_struct_ops_pinning_and_open"))
		test_struct_ops_pinning_and_open();
}

