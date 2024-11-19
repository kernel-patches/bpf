// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include <linux/btf.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>

#include "../test_btf.h"

static inline int _bpf_map_create(void)
{
	static union bpf_attr attr = {
		.map_type = BPF_MAP_TYPE_ARRAY,
		.key_size = 4,
		.value_size = 8,
		.max_entries = 1,
	};

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int _btf_create(void)
{
	struct btf_blob {
		struct btf_header btf_hdr;
		__u32 types[8];
		__u32 str;
	} raw_btf = {
		.btf_hdr = {
			.magic = BTF_MAGIC,
			.version = BTF_VERSION,
			.hdr_len = sizeof(struct btf_header),
			.type_len = sizeof(raw_btf.types),
			.str_off = offsetof(struct btf_blob, str) - offsetof(struct btf_blob, types),
			.str_len = sizeof(raw_btf.str),
		},
		.types = {
			/* long */
			BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 64, 8),  /* [1] */
			/* unsigned long */
			BTF_TYPE_INT_ENC(0, 0, 0, 64, 8),  /* [2] */
		},
	};
	static union bpf_attr attr = {
		.btf_size = sizeof(raw_btf),
	};

	attr.btf = (long)&raw_btf;

	return syscall(__NR_bpf, BPF_BTF_LOAD, &attr, sizeof(attr));
}

static bool map_exists(__u32 id)
{
	int fd;

	fd = bpf_map_get_fd_by_id(id);
	if (fd >= 0) {
		close(fd);
		return true;
	}
	return false;
}

static inline int bpf_prog_get_map_ids(int prog_fd, __u32 *nr_map_ids, __u32 *map_ids)
{
	__u32 len = sizeof(struct bpf_prog_info);
	struct bpf_prog_info info = {
		.nr_map_ids = *nr_map_ids,
		.map_ids = ptr_to_u64(map_ids),
	};
	int err;

	err = bpf_prog_get_info_by_fd(prog_fd, &info, &len);
	if (!ASSERT_OK(err, "bpf_prog_get_info_by_fd"))
		return -1;

	*nr_map_ids = info.nr_map_ids;

	return 0;
}

static int __load_test_prog(int map_fd, int *fd_array, int fd_array_cnt)
{
	/* A trivial program which uses one map */
	struct bpf_insn insns[] = {
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(fd_array),
		.fd_array_cnt = fd_array_cnt,
	};

	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int load_test_prog(int *fd_array, int fd_array_cnt)
{
	int map_fd;
	int ret;

	map_fd = _bpf_map_create();
	if (!ASSERT_GE(map_fd, 0, "_bpf_map_create"))
		return map_fd;

	ret = __load_test_prog(map_fd, fd_array, fd_array_cnt);
	close(map_fd);

	/* switch back to returning the actual value */
	if (ret < 0)
		return -errno;
	return ret;
}

static bool check_expected_map_ids(int prog_fd, int expected, __u32 *map_ids, __u32 *nr_map_ids)
{
	int err;

	err = bpf_prog_get_map_ids(prog_fd, nr_map_ids, map_ids);
	if (!ASSERT_OK(err, "bpf_prog_get_map_ids"))
		return false;
	if (!ASSERT_EQ(*nr_map_ids, expected, "unexpected nr_map_ids"))
		return false;

	return true;
}

/*
 * Load a program, which uses one map. No fd_array maps are present.
 * On return only one map is expected to be bound to prog.
 */
static void check_fd_array_cnt__no_fd_array(void)
{
	__u32 map_ids[16];
	__u32 nr_map_ids;
	int prog_fd = -1;

	prog_fd = load_test_prog(NULL, 0);
	if (!ASSERT_GE(prog_fd, 0, "BPF_PROG_LOAD"))
		return;
	nr_map_ids = ARRAY_SIZE(map_ids);
	check_expected_map_ids(prog_fd, 1, map_ids, &nr_map_ids);
	close(prog_fd);
}

/*
 * Load a program, which uses one map, and pass two extra, non-equal, maps in
 * fd_array with fd_array_cnt=2. On return three maps are expected to be bound
 * to the program.
 */
static void check_fd_array_cnt__fd_array_ok(void)
{
	int extra_fds[2] = { -1, -1 };
	__u32 map_ids[16];
	__u32 nr_map_ids;
	int prog_fd = -1;

	extra_fds[0] = _bpf_map_create();
	if (!ASSERT_GE(extra_fds[0], 0, "_bpf_map_create"))
		goto cleanup;
	extra_fds[1] = _bpf_map_create();
	if (!ASSERT_GE(extra_fds[1], 0, "_bpf_map_create"))
		goto cleanup;
	prog_fd = load_test_prog(extra_fds, 2);
	if (!ASSERT_GE(prog_fd, 0, "BPF_PROG_LOAD"))
		goto cleanup;
	nr_map_ids = ARRAY_SIZE(map_ids);
	if (!check_expected_map_ids(prog_fd, 3, map_ids, &nr_map_ids))
		goto cleanup;

	/* maps should still exist when original file descriptors are closed */
	close(extra_fds[0]);
	close(extra_fds[1]);
	if (!ASSERT_EQ(map_exists(map_ids[0]), true, "map_ids[0] should exist"))
		goto cleanup;
	if (!ASSERT_EQ(map_exists(map_ids[1]), true, "map_ids[1] should exist"))
		goto cleanup;

	/* some fds might be invalid, so ignore return codes */
cleanup:
	close(extra_fds[1]);
	close(extra_fds[0]);
	close(prog_fd);
}

/*
 * Load a program with a few extra maps duplicated in the fd_array.
 * After the load maps should only be referenced once.
 */
static void check_fd_array_cnt__duplicated_maps(void)
{
	int extra_fds[4] = { -1, -1, -1, -1 };
	__u32 map_ids[16];
	__u32 nr_map_ids;
	int prog_fd = -1;

	extra_fds[0] = extra_fds[2] = _bpf_map_create();
	if (!ASSERT_GE(extra_fds[0], 0, "_bpf_map_create"))
		goto cleanup;
	extra_fds[1] = extra_fds[3] = _bpf_map_create();
	if (!ASSERT_GE(extra_fds[1], 0, "_bpf_map_create"))
		goto cleanup;
	prog_fd = load_test_prog(extra_fds, 4);
	if (!ASSERT_GE(prog_fd, 0, "BPF_PROG_LOAD"))
		goto cleanup;
	nr_map_ids = ARRAY_SIZE(map_ids);
	if (!check_expected_map_ids(prog_fd, 3, map_ids, &nr_map_ids))
		goto cleanup;

	/* maps should still exist when original file descriptors are closed */
	close(extra_fds[0]);
	close(extra_fds[1]);
	if (!ASSERT_EQ(map_exists(map_ids[0]), true, "map should exist"))
		goto cleanup;
	if (!ASSERT_EQ(map_exists(map_ids[1]), true, "map should exist"))
		goto cleanup;

	/* some fds might be invalid, so ignore return codes */
cleanup:
	close(extra_fds[1]);
	close(extra_fds[0]);
	close(prog_fd);
}

/*
 * Check that if maps which are referenced by a program are
 * passed in fd_array, then they will be referenced only once
 */
static void check_fd_array_cnt__referenced_maps_in_fd_array(void)
{
	int extra_fds[1] = { -1 };
	__u32 map_ids[16];
	__u32 nr_map_ids;
	int prog_fd = -1;

	extra_fds[0] = _bpf_map_create();
	if (!ASSERT_GE(extra_fds[0], 0, "_bpf_map_create"))
		goto cleanup;
	prog_fd = __load_test_prog(extra_fds[0], extra_fds, 1);
	if (!ASSERT_GE(prog_fd, 0, "BPF_PROG_LOAD"))
		goto cleanup;
	nr_map_ids = ARRAY_SIZE(map_ids);
	if (!check_expected_map_ids(prog_fd, 1, map_ids, &nr_map_ids))
		goto cleanup;

	/* map should still exist when original file descriptor is closed */
	close(extra_fds[0]);
	if (!ASSERT_EQ(map_exists(map_ids[0]), true, "map should exist"))
		goto cleanup;

	/* some fds might be invalid, so ignore return codes */
cleanup:
	close(extra_fds[0]);
	close(prog_fd);
}

/*
 * Test that a program with trash in fd_array can't be loaded:
 * only map and BTF file descriptors should be accepted.
 */
static void check_fd_array_cnt__fd_array_with_trash(void)
{
	int extra_fds[3] = { -1, -1, -1 };
	int prog_fd = -1;

	extra_fds[0] = _bpf_map_create();
	if (!ASSERT_GE(extra_fds[0], 0, "_bpf_map_create"))
		goto cleanup;
	extra_fds[1] = _btf_create();
	if (!ASSERT_GE(extra_fds[1], 0, "_btf_create"))
		goto cleanup;

	/* trash 1: not a file descriptor */
	extra_fds[2] = 0xbeef;
	prog_fd = load_test_prog(extra_fds, 3);
	if (!ASSERT_EQ(prog_fd, -EBADF, "prog should have been rejected with -EBADF"))
		goto cleanup;

	/* trash 2: not a map or btf */
	extra_fds[2] = socket(AF_INET, SOCK_STREAM, 0);
	if (!ASSERT_GE(extra_fds[2], 0, "socket"))
		goto cleanup;

	prog_fd = load_test_prog(extra_fds, 3);
	if (!ASSERT_EQ(prog_fd, -EINVAL, "prog should have been rejected with -EINVAL"))
		goto cleanup;

	/* some fds might be invalid, so ignore return codes */
cleanup:
	close(extra_fds[2]);
	close(extra_fds[1]);
	close(extra_fds[0]);
}

/*
 * Test that a program with zeroes (= holes) in fd_array can be loaded:
 * only map and BTF file descriptors should be accepted.
 */
static void check_fd_array_cnt__fd_array_with_holes(void)
{
	int extra_fds[4] = { -1, -1, -1, -1 };
	int prog_fd = -1;

	extra_fds[0] = _bpf_map_create();
	if (!ASSERT_GE(extra_fds[0], 0, "_bpf_map_create"))
		goto cleanup;
	/* punch a hole*/
	extra_fds[1] = 0;
	extra_fds[2] = _btf_create();
	if (!ASSERT_GE(extra_fds[1], 0, "_btf_create"))
		goto cleanup;
	/* punch a hole*/
	extra_fds[3] = 0;

	prog_fd = load_test_prog(extra_fds, 4);
	ASSERT_GE(prog_fd, 0, "prog with holes should have been loaded");

	/* some fds might be invalid, so ignore return codes */
cleanup:
	close(extra_fds[2]);
	close(extra_fds[0]);
	close(prog_fd);
}

/*
 * Test that a program with too big fd_array can't be loaded.
 */
static void check_fd_array_cnt__fd_array_too_big(void)
{
	int extra_fds[65];
	int prog_fd = -1;
	int i;

	for (i = 0; i < 65; i++) {
		extra_fds[i] = _bpf_map_create();
		if (!ASSERT_GE(extra_fds[i], 0, "_bpf_map_create"))
			goto cleanup_fds;
	}

	prog_fd = load_test_prog(extra_fds, 65);
	ASSERT_EQ(prog_fd, -E2BIG, "prog should have been rejected with -E2BIG");

cleanup_fds:
	while (i > 0)
		close(extra_fds[--i]);
}

void test_fd_array_cnt(void)
{
	if (test__start_subtest("no-fd-array"))
		check_fd_array_cnt__no_fd_array();

	if (test__start_subtest("fd-array-ok"))
		check_fd_array_cnt__fd_array_ok();

	if (test__start_subtest("fd-array-dup-input"))
		check_fd_array_cnt__duplicated_maps();

	if (test__start_subtest("fd-array-ref-maps-in-array"))
		check_fd_array_cnt__referenced_maps_in_fd_array();

	if (test__start_subtest("fd-array-trash-input"))
		check_fd_array_cnt__fd_array_with_trash();

	if (test__start_subtest("fd-array-with-holes"))
		check_fd_array_cnt__fd_array_with_holes();

	if (test__start_subtest("fd-array-2big"))
		check_fd_array_cnt__fd_array_too_big();
}
