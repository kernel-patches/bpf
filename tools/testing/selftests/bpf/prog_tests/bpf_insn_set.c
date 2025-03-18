// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <test_progs.h>

static inline int map_create(__u32 map_type, __u32 max_entries)
{
	const char *map_name = "insn_set";
	__u32 key_size = 4;
	__u32 value_size = 4;

	return bpf_map_create(map_type, map_name, key_size, value_size, max_entries, NULL);
}

/*
 * Load a program, which will not be anyhow mangled by the verifier.  Add an
 * insn_set map pointing to every instruction. Check that it hasn't changed
 * after the program load.
 */
static void check_one_to_one_mapping(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++)
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &i, 0), 0, "bpf_map_update_elem"))
			goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		return;

	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		__u32 val;

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val, i, "val should be equal i");
	}

cleanup:
	close(prog_fd);
	close(map_fd);
}

/*
 * Try to load a program with a map which points to outside of the program
 */
static void check_out_of_bounds_index(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	int key, val;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, 1);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	key = 0;
	val = ARRAY_SIZE(insns); /* too big */
	if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &key, &val, 0), 0, "bpf_map_update_elem"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	errno = 0;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_EQ(prog_fd, -1, "program should have been rejected (prog_fd != -1)"))
		goto cleanup;
	if (!ASSERT_EQ(errno, EINVAL, "program should have been rejected (errno != EINVAL)"))
		goto cleanup;

cleanup:
	close(map_fd);
}

/*
 * Try to load a program with a map which points to the middle of 16-bit insn
 */
static void check_mid_insn_index(void)
{
	struct bpf_insn insns[] = {
		BPF_LD_IMM64(BPF_REG_0, 0), /* 2 x 8 */
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	int key, val;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, 1);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	key = 0;
	val = 1; /* middle of 16-byte instruction */
	if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &key, &val, 0), 0, "bpf_map_update_elem"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	errno = 0;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_EQ(prog_fd, -1, "program should have been rejected (prog_fd != -1)"))
		goto cleanup;
	if (!ASSERT_EQ(errno, EINVAL, "program should have been rejected (errno != EINVAL)"))
		goto cleanup;

cleanup:
	close(map_fd);
}

static void check_incorrect_index(void)
{
	check_out_of_bounds_index();
	check_mid_insn_index();
}

static void check_not_sorted(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	int i, val;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		val = ARRAY_SIZE(insns) - i - 1; /* reverse indexes */
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	errno = 0;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_EQ(prog_fd, -1, "program should have been rejected (prog_fd != -1)"))
		goto cleanup;
	if (!ASSERT_EQ(errno, EINVAL, "program should have been rejected (errno != EINVAL)"))
		goto cleanup;

cleanup:
	close(map_fd);
}

static void check_not_unique(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	int i, val;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		val = 1;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	errno = 0;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_EQ(prog_fd, -1, "program should have been rejected (prog_fd != -1)"))
		goto cleanup;
	if (!ASSERT_EQ(errno, EINVAL, "program should have been rejected (errno != EINVAL)"))
		goto cleanup;

cleanup:
	close(map_fd);
}

static void check_not_sorted_or_unique(void)
{
	check_not_sorted();
	check_not_unique();
}

/*
 * Load a program with two patches (get jiffies, for simplicity). Add an
 * insn_set map pointing to every instruction. Check how it was relocated
 * after the program load.
 */
static void check_relocate_simple(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	__u32 map_in[] = {0, 1, 2, 3, 4, 5};
	__u32 map_out[] = {0, 1, 4, 5, 8, 9};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++)
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &map_in[i], 0), 0,
			       "bpf_map_update_elem"))
			goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		return;

	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		__u32 val;

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val, map_out[i], "val should be equal map_out[i]");
	}

cleanup:
	close(prog_fd);
	close(map_fd);
}

/*
 * Verifier can delete code in two cases: nops & dead code. From the relocation
 * point of view, the two cases look the same, so test using the simplest
 * method: by loading some nops
 */
static void check_relocate_deletions(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	__u32 map_in[] = {0, 1, 2, 3, 4, 5};
	__u32 map_out[] = {0, -1, 1, -1, 2, 3};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++)
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &map_in[i], 0), 0,
			       "bpf_map_update_elem"))
			goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		return;

	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		__u32 val;

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val, map_out[i], "val should be equal map_out[i]");
	}

cleanup:
	close(prog_fd);
	close(map_fd);
}

static void check_relocate_with_functions(void)
{
	struct bpf_insn insns[] = {
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 1, 0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	__u32 map_in[] =  { 0, 1,  2, 3, 4, 5, /* func */  6, 7,  8, 9, 10};
	__u32 map_out[] = {-1, 0, -1, 3, 4, 5, /* func */ -1, 6, -1, 9, 10};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++)
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &map_in[i], 0), 0,
			       "bpf_map_update_elem"))
			goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		__u32 val;

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val, map_out[i], "val should be equal map_out[i]");
	}

cleanup:
	close(prog_fd);
	close(map_fd);
}

/* Once map was initialized, it should be frozen */
static void check_load_unfrozen_map(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++)
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &i, 0), 0, "bpf_map_update_elem"))
			goto cleanup;

	errno = 0;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_EQ(prog_fd, -1, "program should have been rejected (prog_fd != -1)"))
		goto cleanup;
	if (!ASSERT_EQ(errno, EINVAL, "program should have been rejected (errno != EINVAL)"))
		goto cleanup;

	/* cirrectness: now freeze the map, the program should load fine */

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		return;

	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		__u32 val;

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val, i, "val should be equal i");
	}

cleanup:
	close(prog_fd);
	close(map_fd);
}

/* Map can be used only by one BPF program */
static void check_no_map_reuse(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd, extra_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
		.fd_array = ptr_to_u64(&map_fd),
		.fd_array_cnt = 1,
	};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++)
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &i, 0), 0, "bpf_map_update_elem"))
			goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		return;

	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		__u32 val;

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val, i, "val should be equal i");
	}

	errno = 0;
	extra_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_EQ(extra_fd, -1, "program should have been rejected (extra_fd != -1)"))
		goto cleanup;
	if (!ASSERT_EQ(errno, EBUSY, "program should have been rejected (errno != EBUSY)"))
		goto cleanup;

	/* correctness: check that prog is still loadable without fd_array */
	attr.fd_array_cnt = 0;
	extra_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD): expected no error"))
		goto cleanup;
	close(extra_fd);

cleanup:
	close(prog_fd);
	close(map_fd);
}

static void check_bpf_no_lookup(void)
{
	struct bpf_insn insns[] = {
		BPF_LD_MAP_FD(BPF_REG_1, 0),
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		BPF_EXIT_INSN(),
	};
	int prog_fd, map_fd;
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
	};

	map_fd = map_create(BPF_MAP_TYPE_INSN_SET, 1);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	/* otherwise will be rejected as unfrozen */
	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		return;

	insns[0].imm = map_fd;

	errno = 0;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_EQ(prog_fd, -1, "program should have been rejected (prog_fd != -1)"))
		goto cleanup;
	if (!ASSERT_EQ(errno, EINVAL, "program should have been rejected (errno != EINVAL)"))
		goto cleanup;

	/* correctness: check that prog is still loadable with normal map */
	close(map_fd);
	map_fd = map_create(BPF_MAP_TYPE_ARRAY, 1);
	insns[0].imm = map_fd;
	prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

cleanup:
	close(prog_fd);
	close(map_fd);
}

static void check_bpf_side(void)
{
	check_bpf_no_lookup();
}

/* Test how relocations work */
void test_bpf_insn_set_reloc(void)
{
	if (test__start_subtest("one2one"))
		check_one_to_one_mapping();

	if (test__start_subtest("relocate-simple"))
		check_relocate_simple();

	if (test__start_subtest("relocate-deletions"))
		check_relocate_deletions();

	if (test__start_subtest("relocate-multiple-functions"))
		check_relocate_with_functions();
}

/* Check all kinds of operations and related restrictions */
void test_bpf_insn_set_ops(void)
{
	if (test__start_subtest("incorrect-index"))
		check_incorrect_index();

	if (test__start_subtest("not-sorted-or-unique"))
		check_not_sorted_or_unique();

	if (test__start_subtest("load-unfrozen-map"))
		check_load_unfrozen_map();

	if (test__start_subtest("no-map-reuse"))
		check_no_map_reuse();

	if (test__start_subtest("bpf-side-ops"))
		check_bpf_side();
}
