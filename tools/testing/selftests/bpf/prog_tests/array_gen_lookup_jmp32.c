// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Corporation. */

#include <test_progs.h>

/*
 * The inlined bpf_map_lookup_elem() for the array map flavors bounds the
 * index with an emitted compare against map->max_entries.  The compare
 * must be a 32-bit JGE: the index is zero-extended into a 64-bit register
 * and the immediate of a 64-bit JGE is sign-extended, so for a map with
 * max_entries >= 0x80000000 the 64-bit compare never fires and the inlined
 * code addresses the array out of bounds (70504de0bb62 fixed the same
 * emitted sequence in xsk_map_gen_lookup()).
 *
 * Triggering the bug needs a map with 0x80000000 entries, i.e. a 16 GiB
 * allocation, so check the emitted compare instead: a regression to the
 * 64-bit form makes the test fail.
 */

static char log_buf[16 * 1024];

/* Loads a program that inlines bpf_map_lookup_elem() on @map_fd and
 * returns 2 (XDP_PASS) when the element is found, 1 (XDP_DROP) when the
 * lookup returns NULL.
 */
static int load_lookup_prog(int map_fd, __u32 key)
{
	const struct bpf_insn insns[] = {
		BPF_LD_MAP_FD(BPF_REG_1, map_fd),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
		BPF_ST_MEM(BPF_W, BPF_REG_2, 0, key),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 2 /* XDP_PASS */),
		BPF_JMP_A(1),
		BPF_MOV64_IMM(BPF_REG_0, 1 /* XDP_DROP */),
		BPF_EXIT_INSN(),
	};
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		    .log_buf = log_buf,
		    .log_size = sizeof(log_buf),
		    .log_level = 1);
	int fd;

	fd = bpf_prog_load(BPF_PROG_TYPE_XDP, "gen_lookup_test", "GPL",
			   insns, ARRAY_SIZE(insns), &opts);
	if (fd < 0)
		fprintf(stderr, "load failed: %s\n", log_buf);
	return fd;
}

static void check_jmp32(int prog_fd, __u32 max_entries, const char *what)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info), len;
	struct bpf_insn *xlated;
	__u32 i, jge32 = 0, jge64 = 0;
	int err;

	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (!ASSERT_OK(err, "prog_get_info"))
		return;

	len = info.xlated_prog_len;
	xlated = calloc(1, len);
	if (!ASSERT_OK_PTR(xlated, "calloc xlated"))
		return;

	memset(&info, 0, sizeof(info));
	info.xlated_prog_len = len;
	info.xlated_prog_insns = ptr_to_u64(xlated);
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (!ASSERT_OK(err, "prog_get_info xlated"))
		goto out;

	for (i = 0; i + 1 < info.xlated_prog_len / (u32)sizeof(*xlated); i++) {
		if (xlated[i].code != (BPF_LDX | BPF_W | BPF_MEM))
			continue;
		if (xlated[i + 1].code != (BPF_JMP32 | BPF_JGE | BPF_K) &&
		    xlated[i + 1].code != (BPF_JMP | BPF_JGE | BPF_K))
			continue;
		/* The bounds check follows the index load and uses its result. */
		if (xlated[i + 1].dst_reg != xlated[i].dst_reg)
			continue;
		if (xlated[i + 1].imm != (int)max_entries)
			continue;

		if (xlated[i + 1].code == (BPF_JMP32 | BPF_JGE | BPF_K))
			jge32++;
		else
			jge64++;
	}

	ASSERT_EQ(jge64, 0, "no 64-bit JGE after index load");
	ASSERT_EQ(jge32, 1, what);

out:
	free(xlated);
}

static void run_lookup(int map_fd, __u32 key, bool expect_found)
{
	static char data[64];
	int prog_fd = load_lookup_prog(map_fd, key);

	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = data,
		    .data_size_in = sizeof(data));

	if (!ASSERT_GE(prog_fd, 0, "prog load"))
		return;

	if (!ASSERT_OK(bpf_prog_test_run_opts(prog_fd, &opts), "test_run"))
		goto out;

	if (expect_found)
		ASSERT_EQ(opts.retval, 2, "in-range lookup found");
	else
		ASSERT_EQ(opts.retval, 1, "out-of-range lookup NULL");

out:
	close(prog_fd);
}

void test_array_gen_lookup_jmp32(void)
{
	const __u32 max_entries = 4;
	LIBBPF_OPTS(bpf_map_create_opts, copts);
	LIBBPF_OPTS(bpf_map_create_opts, oopts);
	int map_fd = -1, pcpu_fd = -1, inner_fd = -1, outer_fd = -1, prog_fd;
	__u32 key = 1;
	__u64 val = 0x1234;

	/* The lookup is inlined only for 64-bit programs with the JIT on. */
	if (!is_jit_enabled() || sizeof(void *) != 8) {
		test__skip();
		return;
	}

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "arr", sizeof(__u32),
				sizeof(__u64), max_entries, &copts);
	if (!ASSERT_GE(map_fd, 0, "array map"))
		goto out;
	if (!ASSERT_OK(bpf_map_update_elem(map_fd, &key, &val, BPF_ANY),
		       "fill array"))
		goto out;

	pcpu_fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_ARRAY, "parr",
				 sizeof(__u32), sizeof(__u64), max_entries, &copts);
	if (!ASSERT_GE(pcpu_fd, 0, "percpu array map"))
		goto out;

	inner_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "inner", sizeof(__u32),
				  sizeof(__u64), 1, &copts);
	if (!ASSERT_GE(inner_fd, 0, "inner map"))
		goto out;

	oopts.inner_map_fd = inner_fd;
	outer_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, "aom",
				  sizeof(__u32), sizeof(__u32), max_entries,
				  &oopts);
	if (!ASSERT_GE(outer_fd, 0, "array of maps"))
		goto out;
	if (!ASSERT_OK(bpf_map_update_elem(outer_fd, &key, &inner_fd, BPF_ANY),
		       "fill array of maps"))
		goto out;

	prog_fd = load_lookup_prog(map_fd, key);
	if (!ASSERT_GE(prog_fd, 0, "load array prog"))
		goto out;
	check_jmp32(prog_fd, max_entries, "array gen_lookup uses JMP32 JGE");
	close(prog_fd);

	prog_fd = load_lookup_prog(pcpu_fd, key);
	if (!ASSERT_GE(prog_fd, 0, "load percpu prog"))
		goto out;
	check_jmp32(prog_fd, max_entries, "percpu gen_lookup uses JMP32 JGE");
	close(prog_fd);

	prog_fd = load_lookup_prog(outer_fd, key);
	if (!ASSERT_GE(prog_fd, 0, "load array of maps prog"))
		goto out;
	check_jmp32(prog_fd, max_entries, "array of maps gen_lookup uses JMP32 JGE");
	close(prog_fd);

	/* The inlined lookup still works, in range and out of range. */
	run_lookup(map_fd, key, true);
	run_lookup(map_fd, max_entries + 5, false);
	run_lookup(pcpu_fd, key, true);
	run_lookup(pcpu_fd, max_entries + 5, false);
	run_lookup(outer_fd, key, true);
	run_lookup(outer_fd, max_entries + 5, false);

out:
	if (outer_fd >= 0)
		close(outer_fd);
	if (inner_fd >= 0)
		close(inner_fd);
	if (pcpu_fd >= 0)
		close(pcpu_fd);
	if (map_fd >= 0)
		close(map_fd);
}