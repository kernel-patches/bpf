// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <test_progs.h>

#if defined(__x86_64__) || defined(__powerpc__) || defined(__aarch64__)
static int map_create(__u32 map_type, __u32 max_entries)
{
	const char *map_name = "insn_array";
	__u32 key_size = 4;
	__u32 value_size = sizeof(struct bpf_insn_array_value);

	return bpf_map_create(map_type, map_name, key_size, value_size, max_entries, NULL);
}

static int prog_load(struct bpf_insn *insns, __u32 insn_cnt, int *fd_array, __u32 fd_array_cnt)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts);

	opts.fd_array = fd_array;
	opts.fd_array_cnt = fd_array_cnt;

	return bpf_prog_load(BPF_PROG_TYPE_XDP, NULL, "GPL", insns, insn_cnt, &opts);
}

static void __check_success(struct bpf_insn *insns, __u32 insn_cnt, __u32 *map_in, __u32 *map_out)
{
	struct bpf_insn_array_value val = {};
	int prog_fd = -1, map_fd, i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, insn_cnt);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < insn_cnt; i++) {
		val.orig_off = map_in[i];
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, insn_cnt, &map_fd, 1);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < insn_cnt; i++) {
		char buf[64];

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		snprintf(buf, sizeof(buf), "val.xlated_off should be equal map_out[%d]", i);
		ASSERT_EQ(val.xlated_off, map_out[i], buf);
	}

cleanup:
	close(prog_fd);
	close(map_fd);
}

/*
 * Load a program, which will not be anyhow mangled by the verifier.  Add an
 * insn_array map pointing to every instruction. Check that it hasn't changed
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
	__u32 map_in[] = {0, 1, 2, 3, 4, 5};
	__u32 map_out[] = {0, 1, 2, 3, 4, 5};

	__check_success(insns, ARRAY_SIZE(insns), map_in, map_out);
}

/*
 * Load a program with two patches (get jiffies, for simplicity). Add an
 * insn_array map pointing to every instruction. Check how it was changed
 * after the program load.
 */
static void check_simple(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_jiffies64),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	__u32 map_in[] = {0, 1, 2, 3, 4, 5};
	__u32 map_out[] = {0, 1, 4, 5, 8, 9};

	__check_success(insns, ARRAY_SIZE(insns), map_in, map_out);
}

/*
 * Verifier can delete code in two cases: nops & dead code. From insn
 * array's point of view, the two cases are the same, so test using
 * the simplest method: by loading some nops
 */
static void check_deletions(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, 0), /* nop */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	__u32 map_in[] = {0, 1, 2, 3, 4, 5};
	__u32 map_out[] = {0, -1, 1, -1, 2, 3};

	__check_success(insns, ARRAY_SIZE(insns), map_in, map_out);
}

/*
 * Same test as check_deletions, but also add code which adds instructions
 */
static void check_deletions_with_functions(void)
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
	__u32 map_in[] =  { 0, 1,  2, 3, 4, 5, /* func */  6, 7,  8, 9, 10};
	__u32 map_out[] = {-1, 0, -1, 3, 4, 5, /* func */ -1, 6, -1, 9, 10};

	__check_success(insns, ARRAY_SIZE(insns), map_in, map_out);
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
	struct bpf_insn_array_value val = {};
	int key;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, 1);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	key = 0;
	val.orig_off = ARRAY_SIZE(insns); /* too big */
	if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &key, &val, 0), 0, "bpf_map_update_elem"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_EQ(prog_fd, -EINVAL, "program should have been rejected (prog_fd != -EINVAL)")) {
		close(prog_fd);
		goto cleanup;
	}

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
	struct bpf_insn_array_value val = {};
	int key;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, 1);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	key = 0;
	val.orig_off = 1; /* middle of 16-byte instruction */
	if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &key, &val, 0), 0, "bpf_map_update_elem"))
		goto cleanup;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_EQ(prog_fd, -EINVAL, "program should have been rejected (prog_fd != -EINVAL)")) {
		close(prog_fd);
		goto cleanup;
	}

cleanup:
	close(map_fd);
}

static void check_incorrect_index(void)
{
	check_out_of_bounds_index();
	check_mid_insn_index();
}

static int set_bpf_jit_harden(char *level)
{
	char old_level;
	int err = -1;
	int fd = -1;

	fd = open("/proc/sys/net/core/bpf_jit_harden", O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		ASSERT_FAIL("open .../bpf_jit_harden returned %d (errno=%d)", fd, errno);
		return -1;
	}

	err = read(fd, &old_level, 1);
	if (err != 1) {
		ASSERT_FAIL("read from .../bpf_jit_harden returned %d (errno=%d)", err, errno);
		err = -1;
		goto end;
	}

	lseek(fd, 0, SEEK_SET);

	err = write(fd, level, 1);
	if (err != 1) {
		ASSERT_FAIL("write to .../bpf_jit_harden returned %d (errno=%d)", err, errno);
		err = -1;
		goto end;
	}

	err = 0;
	*level = old_level;
end:
	if (fd >= 0)
		close(fd);
	return err;
}

static void check_blindness(void)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 4),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	};
	int prog_fd = -1, map_fd;
	struct bpf_insn_array_value val = {};
	char bpf_jit_harden = '@'; /* non-exizsting value */
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		val.orig_off = i;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	bpf_jit_harden = '2';
	if (set_bpf_jit_harden(&bpf_jit_harden)) {
		bpf_jit_harden = '@'; /* open, read or write failed => no write was done */
		goto cleanup;
	}

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		char fmt[32];

		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		snprintf(fmt, sizeof(fmt), "val should be equal 3*%d", i);
		ASSERT_EQ(val.xlated_off, i * 3, fmt);
	}

cleanup:
	/* restore the old one */
	if (bpf_jit_harden != '@')
		set_bpf_jit_harden(&bpf_jit_harden);

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
	int prog_fd = -1, map_fd;
	struct bpf_insn_array_value val = {};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		val.orig_off = i;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_EQ(prog_fd, -EINVAL, "program should have been rejected (prog_fd != -EINVAL)"))
		goto cleanup;

	/* correctness: now freeze the map, the program should load fine */

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val.xlated_off, i, "val should be equal i");
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
	int prog_fd = -1, map_fd, extra_fd = -1;
	struct bpf_insn_array_value val = {};
	int i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, ARRAY_SIZE(insns));
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		val.orig_off = i;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0, "bpf_map_update_elem"))
			goto cleanup;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(insns); i++) {
		if (!ASSERT_EQ(bpf_map_lookup_elem(map_fd, &i, &val), 0, "bpf_map_lookup_elem"))
			goto cleanup;

		ASSERT_EQ(val.xlated_off, i, "val should be equal i");
	}

	extra_fd = prog_load(insns, ARRAY_SIZE(insns), &map_fd, 1);
	if (!ASSERT_EQ(extra_fd, -EBUSY, "program should have been rejected (extra_fd != -EBUSY)"))
		goto cleanup;

	/* correctness: check that prog is still loadable without fd_array */
	extra_fd = prog_load(insns, ARRAY_SIZE(insns), NULL, 0);
	if (!ASSERT_GE(extra_fd, 0, "bpf(BPF_PROG_LOAD): expected no error"))
		goto cleanup;

cleanup:
	close(extra_fd);
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
	int prog_fd = -1, map_fd;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, 1);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;

	insns[0].imm = map_fd;

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto cleanup;

	prog_fd = prog_load(insns, ARRAY_SIZE(insns), NULL, 0);
	if (!ASSERT_EQ(prog_fd, -EINVAL, "program should have been rejected (prog_fd != -EINVAL)"))
		goto cleanup;

	/* correctness: check that prog is still loadable with normal map */
	close(map_fd);
	map_fd = map_create(BPF_MAP_TYPE_ARRAY, 1);
	insns[0].imm = map_fd;
	prog_fd = prog_load(insns, ARRAY_SIZE(insns), NULL, 0);
	if (!ASSERT_GE(prog_fd, 0, "bpf(BPF_PROG_LOAD)"))
		goto cleanup;

cleanup:
	close(prog_fd);
	close(map_fd);
}

#define GOTOX_CNT_AT_LIMIT	1000
#define GOTOX_LOG_SZ		(256 * 1024)

static const char gotox_limit_msg[] =
	"number of indirect jump edges in the program exceeds";

static int gotox_jt_create(__u32 first_gotox, __u32 gotox_cnt)
{
	/* the run of gotox itself, plus the exit block right after it */
	const __u32 jt_cnt = gotox_cnt + 1;
	struct bpf_insn_array_value val = {};
	int map_fd;
	__u32 i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, jt_cnt);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return map_fd;

	for (i = 0; i < jt_cnt; i++) {
		val.orig_off = first_gotox + i;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0,
			       "bpf_map_update_elem"))
			goto err;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto err;

	return map_fd;
err:
	close(map_fd);
	return -1;
}

static int gotox_prog_load_funcs(struct bpf_insn *insns, __u32 insn_cnt,
				 int *fd_array, __u32 fd_array_cnt, char *log,
				 int btf_fd, struct bpf_func_info *fi, __u32 fi_cnt)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts);
	int prog_fd;

	log[0] = 0;
	opts.fd_array = fd_array;
	opts.fd_array_cnt = fd_array_cnt;
	opts.log_buf = log;
	opts.log_size = GOTOX_LOG_SZ;
	opts.log_level = 1;
	if (fi_cnt) {
		opts.prog_btf_fd = btf_fd;
		opts.func_info = fi;
		opts.func_info_cnt = fi_cnt;
		opts.func_info_rec_size = sizeof(*fi);
	}

	prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP, NULL, "GPL", insns, insn_cnt, &opts);
	if (prog_fd >= 0) {
		close(prog_fd);
		return 0;
	}
	return prog_fd;
}

static int gotox_prog_load(struct bpf_insn *insns, __u32 insn_cnt,
			   int *fd_array, __u32 fd_array_cnt, char *log)
{
	return gotox_prog_load_funcs(insns, insn_cnt, fd_array, fd_array_cnt, log,
				     -1, NULL, 0);
}

/* Fill in 'r1 = 0; gotox_cnt x gotox r1' at 'insns'. */
static void gotox_run_fill(struct bpf_insn *insns, __u32 gotox_cnt)
{
	__u32 i;

	insns[0] = BPF_MOV64_IMM(BPF_REG_1, 0);
	for (i = 1; i <= gotox_cnt; i++)
		insns[i] = BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_1, 0, 0, 0);
}

static void check_gotox_limit_hit(const char *log, int err)
{
	ASSERT_EQ(err, -E2BIG, "program should have been rejected");
	ASSERT_HAS_SUBSTR(log, gotox_limit_msg, "verifier log");
}

static bool try_load_gotox_prog(__u32 gotox_cnt, char *log, int *err)
{
	const __u32 insn_cnt = gotox_cnt + 3;
	struct bpf_insn *insns;
	bool attempted = false;
	int map_fd;

	insns = calloc(insn_cnt, sizeof(*insns));
	if (!ASSERT_OK_PTR(insns, "calloc insns"))
		return false;

	gotox_run_fill(insns, gotox_cnt);
	insns[gotox_cnt + 1] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[gotox_cnt + 2] = BPF_EXIT_INSN();

	map_fd = gotox_jt_create(1, gotox_cnt);
	if (map_fd < 0)
		goto free_insns;

	*err = gotox_prog_load(insns, insn_cnt, &map_fd, 1, log);
	close(map_fd);
	attempted = true;
free_insns:
	free(insns);
	return attempted;
}

/*
 * The extra exit target in the jump table makes for gotox_cnt * (gotox_cnt
 * + 1) edges, hence the program is over the limit by gotox_cnt edges.
 */
static void check_too_many_gotox_edges(void)
{
	const __u32 gotox_cnt = GOTOX_CNT_AT_LIMIT;
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	if (try_load_gotox_prog(gotox_cnt, log, &err))
		check_gotox_limit_hit(log, err);

	free(log);
}

/*
 * A chain of blocks, where block k loads jt[k] and jumps to it. The jump
 * table holds the starts of the blocks that follow plus the exit block,
 * which is gotox_cnt targets for gotox_cnt gotox, so the program sits
 * exactly at the limit and must still load.
 */
#define GOTOX_BLOCK_SZ		4

static void gotox_chain_fill(struct bpf_insn *insns, __u32 gotox_cnt)
{
	struct bpf_insn *at;
	__u32 k;

	for (k = 0; k < gotox_cnt; k++) {
		at = insns + k * GOTOX_BLOCK_SZ;

		/* r1 = &jt[0], by index 0 into fd_array */
		at[0] = (struct bpf_insn) {
			.code = BPF_LD | BPF_DW | BPF_IMM,
			.dst_reg = BPF_REG_1,
			.src_reg = BPF_PSEUDO_MAP_IDX_VALUE,
			.imm = 0,
		};
		at[1] = (struct bpf_insn) { .imm = 0 };
		at[2] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, k * 8);
		at[3] = BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_1, 0, 0, 0);
	}

	insns[gotox_cnt * GOTOX_BLOCK_SZ] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[gotox_cnt * GOTOX_BLOCK_SZ + 1] = BPF_EXIT_INSN();
}

static int gotox_chain_jt_create(__u32 gotox_cnt)
{
	struct bpf_insn_array_value val = {};
	int map_fd;
	__u32 i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, gotox_cnt);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return map_fd;

	for (i = 0; i < gotox_cnt; i++) {
		val.orig_off = (i + 1) * GOTOX_BLOCK_SZ;
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0,
			       "bpf_map_update_elem"))
			goto err;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto err;

	return map_fd;
err:
	close(map_fd);
	return -1;
}

static void check_gotox_edges_at_limit(void)
{
	const __u32 gotox_cnt = GOTOX_CNT_AT_LIMIT;
	const __u32 insn_cnt = gotox_cnt * GOTOX_BLOCK_SZ + 2;
	struct bpf_insn *insns;
	char *log;
	int map_fd, err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	insns = calloc(insn_cnt, sizeof(*insns));
	if (!ASSERT_OK_PTR(insns, "calloc insns"))
		goto free_log;

	gotox_chain_fill(insns, gotox_cnt);

	map_fd = gotox_chain_jt_create(gotox_cnt);
	if (map_fd < 0)
		goto free_insns;

	err = gotox_prog_load(insns, insn_cnt, &map_fd, 1, log);
	close(map_fd);

	if (!ASSERT_OK(err, "program at the edge limit should load"))
		fprintf(stderr, "verifier log: %s\n", log);

free_insns:
	free(insns);
free_log:
	free(log);
}

static void check_gotox_edges_across_subprogs(void)
{
	const __u32 gotox_cnt = GOTOX_CNT_AT_LIMIT * 3 / 4;
	const __u32 sub_start = gotox_cnt + 3;
	const __u32 insn_cnt = 2 * (gotox_cnt + 3);
	int map_fd[2] = { -1, -1 };
	struct bpf_insn *insns;
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	insns = calloc(insn_cnt, sizeof(*insns));
	if (!ASSERT_OK_PTR(insns, "calloc insns"))
		goto free_log;

	gotox_run_fill(insns, gotox_cnt);
	insns[gotox_cnt + 1] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0,
					    BPF_PSEUDO_CALL, 0,
					    sub_start - (gotox_cnt + 1) - 1);
	insns[gotox_cnt + 2] = BPF_EXIT_INSN();

	gotox_run_fill(insns + sub_start, gotox_cnt);
	insns[sub_start + gotox_cnt + 1] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[sub_start + gotox_cnt + 2] = BPF_EXIT_INSN();

	map_fd[0] = gotox_jt_create(1, gotox_cnt);
	if (map_fd[0] < 0)
		goto free_insns;
	map_fd[1] = gotox_jt_create(sub_start + 1, gotox_cnt);
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, insn_cnt, map_fd, 2, log);
	check_gotox_limit_hit(log, err);

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_insns:
	free(insns);
free_log:
	free(log);
}

static int gotox_jt_create_offs(const __u32 *offs, __u32 cnt)
{
	struct bpf_insn_array_value val = {};
	int map_fd;
	__u32 i;

	map_fd = map_create(BPF_MAP_TYPE_INSN_ARRAY, cnt);
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return map_fd;

	for (i = 0; i < cnt; i++) {
		val.orig_off = offs[i];
		if (!ASSERT_EQ(bpf_map_update_elem(map_fd, &i, &val, 0), 0,
			       "bpf_map_update_elem"))
			goto err;
	}

	if (!ASSERT_EQ(bpf_map_freeze(map_fd), 0, "bpf_map_freeze"))
		goto err;

	return map_fd;
err:
	close(map_fd);
	return -1;
}

#define GOTOX_SUB_START		4
#define GOTOX_MAIN_TGT		2
#define GOTOX_SUB_TGT		8
#define GOTOX_TWO_INSN_CNT	10

static void gotox_two_subprogs_fill(struct bpf_insn *insns, __u32 jt_idx, __u32 jt_off)
{
	insns[0] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[1] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0,
				GOTOX_SUB_START - 1 - 1);
	insns[GOTOX_MAIN_TGT] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[3] = BPF_EXIT_INSN();

	/* r1 = &jt[0], by index 'jt_idx' into fd_array */
	insns[GOTOX_SUB_START] = (struct bpf_insn) {
		.code = BPF_LD | BPF_DW | BPF_IMM,
		.dst_reg = BPF_REG_1,
		.src_reg = BPF_PSEUDO_MAP_IDX_VALUE,
		.imm = jt_idx,
	};
	insns[GOTOX_SUB_START + 1] = (struct bpf_insn) { .imm = 0 };
	insns[6] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, jt_off * 8);
	insns[7] = BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_1, 0, 0, 0);
	insns[GOTOX_SUB_TGT] = BPF_MOV64_IMM(BPF_REG_0, 1);
	insns[9] = BPF_EXIT_INSN();
}

/*
 * An insn_array map is not necessarily a jump table: one that tracks
 * instruction offsets covers the whole program and is of no subprog. Such a
 * map must not keep a program with a gotox elsewhere from loading.
 */
static void check_gotox_tracker_map(void)
{
	const __u32 jt_track[] = { 0, GOTOX_MAIN_TGT, GOTOX_SUB_TGT };
	const __u32 jt_sub[] = { GOTOX_SUB_TGT };
	struct bpf_insn insns[GOTOX_TWO_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_two_subprogs_fill(insns, 1, 0);

	map_fd[0] = gotox_jt_create_offs(jt_track, ARRAY_SIZE(jt_track));
	if (map_fd[0] < 0)
		goto free_log;
	map_fd[1] = gotox_jt_create_offs(jt_sub, ARRAY_SIZE(jt_sub));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, ARRAY_SIZE(insns), map_fd, 2, log);
	if (!ASSERT_OK(err, "program with a tracking map should load"))
		fprintf(stderr, "verifier log: %s\n", log);

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_log:
	free(log);
}

static void check_gotox_target_other_subprog(void)
{
	const __u32 jt_main[] = { GOTOX_MAIN_TGT };
	const __u32 jt_sub[] = { GOTOX_SUB_TGT };
	struct bpf_insn insns[GOTOX_TWO_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_two_subprogs_fill(insns, 0, 0);

	map_fd[0] = gotox_jt_create_offs(jt_main, ARRAY_SIZE(jt_main));
	if (map_fd[0] < 0)
		goto free_log;
	map_fd[1] = gotox_jt_create_offs(jt_sub, ARRAY_SIZE(jt_sub));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, ARRAY_SIZE(insns), map_fd, 2, log);
	ASSERT_EQ(err, -EINVAL, "program should have been rejected");
	ASSERT_HAS_SUBSTR(log, "indirect jump from insn 7 to 2 leaves the subprog [4,10)",
			  "verifier log");

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_log:
	free(log);
}

static void check_gotox_jt_per_subprog(void)
{
	const __u32 jt_main[] = { GOTOX_MAIN_TGT };
	const __u32 jt_sub[] = { GOTOX_SUB_TGT };
	struct bpf_insn insns[GOTOX_TWO_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_two_subprogs_fill(insns, 1, 0);

	map_fd[0] = gotox_jt_create_offs(jt_main, ARRAY_SIZE(jt_main));
	if (map_fd[0] < 0)
		goto free_log;
	map_fd[1] = gotox_jt_create_offs(jt_sub, ARRAY_SIZE(jt_sub));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, ARRAY_SIZE(insns), map_fd, 2, log);
	ASSERT_EQ(err, 0, "bpf(BPF_PROG_LOAD)");

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_log:
	free(log);
}

/*
 * The spanning map is of no subprog and is dropped, and the entry the gotox
 * register can reach is in the subprog of the gotox and in the jump table the
 * CFG walked, so nothing unsafe is left and the program loads.
 */
static void check_gotox_span_unreached_entry(void)
{
	const __u32 jt_span[] = { GOTOX_MAIN_TGT, GOTOX_SUB_TGT };
	const __u32 jt_sub[] = { GOTOX_SUB_TGT };
	struct bpf_insn insns[GOTOX_TWO_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_two_subprogs_fill(insns, 0, 1);

	map_fd[0] = gotox_jt_create_offs(jt_span, ARRAY_SIZE(jt_span));
	if (map_fd[0] < 0)
		goto free_log;
	map_fd[1] = gotox_jt_create_offs(jt_sub, ARRAY_SIZE(jt_sub));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, ARRAY_SIZE(insns), map_fd, 2, log);
	if (!ASSERT_OK(err, "program with an unreachable spanning entry should load"))
		fprintf(stderr, "verifier log: %s\n", log);

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_log:
	free(log);
}

#define GOTOX_FWD_GOTOX		11
#define GOTOX_FWD_OWN_TGT	12
#define GOTOX_FWD_SUB_START	14
#define GOTOX_FWD_INSN_CNT	16

static void gotox_from_main_fill(struct bpf_insn *insns)
{
	insns[0] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);
	insns[1] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0,
				GOTOX_FWD_SUB_START - 1 - 1);
	insns[2] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6,
			       offsetof(struct xdp_md, ingress_ifindex));
	insns[3] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, 0, 4);

	/* r1 = &jt_leaves[0], by index 1 into fd_array */
	insns[4] = (struct bpf_insn) {
		.code = BPF_LD | BPF_DW | BPF_IMM,
		.dst_reg = BPF_REG_1,
		.src_reg = BPF_PSEUDO_MAP_IDX_VALUE,
		.imm = 1,
	};
	insns[5] = (struct bpf_insn) { .imm = 0 };
	insns[6] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);
	insns[7] = BPF_JMP_A(3);

	/* r1 = &jt_own[0], by index 0 into fd_array */
	insns[8] = (struct bpf_insn) {
		.code = BPF_LD | BPF_DW | BPF_IMM,
		.dst_reg = BPF_REG_1,
		.src_reg = BPF_PSEUDO_MAP_IDX_VALUE,
		.imm = 0,
	};
	insns[9] = (struct bpf_insn) { .imm = 0 };
	insns[10] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);

	insns[GOTOX_FWD_GOTOX] = BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_1, 0, 0, 0);
	insns[GOTOX_FWD_OWN_TGT] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[13] = BPF_EXIT_INSN();
	insns[GOTOX_FWD_SUB_START] = BPF_MOV64_IMM(BPF_REG_0, 1);
	insns[15] = BPF_EXIT_INSN();
}

static void check_gotox_target_subprog_from_main(void)
{
	const __u32 jt_own[] = { GOTOX_FWD_OWN_TGT };
	const __u32 jt_leaves[] = { GOTOX_FWD_SUB_START };
	struct bpf_insn insns[GOTOX_FWD_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_from_main_fill(insns);

	map_fd[0] = gotox_jt_create_offs(jt_own, ARRAY_SIZE(jt_own));
	if (map_fd[0] < 0)
		goto free_log;
	map_fd[1] = gotox_jt_create_offs(jt_leaves, ARRAY_SIZE(jt_leaves));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, ARRAY_SIZE(insns), map_fd, 2, log);
	ASSERT_EQ(err, -EINVAL, "program should have been rejected");
	ASSERT_HAS_SUBSTR(log, "indirect jump from insn 11 to 14 leaves the subprog [0,14)",
			  "verifier log");

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_log:
	free(log);
}

/*
 * The only map of the subprog holding the gotox reaches past that subprog, so
 * the subprog is left without a jump table at all.
 */
static void check_gotox_jt_spans_subprogs(void)
{
	const __u32 jt_span[] = { GOTOX_FWD_OWN_TGT, GOTOX_FWD_SUB_START };
	const __u32 jt_leaves[] = { GOTOX_FWD_SUB_START };
	struct bpf_insn insns[GOTOX_FWD_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_from_main_fill(insns);

	map_fd[0] = gotox_jt_create_offs(jt_span, ARRAY_SIZE(jt_span));
	if (map_fd[0] < 0)
		goto free_log;
	map_fd[1] = gotox_jt_create_offs(jt_leaves, ARRAY_SIZE(jt_leaves));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, ARRAY_SIZE(insns), map_fd, 2, log);
	ASSERT_EQ(err, -EINVAL, "program should have been rejected");
	ASSERT_HAS_SUBSTR(log, "jump table of subprog starting at 0 spans multiple subprogs",
			  "verifier log");

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_log:
	free(log);
}

/*
 * The subprog holding the gotox has a well formed jump table of its own and
 * also collects a map that reaches past its end. The spanning map is still
 * rejected, even though the subprog is not left without a table.
 */
static void check_gotox_jt_spans_with_own_table(void)
{
	const __u32 jt_own[] = { GOTOX_FWD_OWN_TGT };
	const __u32 jt_span[] = { GOTOX_FWD_OWN_TGT, GOTOX_FWD_SUB_START };
	struct bpf_insn insns[GOTOX_FWD_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_from_main_fill(insns);

	map_fd[0] = gotox_jt_create_offs(jt_own, ARRAY_SIZE(jt_own));
	if (map_fd[0] < 0)
		goto free_log;
	map_fd[1] = gotox_jt_create_offs(jt_span, ARRAY_SIZE(jt_span));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, ARRAY_SIZE(insns), map_fd, 2, log);
	ASSERT_EQ(err, -EINVAL, "program should have been rejected");
	ASSERT_HAS_SUBSTR(log, "jump table of subprog starting at 0 spans multiple subprogs",
			  "verifier log");

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_log:
	free(log);
}

#define GOTOX_EDGE_MAIN_TGT	2
#define GOTOX_EDGE_SUB_START	4
#define GOTOX_EDGE_GOTOX	9
#define GOTOX_EDGE_BR_TGT	10
#define GOTOX_EDGE_JT_TGT	11
#define GOTOX_EDGE_INSN_CNT	12

static void gotox_no_edge_fill(struct bpf_insn *insns)
{
	insns[0] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[1] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0,
				GOTOX_EDGE_SUB_START - 1 - 1);
	insns[GOTOX_EDGE_MAIN_TGT] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[3] = BPF_EXIT_INSN();

	insns[GOTOX_EDGE_SUB_START] =
		BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
			    offsetof(struct xdp_md, ingress_ifindex));
	insns[5] = BPF_JMP_IMM(BPF_JNE, BPF_REG_2, 0, 4);

	/* r1 = &jt_span[0], by index 0 into fd_array */
	insns[6] = (struct bpf_insn) {
		.code = BPF_LD | BPF_DW | BPF_IMM,
		.dst_reg = BPF_REG_1,
		.src_reg = BPF_PSEUDO_MAP_IDX_VALUE,
		.imm = 0,
	};
	insns[7] = (struct bpf_insn) { .imm = 0 };
	insns[8] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 8);

	insns[GOTOX_EDGE_GOTOX] = BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_1, 0, 0, 0);
	insns[GOTOX_EDGE_BR_TGT] = BPF_MOV64_IMM(BPF_REG_0, 1);
	insns[GOTOX_EDGE_JT_TGT] = BPF_EXIT_INSN();
}

/*
 * The gotox resolves a target inside its own subprog, but out of a map that
 * spans subprogs and is therefore of no subprog. The CFG never walked that
 * edge, so the jump has to be rejected even though it stays in the subprog.
 */
static void check_gotox_target_without_cfg_edge(void)
{
	const __u32 jt_span[] = { GOTOX_EDGE_MAIN_TGT, GOTOX_EDGE_BR_TGT };
	const __u32 jt_sub[] = { GOTOX_EDGE_JT_TGT };
	struct bpf_insn insns[GOTOX_EDGE_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_no_edge_fill(insns);

	map_fd[0] = gotox_jt_create_offs(jt_span, ARRAY_SIZE(jt_span));
	if (map_fd[0] < 0)
		goto free_log;
	map_fd[1] = gotox_jt_create_offs(jt_sub, ARRAY_SIZE(jt_sub));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, ARRAY_SIZE(insns), map_fd, 2, log);
	ASSERT_EQ(err, -EINVAL, "program should have been rejected");
	ASSERT_HAS_SUBSTR(log,
			  "indirect jump from insn 9 to 10 is not in the jump table of the subprog",
			  "verifier log");

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_log:
	free(log);
}

#define GOTOX_SLICE_SUB_START	6
#define GOTOX_SLICE_GOTOX	14
#define GOTOX_SLICE_SUB_TGT	15
#define GOTOX_SLICE_INSN_CNT	17

static void gotox_slice_fill(struct bpf_insn *insns)
{
	insns[0] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[1] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0,
				GOTOX_SLICE_SUB_START - 1 - 1);
	insns[2] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[3] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[4] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[5] = BPF_EXIT_INSN();

	insns[GOTOX_SLICE_SUB_START] =
		BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
			    offsetof(struct xdp_md, ingress_ifindex));
	insns[7] = BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 1);
	insns[8] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, 1);
	insns[9] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 3);

	/* r1 = &jt_main[0], by index 0 into fd_array */
	insns[10] = (struct bpf_insn) {
		.code = BPF_LD | BPF_DW | BPF_IMM,
		.dst_reg = BPF_REG_1,
		.src_reg = BPF_PSEUDO_MAP_IDX_VALUE,
		.imm = 0,
	};
	insns[11] = (struct bpf_insn) { .imm = 0 };
	insns[12] = BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2);
	insns[13] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);

	insns[GOTOX_SLICE_GOTOX] = BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_1, 0, 0, 0);
	insns[GOTOX_SLICE_SUB_TGT] = BPF_MOV64_IMM(BPF_REG_0, 1);
	insns[16] = BPF_EXIT_INSN();
}

static void check_gotox_index_slice_other_subprog(void)
{
	const __u32 jt_main[] = { 2, 3, 4 };
	const __u32 jt_sub[] = { GOTOX_SLICE_SUB_TGT };
	struct bpf_insn insns[GOTOX_SLICE_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_slice_fill(insns);

	map_fd[0] = gotox_jt_create_offs(jt_main, ARRAY_SIZE(jt_main));
	if (map_fd[0] < 0)
		goto free_log;
	map_fd[1] = gotox_jt_create_offs(jt_sub, ARRAY_SIZE(jt_sub));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load(insns, ARRAY_SIZE(insns), map_fd, 2, log);
	ASSERT_EQ(err, -EINVAL, "program should have been rejected");
	ASSERT_HAS_SUBSTR(log, "indirect jump from insn 14 to 3 leaves the subprog [6,17)",
			  "verifier log");

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_log:
	free(log);
}

static int gotox_btf_create(const __u32 *starts, const __u8 *linkage, __u32 cnt,
			    struct bpf_func_info *fi, struct btf **pbtf)
{
	int int_id, proto_id, id;
	struct btf *btf;
	char name[24];
	__u32 i;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "btf__new_empty"))
		return -1;

	int_id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (!ASSERT_GT(int_id, 0, "btf__add_int"))
		goto err;

	proto_id = btf__add_func_proto(btf, int_id);
	if (!ASSERT_GT(proto_id, 0, "btf__add_func_proto"))
		goto err;

	for (i = 0; i < cnt; i++) {
		snprintf(name, sizeof(name), "gotox_f%u", i);
		id = btf__add_func(btf, name, linkage[i], proto_id);
		if (!ASSERT_GT(id, 0, "btf__add_func"))
			goto err;
		fi[i].insn_off = starts[i];
		fi[i].type_id = id;
	}

	if (!ASSERT_OK(btf__load_into_kernel(btf), "btf__load_into_kernel"))
		goto err;

	*pbtf = btf;
	return btf__fd(btf);
err:
	btf__free(btf);
	return -1;
}

static void check_gotox_target_other_global_subprog(void)
{
	const __u32 starts[] = { 0, GOTOX_SUB_START };
	const __u8 linkage[] = { BTF_FUNC_GLOBAL, BTF_FUNC_GLOBAL };
	const __u32 jt_main[] = { GOTOX_MAIN_TGT };
	const __u32 jt_sub[] = { GOTOX_SUB_TGT };
	struct bpf_insn insns[GOTOX_TWO_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	struct bpf_func_info fi[2];
	struct btf *btf = NULL;
	int btf_fd;
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_two_subprogs_fill(insns, 0, 0);

	btf_fd = gotox_btf_create(starts, linkage, ARRAY_SIZE(starts), fi, &btf);
	if (btf_fd < 0)
		goto free_log;

	map_fd[0] = gotox_jt_create_offs(jt_main, ARRAY_SIZE(jt_main));
	if (map_fd[0] < 0)
		goto free_btf;
	map_fd[1] = gotox_jt_create_offs(jt_sub, ARRAY_SIZE(jt_sub));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load_funcs(insns, ARRAY_SIZE(insns), map_fd, 2, log,
				    btf_fd, fi, ARRAY_SIZE(fi));
	ASSERT_EQ(err, -EINVAL, "program should have been rejected");
	ASSERT_HAS_SUBSTR(log, "indirect jump from insn 7 to 2 leaves the subprog [4,10)",
			  "verifier log");

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_btf:
	btf__free(btf);
free_log:
	free(log);
}

#define GOTOX_CB_MAIN_TGT	6
#define GOTOX_CB_START		8
#define GOTOX_CB_GOTOX		11
#define GOTOX_CB_TGT		12
#define GOTOX_CB_INSN_CNT	14

static void gotox_callback_fill(struct bpf_insn *insns)
{
	insns[0] = BPF_MOV64_IMM(BPF_REG_1, 1);
	/* r2 = &callback */
	insns[1] = (struct bpf_insn) {
		.code = BPF_LD | BPF_DW | BPF_IMM,
		.dst_reg = BPF_REG_2,
		.src_reg = BPF_PSEUDO_FUNC,
		.imm = GOTOX_CB_START - 1 - 1,
	};
	insns[2] = (struct bpf_insn) { .imm = 0 };
	insns[3] = BPF_MOV64_IMM(BPF_REG_3, 0);
	insns[4] = BPF_MOV64_IMM(BPF_REG_4, 0);
	insns[5] = BPF_EMIT_CALL(BPF_FUNC_loop);
	insns[GOTOX_CB_MAIN_TGT] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[7] = BPF_EXIT_INSN();

	/* r1 = &jt_main[0], by index 0 into fd_array */
	insns[GOTOX_CB_START] = (struct bpf_insn) {
		.code = BPF_LD | BPF_DW | BPF_IMM,
		.dst_reg = BPF_REG_1,
		.src_reg = BPF_PSEUDO_MAP_IDX_VALUE,
		.imm = 0,
	};
	insns[9] = (struct bpf_insn) { .imm = 0 };
	insns[10] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);
	insns[GOTOX_CB_GOTOX] = BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_1, 0, 0, 0);
	insns[GOTOX_CB_TGT] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[13] = BPF_EXIT_INSN();
}

static void check_gotox_callback_leaves_subprog(void)
{
	const __u32 starts[] = { 0, GOTOX_CB_START };
	const __u8 linkage[] = { BTF_FUNC_GLOBAL, BTF_FUNC_STATIC };
	const __u32 jt_main[] = { GOTOX_CB_MAIN_TGT };
	const __u32 jt_cb[] = { GOTOX_CB_TGT };
	struct bpf_insn insns[GOTOX_CB_INSN_CNT];
	int map_fd[2] = { -1, -1 };
	struct bpf_func_info fi[2];
	struct btf *btf = NULL;
	int btf_fd;
	char *log;
	int err;

	log = calloc(1, GOTOX_LOG_SZ);
	if (!ASSERT_OK_PTR(log, "calloc log"))
		return;

	gotox_callback_fill(insns);

	btf_fd = gotox_btf_create(starts, linkage, ARRAY_SIZE(starts), fi, &btf);
	if (btf_fd < 0)
		goto free_log;

	map_fd[0] = gotox_jt_create_offs(jt_main, ARRAY_SIZE(jt_main));
	if (map_fd[0] < 0)
		goto free_btf;
	map_fd[1] = gotox_jt_create_offs(jt_cb, ARRAY_SIZE(jt_cb));
	if (map_fd[1] < 0)
		goto close_maps;

	err = gotox_prog_load_funcs(insns, ARRAY_SIZE(insns), map_fd, 2, log,
				    btf_fd, fi, ARRAY_SIZE(fi));
	ASSERT_EQ(err, -EINVAL, "program should have been rejected");
	ASSERT_HAS_SUBSTR(log, "indirect jump from insn 11 to 6 leaves the subprog [8,14)",
			  "verifier log");

close_maps:
	close(map_fd[0]);
	close(map_fd[1]);
free_btf:
	btf__free(btf);
free_log:
	free(log);
}

static void check_bpf_side(void)
{
	check_bpf_no_lookup();
}

static void __test_bpf_insn_array(void)
{
	/* Test if offsets are adjusted properly */

	if (test__start_subtest("one2one"))
		check_one_to_one_mapping();

	if (test__start_subtest("simple"))
		check_simple();

	if (test__start_subtest("deletions"))
		check_deletions();

	if (test__start_subtest("deletions-with-functions"))
		check_deletions_with_functions();

	if (test__start_subtest("blindness"))
		check_blindness();

	/* Check all kinds of operations and related restrictions */

	if (test__start_subtest("incorrect-index"))
		check_incorrect_index();

	if (test__start_subtest("load-unfrozen-map"))
		check_load_unfrozen_map();

	if (test__start_subtest("no-map-reuse"))
		check_no_map_reuse();

	if (test__start_subtest("bpf-side-ops"))
		check_bpf_side();

	if (test__start_subtest("too-many-gotox-edges"))
		check_too_many_gotox_edges();

	if (test__start_subtest("gotox-edges-at-limit"))
		check_gotox_edges_at_limit();

	if (test__start_subtest("gotox-edges-across-subprogs"))
		check_gotox_edges_across_subprogs();

	if (test__start_subtest("gotox-tracker-map"))
		check_gotox_tracker_map();

	if (test__start_subtest("gotox-jt-spans-subprogs"))
		check_gotox_jt_spans_subprogs();

	if (test__start_subtest("gotox-jt-spans-with-own-table"))
		check_gotox_jt_spans_with_own_table();

	if (test__start_subtest("gotox-target-without-cfg-edge"))
		check_gotox_target_without_cfg_edge();

	if (test__start_subtest("gotox-target-other-subprog"))
		check_gotox_target_other_subprog();

	if (test__start_subtest("gotox-jt-per-subprog"))
		check_gotox_jt_per_subprog();

	if (test__start_subtest("gotox-span-unreached-entry"))
		check_gotox_span_unreached_entry();

	if (test__start_subtest("gotox-target-subprog-from-main"))
		check_gotox_target_subprog_from_main();

	if (test__start_subtest("gotox-index-slice-other-subprog"))
		check_gotox_index_slice_other_subprog();

	if (test__start_subtest("gotox-target-other-global-subprog"))
		check_gotox_target_other_global_subprog();

	if (test__start_subtest("gotox-callback-leaves-subprog"))
		check_gotox_callback_leaves_subprog();
}
#else
static void __test_bpf_insn_array(void)
{
	test__skip();
}
#endif

void test_bpf_insn_array(void)
{
	__test_bpf_insn_array();
}
