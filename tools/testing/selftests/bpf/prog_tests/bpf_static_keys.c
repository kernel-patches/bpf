// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include <sys/syscall.h>
#include <bpf/bpf.h>

#include "bpf_static_keys.skel.h"

#define VAL_ON	7
#define VAL_OFF	3

enum {
	OFF,
	ON
};

static int _bpf_prog_load(struct bpf_insn *insns, __u32 insn_cnt)
{
	return bpf_prog_load(BPF_PROG_TYPE_XDP, NULL, "GPL", insns, insn_cnt, NULL);
}

static int _bpf_static_key_update(int map_fd, __u32 on)
{
	LIBBPF_OPTS(bpf_static_key_update_opts, opts);

	opts.on = on;

	return bpf_static_key_update(map_fd, &opts);
}

#define BPF_JMP32_OR_NOP(IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_JA | BPF_K,		\
		.dst_reg = 0,					\
		.src_reg = BPF_STATIC_BRANCH_JA,		\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_JMP_OR_NOP(IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_JA | BPF_K,		\
		.dst_reg = 0,					\
		.src_reg = BPF_STATIC_BRANCH_JA,		\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_NOP_OR_JMP32(IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_JA | BPF_K,		\
		.dst_reg = 0,					\
		.src_reg = BPF_STATIC_BRANCH_JA |		\
			   BPF_STATIC_BRANCH_NOP,		\
		.off   = OFF,					\
		.imm   = IMM })

#define BPF_NOP_OR_JMP(IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_JA | BPF_K,		\
		.dst_reg = 0,					\
		.src_reg = BPF_STATIC_BRANCH_JA |		\
			   BPF_STATIC_BRANCH_NOP,		\
		.off   = OFF,					\
		.imm   = IMM })

static const struct bpf_insn insns0[] = {
	BPF_JMP_OR_NOP(0, 1),
	BPF_NOP_OR_JMP(0, 1),
	BPF_JMP32_OR_NOP(1, 0),
	BPF_NOP_OR_JMP32(1, 0),
};

/* Lower-level selftests for the gotol_or_nop/nop_or_gotol instructions */
static void check_insn(void)
{
	struct bpf_insn insns[] = {
		{}, /* we will substitute this by insn0[i], i=0,1,2,3 */
		BPF_JMP_IMM(BPF_JA, 0, 0, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, -2),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	bool stop = false;
	int prog_fd[4];
	int i;

	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_GE(prog_fd[i], 0, "correct program"))
			stop = true;
	}

	for (i = 0; i < 4; i++)
		close(prog_fd[i]);

	if (stop)
		return;

	/* load should fail: incorrect SRC */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		insns[0].src_reg |= 4;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect src"))
			return;
	}

	/* load should fail: incorrect DST */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		insns[0].dst_reg = i + 1; /* non-zero */
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect dst"))
			return;
	}

	/* load should fail: both off and imm are set */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		insns[0].imm = insns[0].off = insns0[i].imm ?: insns0[i].off;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect imm/off"))
			return;
	}

	/* load should fail: offset is incorrect */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];

		if (insns0[i].imm)
			insns[0].imm = -2;
		else
			insns[0].off = -2;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect imm/off"))
			return;

		if (insns0[i].imm)
			insns[0].imm = 42;
		else
			insns[0].off = 42;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect imm/off"))
			return;

		/* 0 is not allowed */
		insns[0].imm = insns[0].off = 0;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect imm/off"))
			return;
	}

	/* incorrect field is used */
	for (i = 0; i < 4; i++) {
		int tmp;

		insns[0] = insns0[i];

		tmp = insns[0].imm;
		insns[0].imm = insns[0].off;
		insns[0].off = tmp;

		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -EINVAL, "incorrect field"))
			return;
	}
}

static void trigger_prog(void)
{
	usleep(1);
}

static void __check_one_key(struct bpf_static_keys *skel,
			    struct bpf_map *key,
			    int val_off,
			    int val_on)
{
	int map_fd;
	int ret;

	map_fd = bpf_map__fd(key);
	if (!ASSERT_GT(map_fd, 0, "key"))
		return;

	ret = _bpf_static_key_update(map_fd, ON);
	if (!ASSERT_EQ(ret, 0, "_bpf_static_key_update(ON)"))
		return;
	skel->bss->ret_user = 0;
	trigger_prog();
	if (!ASSERT_EQ(skel->bss->ret_user, val_on, "skel->bss->ret_user"))
		return;

	_bpf_static_key_update(map_fd, OFF);
	skel->bss->ret_user = 0;
	trigger_prog();
	if (!ASSERT_EQ(skel->bss->ret_user, val_off, "skel->bss->ret_user"))
		return;
}

static void check_one_key(struct bpf_static_keys *skel, struct bpf_program *prog, struct bpf_map *key)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	__check_one_key(skel, key, VAL_OFF, VAL_ON);

	bpf_link__destroy(link);
}

static void check_one_key_multiple(struct bpf_static_keys *skel, struct bpf_map *key)
{
	struct bpf_link *link;

	link = bpf_program__attach(skel->progs.check_one_key_multiple);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	__check_one_key(skel, key, VAL_OFF * 3, VAL_ON * 3);

	bpf_link__destroy(link);
}

static void check_one_key_long_jump(struct bpf_static_keys *skel, struct bpf_map *key)
{
	struct bpf_link *link;

	link = bpf_program__attach(skel->progs.check_one_key_long_jump);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	__check_one_key(skel, key, 1000, 2000);

	bpf_link__destroy(link);
}

static void __check_multiple_keys(struct bpf_static_keys *skel,
				  struct bpf_map *key1,
				  struct bpf_map *key2,
				  int val_off_off,
				  int val_off_on,
				  int val_on_off,
				  int val_on_on)
{
	int map_fd1, map_fd2;
	int ret;

	map_fd1 = bpf_map__fd(key1);
	if (!ASSERT_GT(map_fd1, 0, "key1"))
		return;

	map_fd2 = bpf_map__fd(key2);
	if (!ASSERT_GT(map_fd2, 0, "key2"))
		return;

	ret = _bpf_static_key_update(map_fd1, OFF);
	if (!ASSERT_EQ(ret, 0, "_bpf_static_key_update(key1, OFF)"))
		return;
	ret = _bpf_static_key_update(map_fd2, OFF);
	if (!ASSERT_EQ(ret, 0, "_bpf_static_key_update(key2, OFF)"))
		return;
	skel->bss->ret_user = 0;
	trigger_prog();
	if (!ASSERT_EQ(skel->bss->ret_user, val_off_off, "skel->bss->ret_user"))
		return;

	ret = _bpf_static_key_update(map_fd1, ON);
	if (!ASSERT_EQ(ret, 0, "_bpf_static_key_update(key1, ON)"))
		return;
	ret = _bpf_static_key_update(map_fd2, OFF);
	if (!ASSERT_EQ(ret, 0, "_bpf_static_key_update(key2, OFF)"))
		return;
	skel->bss->ret_user = 0;
	trigger_prog();
	if (!ASSERT_EQ(skel->bss->ret_user, val_off_on, "skel->bss->ret_user"))
		return;

	ret = _bpf_static_key_update(map_fd1, OFF);
	if (!ASSERT_EQ(ret, 0, "_bpf_static_key_update(key1, OFF)"))
		return;
	ret = _bpf_static_key_update(map_fd2, ON);
	if (!ASSERT_EQ(ret, 0, "_bpf_static_key_update(key2, ON)"))
		return;
	skel->bss->ret_user = 0;
	trigger_prog();
	if (!ASSERT_EQ(skel->bss->ret_user, val_on_off, "skel->bss->ret_user"))
		return;

	ret = _bpf_static_key_update(map_fd1, ON);
	if (!ASSERT_EQ(ret, 0, "_bpf_static_key_update(key1, ON)"))
		return;
	ret = _bpf_static_key_update(map_fd2, ON);
	if (!ASSERT_EQ(ret, 0, "_bpf_static_key_update(key2, ON)"))
		return;
	skel->bss->ret_user = 0;
	trigger_prog();
	if (!ASSERT_EQ(skel->bss->ret_user, val_on_on, "skel->bss->ret_user"))
		return;
}

static void check_multiple_keys(struct bpf_static_keys *skel,
				struct bpf_map *key1,
				struct bpf_map *key2)
{
	struct bpf_link *link;

	link = bpf_program__attach(skel->progs.check_multiple_keys);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	__check_multiple_keys(skel, key1, key2, 0, 3, 30, 33);

	bpf_link__destroy(link);
}

static void check_bpf_to_bpf_call(struct bpf_static_keys *skel,
				  struct bpf_map *key1,
				  struct bpf_map *key2)
{
	struct bpf_link *link;

	link = bpf_program__attach(skel->progs.check_bpf_to_bpf_call);
	if (!ASSERT_OK_PTR(link, "link"))
		return;

	__check_multiple_keys(skel, key1, key2, 0, 303, 3030, 3333);

	bpf_link__destroy(link);
}

static void check_syscall(void)
{
	struct bpf_static_keys *skel;

	skel = bpf_static_keys__open_and_load();
	if (!ASSERT_OK_PTR(skel, "bpf_static_keys__open_and_load"))
		return;

	check_one_key(skel, skel->progs.check_one_key_likely, skel->maps.key1);
	check_one_key(skel, skel->progs.check_one_key_unlikely, skel->maps.key2);
	check_one_key_multiple(skel, skel->maps.key3);
	check_one_key_long_jump(skel, skel->maps.key4);
	check_multiple_keys(skel, skel->maps.key5, skel->maps.key6);

	bpf_static_keys__destroy(skel);
}

void test_bpf_static_keys(void)
{
	if (test__start_subtest("check_insn"))
		check_insn();

	if (test__start_subtest("check_syscall"))
		check_syscall();
}
