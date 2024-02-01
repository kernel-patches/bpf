// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Isovalent */

#include <test_progs.h>

#include <sys/syscall.h>
#include <bpf/bpf.h>

static inline int _bpf_prog_load(struct bpf_insn *insns, __u32 insn_cnt)
{
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP, /* we don't care */
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = insn_cnt,
		.license   = ptr_to_u64("GPL"),
	};

	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

enum {
	OFF,
	ON
};

static inline int bpf_static_branch_update(int prog_fd, __u32 insn_off, __u32 on)
{
	union bpf_attr attr = {
		.static_branch.prog_fd = (__u32)prog_fd,
		.static_branch.insn_off = insn_off,
		.static_branch.on = on,
	};

	return syscall(__NR_bpf, BPF_STATIC_BRANCH_UPDATE, &attr, sizeof(attr));
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

static void check_ops(void)
{
	struct bpf_insn insns[] = {
		{}, /* we will substitute this by insn0[i], i=0,1,2,3 */
		BPF_JMP_IMM(BPF_JA, 0, 0, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, -2),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
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
		if (!ASSERT_EQ(prog_fd[i], -1, "incorrect src"))
			return;
	}

	/* load should fail: incorrect DST */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		insns[0].dst_reg = i + 1; /* non-zero */
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -1, "incorrect dst"))
			return;
	}

	/* load should fail: both off and imm are set */
	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		insns[0].imm = insns[0].off = insns0[i].imm ?: insns0[i].off;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -1, "incorrect imm/off"))
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
		if (!ASSERT_EQ(prog_fd[i], -1, "incorrect imm/off"))
			return;

		if (insns0[i].imm)
			insns[0].imm = 42;
		else
			insns[0].off = 42;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -1, "incorrect imm/off"))
			return;

		/* 0 is not allowed */
		insns[0].imm = insns[0].off = 0;
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_EQ(prog_fd[i], -1, "incorrect imm/off"))
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
		if (!ASSERT_EQ(prog_fd[i], -1, "incorrect field"))
			return;
	}
}

static void check_syscall(void)
{
	struct bpf_insn insns[] = {
		{}, /* we will substitute this by insn0[i], i=0,1,2,3 */
		BPF_JMP_IMM(BPF_JA, 0, 0, 1),
		BPF_JMP_IMM(BPF_JA, 0, 0, -2),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	union bpf_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.insns     = ptr_to_u64(insns),
		.insn_cnt  = ARRAY_SIZE(insns),
		.license   = ptr_to_u64("GPL"),
	};
	bool stop = false;
	int prog_fd[4];
	__u32 insn_off;
	int ret;
	int i;

	for (i = 0; i < 4; i++) {
		insns[0] = insns0[i];
		prog_fd[i] = _bpf_prog_load(insns, ARRAY_SIZE(insns));
		if (!ASSERT_GE(prog_fd[i], 0, "correct program"))
			stop = true;
	}

	if (stop)
		goto end;

	for (i = 0; i < 4; i++) {
		/* we can set branch off */
		ret = bpf_static_branch_update(prog_fd[i], 0, OFF);
		if (!ASSERT_EQ(ret, 0, "correct update"))
			goto end;

		/* we can set branch on */
		ret = bpf_static_branch_update(prog_fd[i], 0, ON);
		if (!ASSERT_EQ(ret, 0, "correct update"))
			goto end;

		/* incorrect.static_branch.on: can only be 0|1 */
		ret = bpf_static_branch_update(prog_fd[i], 0, 2);
		if (!ASSERT_EQ(ret, -1, "incorrect static_branch.on value"))
			goto end;

		/* incorrect static_branch.insn_off: can only be 0 in this case */
		for (insn_off = 1; insn_off < 5; insn_off++) {
			ret = bpf_static_branch_update(prog_fd[i], insn_off, OFF);
			if (!ASSERT_EQ(ret, -1, "incorrect insn_off: not a correct insns"))
				goto end;
			if (!ASSERT_EQ(errno, EINVAL, "incorrect insn_off: not a correct insns"))
				goto end;
		}
		ret = bpf_static_branch_update(prog_fd[i], 666, OFF);
		if (!ASSERT_EQ(ret, -1, "incorrect insn_off: out of range"))
			goto end;
		if (!ASSERT_EQ(errno, ERANGE, "incorrect insn_off: out puf range"))
			goto end;

		/* bad file descriptor: no open file */
		ret = bpf_static_branch_update(-1, 0, OFF);
		if (!ASSERT_EQ(ret, -1, "incorrect prog_fd: no file"))
			goto end;
		if (!ASSERT_EQ(errno, EBADF, "incorrect prog_fd: no file"))
			goto end;

		/* bad file descriptor: not a bpf prog */
		ret = bpf_static_branch_update(0, 0, OFF);
		if (!ASSERT_EQ(ret, -1, "incorrect prog_fd: not a bpf prog"))
			goto end;
		if (!ASSERT_EQ(errno, EINVAL, "incorrect prog_fd: not a bpf prog"))
			goto end;
	}

end:
	for (i = 0; i < 4; i++)
		close(prog_fd[i]);

}

void test_bpf_static_branches(void)
{
	if (test__start_subtest("check_ops"))
		check_ops();

	if (test__start_subtest("check_syscall"))
		check_syscall();
}
