// SPDX-License-Identifier: GPL-2.0
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <sys/syscall.h>

#include "test_progs.h"

#define BPF_ALU64_IMM(OP, DST, IMM)					\
	((struct bpf_insn) {							\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,								\
		.src_reg = 0,								\
		.off   = 0,									\
		.imm   = IMM })

#define BPF_EXIT_INSN()					\
	((struct bpf_insn) {				\
		.code  = BPF_JMP | BPF_EXIT,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,						\
		.imm   = 0 })

void test_no_charge(void)
{
	struct bpf_insn prog[] = {
		BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	union bpf_attr attr;
	int duration = 0;
	int fd;

	bzero(&attr, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
	attr.insn_cnt = 2;
	attr.insns = (__u64)prog;
	attr.license = (__u64)("GPL");
	attr.prog_flags |= BPF_F_PROG_NO_CHARGE;

	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	CHECK(fd < 0 && fd != -EPERM, "no_charge", "error: %s\n",
			strerror(errno));

	if (fd > 0)
		close(fd);
}
