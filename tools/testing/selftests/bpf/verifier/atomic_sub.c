{
	"BPF_ATOMIC_SUB without fetch",
	.insns = {
		/* val = 100; */
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 100),
		/* atomic_sub(&val, 4); */
		BPF_MOV64_IMM(BPF_REG_1, 4),
		BPF_ATOMIC_SUB(BPF_DW, BPF_REG_10, BPF_REG_1, -8),
		/* if (val != 96) exit(2); */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_10, -8),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 96, 2),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_EXIT_INSN(),
		/* r1 should not be clobbered, no BPF_FETCH flag */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 4, 1),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"BPF_ATOMIC_SUB with fetch",
	.insns = {
		/* val = 100; */
		BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 100),
		/* old = atomic_fetch_sub(&val, 4); */
		BPF_MOV64_IMM(BPF_REG_1, 4),
		BPF_ATOMIC_FETCH_SUB(BPF_DW, BPF_REG_10, BPF_REG_1, -8),
		/* if (old != 100) exit(3); */
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 100, 2),
		BPF_MOV64_IMM(BPF_REG_0, 3),
		BPF_EXIT_INSN(),
		/* if (val != 96) exit(2); */
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_10, -8),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 96, 2),
		BPF_MOV64_IMM(BPF_REG_0, 2),
		BPF_EXIT_INSN(),
		/* exit(0); */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
