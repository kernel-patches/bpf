{
	"atomic exchange smoketest - 64bit",
	.insns = {
	/* val = 3; */
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 3),
	/* old = atomic_xchg(&val, 4); */
	BPF_MOV64_IMM(BPF_REG_1, 4),
	BPF_ATOMIC_XCHG(BPF_DW, BPF_REG_10, BPF_REG_1, -8),
	/* if (old != 3) exit(1); */
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 3, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	/* if (val != 4) exit(2); */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 4, 2),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	/* exit(0); */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"atomic exchange smoketest - 32bit",
	.insns = {
	/* val = 3; */
	BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 3),
	/* old = atomic_xchg(&val, 4); */
	BPF_MOV32_IMM(BPF_REG_1, 4),
	BPF_ATOMIC_XCHG(BPF_W, BPF_REG_10, BPF_REG_1, -4),
	/* if (old != 3) exit(1); */
	BPF_JMP32_IMM(BPF_JEQ, BPF_REG_1, 3, 2),
	BPF_MOV32_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	/* if (val != 4) exit(2); */
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_10, -4),
	BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 4, 2),
	BPF_MOV32_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	/* exit(0); */
	BPF_MOV32_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"atomic set smoketest - 64bit",
	.insns = {
	/* val = 3; */
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 3),
	/* atomic_xchg(&val, 4); */
	BPF_MOV64_IMM(BPF_REG_1, 4),
	BPF_ATOMIC_SET(BPF_DW, BPF_REG_10, BPF_REG_1, -8),
	/* r1 should not be clobbered, no BPF_FETCH flag */
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 4, 2),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	/* if (val != 4) exit(2); */
	BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8),
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 4, 2),
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	/* exit(0); */
	BPF_MOV64_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"atomic set smoketest - 32bit",
	.insns = {
	/* val = 3; */
	BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 3),
	/* atomic_xchg(&val, 4); */
	BPF_MOV32_IMM(BPF_REG_1, 4),
	BPF_ATOMIC_SET(BPF_W, BPF_REG_10, BPF_REG_1, -4),
	/* r1 should not be clobbered, no BPF_FETCH flag */
	BPF_JMP32_IMM(BPF_JEQ, BPF_REG_1, 4, 2),
	BPF_MOV32_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	/* if (val != 4) exit(2); */
	BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_10, -4),
	BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 4, 2),
	BPF_MOV32_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	/* exit(0); */
	BPF_MOV32_IMM(BPF_REG_0, 0),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"Can't use atomic set on kernel memory",
	.insns = {
	/* This is an fentry prog, context is array of the args of the
	 * kernel function being called. Load first arg into R2.
	 */
	BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0),
	/* First arg of bpf_fentry_test7 is a pointer to a struct.
	 * Attempt to modify that struct. Verifier shouldn't let us
	 * because it's kernel memory.
	 */
	BPF_MOV64_IMM(BPF_REG_3, 1),
	BPF_ATOMIC_SET(BPF_DW, BPF_REG_2, BPF_REG_3, 0),
	BPF_EXIT_INSN(),
	},
	.prog_type = BPF_PROG_TYPE_TRACING,
	.expected_attach_type = BPF_TRACE_FENTRY,
	.kfunc = "bpf_fentry_test7",
	.result = REJECT,
	.errstr = "only read is supported",
},
