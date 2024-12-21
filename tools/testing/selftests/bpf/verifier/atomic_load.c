{
	"BPF_ATOMIC load-acquire, 8-bit",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* Write 1 to stack. */
		BPF_ST_MEM(BPF_B, BPF_REG_10, -1, 0x12),
		/* Load-acquire it from stack to R1. */
		BPF_ATOMIC_OP(BPF_B, BPF_LOAD_ACQ, BPF_REG_1, BPF_REG_10, -1),
		/* Check loaded value is 0x12. */
		BPF_JMP32_IMM(BPF_JEQ, BPF_REG_1, 0x12, 1),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"BPF_ATOMIC load-acquire, 16-bit",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* Write 0x1234 to stack. */
		BPF_ST_MEM(BPF_H, BPF_REG_10, -2, 0x1234),
		/* Load-acquire it from stack to R1. */
		BPF_ATOMIC_OP(BPF_H, BPF_LOAD_ACQ, BPF_REG_1, BPF_REG_10, -2),
		/* Check loaded value is 0x1234. */
		BPF_JMP32_IMM(BPF_JEQ, BPF_REG_1, 0x1234, 1),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"BPF_ATOMIC load-acquire, 32-bit",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* Write 0x12345678 to stack. */
		BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0x12345678),
		/* Load-acquire it from stack to R1. */
		BPF_ATOMIC_OP(BPF_W, BPF_LOAD_ACQ, BPF_REG_1, BPF_REG_10, -4),
		/* Check loaded value is 0x12345678. */
		BPF_JMP32_IMM(BPF_JEQ, BPF_REG_1, 0x12345678, 1),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"BPF_ATOMIC load-acquire, 64-bit",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* Save 0x1234567890abcdef to R1, then write it to stack. */
		BPF_LD_IMM64(BPF_REG_1, 0x1234567890abcdef),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -8),
		/* Load-acquire it from stack to R2. */
		BPF_ATOMIC_OP(BPF_DW, BPF_LOAD_ACQ, BPF_REG_2, BPF_REG_10, -8),
		/* Check loaded value is 0x1234567890abcdef. */
		BPF_JMP_REG(BPF_JEQ, BPF_REG_2, BPF_REG_1, 1),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"Cannot load-acquire from uninitialized src_reg",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_ATOMIC_OP(BPF_DW, BPF_LOAD_ACQ, BPF_REG_1, BPF_REG_2, -8),
		BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R2 !read_ok",
},
