{
	"BPF_ATOMIC store-release, 8-bit",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* Store-release 0x12 to stack. */
		BPF_MOV64_IMM(BPF_REG_1, 0x12),
		BPF_ATOMIC_OP(BPF_B, BPF_STORE_REL, BPF_REG_10, BPF_REG_1, -1),
		/* Check loaded value is 0x12. */
		BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, -1),
		BPF_JMP32_REG(BPF_JEQ, BPF_REG_2, BPF_REG_1, 1),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"BPF_ATOMIC store-release, 16-bit",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* Store-release 0x1234 to stack. */
		BPF_MOV64_IMM(BPF_REG_1, 0x1234),
		BPF_ATOMIC_OP(BPF_H, BPF_STORE_REL, BPF_REG_10, BPF_REG_1, -2),
		/* Check loaded value is 0x1234. */
		BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, -2),
		BPF_JMP32_REG(BPF_JEQ, BPF_REG_2, BPF_REG_1, 1),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"BPF_ATOMIC store-release, 32-bit",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* Store-release 0x12345678 to stack. */
		BPF_MOV64_IMM(BPF_REG_1, 0x12345678),
		BPF_ATOMIC_OP(BPF_W, BPF_STORE_REL, BPF_REG_10, BPF_REG_1, -4),
		/* Check loaded value is 0x12345678. */
		BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, -4),
		BPF_JMP32_REG(BPF_JEQ, BPF_REG_2, BPF_REG_1, 1),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"BPF_ATOMIC store-release, 64-bit",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* Store-release 0x1234567890abcdef to stack. */
		BPF_LD_IMM64(BPF_REG_1, 0x1234567890abcdef),
		BPF_ATOMIC_OP(BPF_DW, BPF_STORE_REL, BPF_REG_10, BPF_REG_1, -8),
		/* Check loaded value is 0x1234567890abcdef. */
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -8),
		BPF_JMP_REG(BPF_JEQ, BPF_REG_2, BPF_REG_1, 1),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
},
{
	"Cannot store-release with uninitialized src_reg",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_ATOMIC_OP(BPF_DW, BPF_STORE_REL, BPF_REG_10, BPF_REG_2, -8),
		BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "R2 !read_ok",
},
