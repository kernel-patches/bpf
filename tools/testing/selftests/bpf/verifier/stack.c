{
	/* Check that reading unitialized stack memory is allowed only in privileged
	 * mode. Also check that such reads maintain the max stack depth.
	 */
	"read uninit stack",
	.insns = {
		BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -504),
		/* exit(0); */
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "invalid read from stack",
    .max_stack_depth = 504,
},
{
    /* Check that indirect accesses to stack maintain the max stack depth. */
	"read (indirect) uninit stack",
	.insns = {
		/* We'll use probe_read_user as an arbitrary helper that can access the
		 * stack. We're going to read into *(fp-104).
		 */
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -104),
		BPF_MOV32_IMM(BPF_REG_2, 8),
        /* read from a random address */
		BPF_MOV32_IMM(BPF_REG_3, 0x4242),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_probe_read_user),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
	    BPF_EXIT_INSN(),
		/* exit(0); */
		BPF_MOV32_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "",
    .max_stack_depth = 104,
},