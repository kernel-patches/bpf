{
	"BPF_ATOMIC bounds propagation, mem->reg",
	.insns = {
		/* a = 0; */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),
		/* b = atomic_fetch_add(&a, 1); */
		BPF_MOV64_IMM(BPF_REG_1, 1),
		BPF_ATOMIC_OP(BPF_DW, BPF_ADD | BPF_FETCH, BPF_REG_10, BPF_REG_1, -8),
		/* Verifier should be able to tell that this infinite loop isn't reachable. */
		/* if (b) while (true) continue; */
		BPF_JMP_IMM(BPF_JNE, BPF_REG_1, 0, -1),
		BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.result_unpriv = REJECT,
	.errstr_unpriv = "back-edge",
},
