{
	"netfilter, accept all",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_NETFILTER,
	.retval = 1,
	.data = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x00,
	},
},
{
	"netfilter, stolen verdict",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_0, 2),
	BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.errstr = "At program exit the register R0 has value (0x2; 0x0) should have been in (0x0; 0x1)",
	.prog_type = BPF_PROG_TYPE_NETFILTER,
},
