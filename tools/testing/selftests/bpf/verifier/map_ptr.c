{
	"bpf_map_ptr: read with negative offset rejected",
	.insns = {
	BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, -8),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_map_array_48b = { 1 },
	.result_unpriv = REJECT,
	.errstr_unpriv = "bpf_array access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN",
	.result = REJECT,
	.errstr = "R1 is bpf_array invalid negative access: off=-8",
},
{
	"bpf_map_ptr: write rejected",
	.insns = {
	BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
	BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, 0),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_map_array_48b = { 3 },
	.result_unpriv = REJECT,
	.errstr_unpriv = "bpf_array access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN",
	.result = REJECT,
	.errstr = "only read from bpf_array is supported",
},
{
	"bpf_map_ptr: read non-existent field rejected",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_6, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1, 1),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_map_array_48b = { 1 },
	.result_unpriv = REJECT,
	.errstr_unpriv = "bpf_array access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN",
	.result = REJECT,
	.errstr = "cannot access ptr member ops with moff 0 in struct bpf_map with off 1 size 4",
},
{
	"bpf_map_ptr: read ops field accepted",
	.insns = {
	BPF_MOV64_IMM(BPF_REG_6, 0),
	BPF_LD_MAP_FD(BPF_REG_1, 0),
	BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),
	BPF_MOV64_IMM(BPF_REG_0, 1),
	BPF_EXIT_INSN(),
	},
	.fixup_map_array_48b = { 1 },
	.result_unpriv = REJECT,
	.errstr_unpriv = "bpf_array access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN",
	.result = ACCEPT,
	.retval = 1,
},
{
	"ARG_CONST_MAP_PTR: null pointer",
	.insns = {
		/* bpf_redirect_map arg1 (map) */
		BPF_MOV64_IMM(BPF_REG_1, 0),
		/* bpf_redirect_map arg2 (ifindex) */
		BPF_MOV64_IMM(BPF_REG_2, 0),
		/* bpf_redirect_map arg3 (flags) */
		BPF_MOV64_IMM(BPF_REG_3, 0),
		BPF_EMIT_CALL(BPF_FUNC_redirect_map),
		BPF_EXIT_INSN(),
	},
	.result = REJECT,
	.prog_type = BPF_PROG_TYPE_XDP,
	.errstr = "R1 type=inv expected=map_ptr",
},
{
	"ARG_CONST_MAP_PTR: valid map pointer",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_1, 0),
		/* bpf_redirect_map arg1 (map) */
		BPF_LD_MAP_FD(BPF_REG_1, 0),
		/* bpf_redirect_map arg2 (ifindex) */
		BPF_MOV64_IMM(BPF_REG_2, 0),
		/* bpf_redirect_map arg3 (flags) */
		BPF_MOV64_IMM(BPF_REG_3, 0),
		BPF_EMIT_CALL(BPF_FUNC_redirect_map),
		BPF_EXIT_INSN(),
	},
	.fixup_map_devmap = { 1 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_XDP,
},
{
	"ARG_CONST_MAP_PTR_OR_NULL: null pointer for ex_map",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_1, 0),
		/* bpf_redirect_map_multi arg1 (in_map) */
		BPF_LD_MAP_FD(BPF_REG_1, 0),
		/* bpf_redirect_map_multi arg2 (ex_map) */
		BPF_MOV64_IMM(BPF_REG_2, 0),
		/* bpf_redirect_map_multi arg3 (flags) */
		BPF_MOV64_IMM(BPF_REG_3, 0),
		BPF_EMIT_CALL(BPF_FUNC_redirect_map_multi),
		BPF_EXIT_INSN(),
	},
	.fixup_map_devmap = { 1 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_XDP,
	.retval = 4,
},
{
	"ARG_CONST_MAP_PTR_OR_NULL: valid map pointer for ex_map",
	.insns = {
		BPF_MOV64_IMM(BPF_REG_1, 0),
		/* bpf_redirect_map_multi arg1 (in_map) */
		BPF_LD_MAP_FD(BPF_REG_1, 0),
		/* bpf_redirect_map_multi arg2 (ex_map) */
		BPF_LD_MAP_FD(BPF_REG_2, 1),
		/* bpf_redirect_map_multi arg3 (flags) */
		BPF_MOV64_IMM(BPF_REG_3, 0),
		BPF_EMIT_CALL(BPF_FUNC_redirect_map_multi),
		BPF_EXIT_INSN(),
	},
	.fixup_map_devmap = { 1 },
	.fixup_map_devmap_hash = { 3 },
	.result = ACCEPT,
	.prog_type = BPF_PROG_TYPE_XDP,
	.retval = 4,
},
