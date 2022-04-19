#define SK_WRITABLE_FIELD(tp, field, size, res) \
{ \
	.descr = field, \
	.insns = { \
		/* r1 = *(u64 *)(r1 + 0) */ \
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0), \
		/* r1 = *(u64 *)(r1 + offsetof(struct socket, sk)) */ \
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0), \
		/* r2 = *(u64 *)(r1 + offsetof(struct sock, <field>)) */ \
		BPF_LDX_MEM(size, BPF_REG_2, BPF_REG_1, 0), \
		/* *(u64 *)(r1 + offsetof(struct sock, <field>)) = r2 */ \
		BPF_STX_MEM(size, BPF_REG_1, BPF_REG_2, 0), \
		BPF_MOV64_IMM(BPF_REG_0, 1), \
		BPF_EXIT_INSN(), \
	}, \
	.result = res, \
	.errstr = res ? "no write support to 'struct sock' at off" : "", \
	.prog_type = BPF_PROG_TYPE_LSM, \
	.expected_attach_type = BPF_LSM_CGROUP, \
	.kfunc = "socket_post_create", \
	.fixup_ldx = { \
		{ "socket", "sk", 1 }, \
		{ tp, field, 2 }, \
		{ tp, field, 3 }, \
	}, \
}

SK_WRITABLE_FIELD("sock_common", "skc_family", BPF_H, REJECT),
SK_WRITABLE_FIELD("sock", "sk_sndtimeo", BPF_DW, REJECT),
SK_WRITABLE_FIELD("sock", "sk_priority", BPF_W, ACCEPT),
SK_WRITABLE_FIELD("sock", "sk_mark", BPF_W, ACCEPT),
SK_WRITABLE_FIELD("sock", "sk_pacing_rate", BPF_DW, REJECT),

#undef SK_WRITABLE_FIELD
