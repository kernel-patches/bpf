// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#define FAR_OFF		(1 << 29)	/* BPF_MAX_VAR_OFF */

/* See far_rodata in verifier_barrier.c. Here ld_imm64 makes the far pointer. */
void serial_test_far_map_value(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_RDONLY_PROG);
	struct bpf_insn insns[] = {
		BPF_LD_MAP_VALUE(BPF_REG_1, 0, FAR_OFF),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -16),
		BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_1, 0),
		BPF_MOV64_IMM(BPF_REG_3, 2),
		BPF_ALU64_IMM(BPF_MUL, BPF_REG_3, 2),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_JMP_REG(BPF_JNE, BPF_REG_2, BPF_REG_3, 1),
		BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
		BPF_EXIT_INSN(),
	};
	int map_fd, prog_fd;

	map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, FAR_OFF + 8, 1, &opts);
	if (map_fd == -ENOMEM) {
		test__skip();
		return;
	}
	if (!ASSERT_GE(map_fd, 0, "map_create"))
		return;
	ASSERT_OK(bpf_map_freeze(map_fd), "map_freeze");
	insns[0].imm = map_fd;
	prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", insns,
				ARRAY_SIZE(insns), NULL);
	if (ASSERT_GE(prog_fd, 0, "prog_load"))
		close(prog_fd);
	close(map_fd);
}
