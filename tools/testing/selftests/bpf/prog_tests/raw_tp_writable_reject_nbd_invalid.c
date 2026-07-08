// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <linux/nbd.h>
#include "bpf_util.h"

static void check_nbd_attach_reject(const char *name,
				    const struct bpf_insn *program, size_t prog_len)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts);
	char error[4096];
	int bpf_fd, tp_fd;

	opts.log_level = 2;
	opts.log_buf = error;
	opts.log_size = sizeof(error);

	bpf_fd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, NULL, "GPL v2",
			       program, prog_len, &opts);
	if (!ASSERT_GE(bpf_fd, 0, "prog_load"))
		return;

	tp_fd = bpf_raw_tracepoint_open("nbd_send_request", bpf_fd);
	if (!ASSERT_LT(tp_fd, 0, name))
		close(tp_fd);

	close(bpf_fd);
}

void test_raw_tp_writable_reject_nbd_invalid(void)
{
	const struct bpf_insn program[] = {
		/* r6 is our tp buffer */
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),
		/* one byte beyond the end of the nbd_request struct */
		BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_6,
			    sizeof(struct nbd_request)),
		BPF_EXIT_INSN(),
	};

	const struct bpf_insn negative_var_off_program[] = {
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),
		/* make var_off negative, but keep the effective access offset non-negative */
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -8),
		/* one byte beyond the end of the nbd_request struct */
		BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_6,
			    sizeof(struct nbd_request) + 8),
		BPF_EXIT_INSN(),
	};

	check_nbd_attach_reject("nbd_invalid", program, ARRAY_SIZE(program));
	check_nbd_attach_reject("nbd_invalid_negative_var_off",
				negative_var_off_program,
				ARRAY_SIZE(negative_var_off_program));
}
