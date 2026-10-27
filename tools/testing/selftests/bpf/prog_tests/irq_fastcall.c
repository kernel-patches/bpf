#include <test_progs.h>
#include <network_helpers.h>
#include "irq_fastcall.skel.h"

static void check_spills(int prog_fd)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info), xlated_len;
	struct bpf_insn *insns;
	int err, spill_count = 0, irq_count = 0;

	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (!ASSERT_OK(err, "prog_info"))
		return;
	xlated_len = info.xlated_prog_len;
	insns = malloc(xlated_len);
	if (!ASSERT_OK_PTR(insns, "insns"))
		return;
	memset(&info, 0, sizeof(info));
	info.xlated_prog_len = xlated_len;
	info.xlated_prog_insns = ptr_to_u64(insns);
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (!ASSERT_OK(err, "xlated_info"))
		goto out;
	for (size_t insn_idx = 0; insn_idx < xlated_len / sizeof(*insns); insn_idx++) {
		struct bpf_insn *insn = &insns[insn_idx];

		if (insn->code == (BPF_ST | 0xe0))
			irq_count++;
		if ((insn->code == (BPF_STX | BPF_MEM | BPF_DW) &&
		     insn->dst_reg == BPF_REG_10 && insn->off <= -16) ||
		    (insn->code == (BPF_LDX | BPF_MEM | BPF_DW) &&
		     insn->src_reg == BPF_REG_10 && insn->off <= -16))
			spill_count++;
	}
	ASSERT_TRUE(irq_count == 0 || irq_count == 2, "irq_inlining");
	ASSERT_EQ(spill_count, irq_count ? 0 : 20, "compatibility_spills");
out:
	free(insns);
}

void test_irq_fastcall(void)
{
	struct irq_fastcall *skel;
	int prog_fd, err;

	skel = irq_fastcall__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	prog_fd = bpf_program__fd(skel->progs.irq_fastcall_preserve);
	check_spills(prog_fd);
	for (int mark = 0; mark < 2; mark++) {
		struct __sk_buff ctx = { .mark = mark };

		LIBBPF_OPTS(bpf_test_run_opts, opts,
			.data_in = &pkt_v4,
			.data_size_in = sizeof(pkt_v4),
			.ctx_in = &ctx,
			.ctx_size_in = sizeof(ctx),
			.repeat = 16,
		);

		err = bpf_prog_test_run_opts(prog_fd, &opts);
		ASSERT_OK(err, "test_run");
		ASSERT_EQ(opts.retval, 0, "retval");
		for (int reg_idx = 0; reg_idx < 10; reg_idx++)
			ASSERT_EQ(skel->bss->saved_regs[reg_idx],
				  mark + 17 * (reg_idx % 5 + 1), "preserved_register");
	}
	irq_fastcall__destroy(skel);
}
