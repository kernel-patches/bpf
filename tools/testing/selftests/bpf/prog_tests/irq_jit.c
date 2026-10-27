#include <test_progs.h>
#include <network_helpers.h>
#include <sysctl_helpers.h>
#include "irq_jit.skel.h"

static void check_irq_native(int prog_fd, __u32 jited_len)
{
#if defined(__x86_64__)
	static const __u8 save[] = { 0x9c, 0x41, 0x5a, 0xfa, 0x4c, 0x89, 0x17 };
	static const __u8 restore[] = {
		0x4c, 0x8b, 0x17, 0x49, 0xf7, 0xc2, 0x00, 0x02, 0x00, 0x00, 0x74, 0x01, 0xfb,
	};
#elif defined(__aarch64__)
	static const __u8 save[] = { 0xdf, 0x43, 0x03, 0xd5 };
	static const __u8 restore[] = { 0x0a, 0x00, 0x40, 0xf9, 0x2a, 0x42, 0x1b, 0xd5 };
	static const __u8 pmr_save[] = { 0x0b, 0x46, 0x18, 0xd5 };
	static const __u8 pmr_restore[] = { 0x0a, 0x00, 0x40, 0xf9, 0x0a, 0x46, 0x18, 0xd5 };
#else
	return;
#endif
#if defined(__x86_64__) || defined(__aarch64__)
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	__u8 *image;
	int err;

	if (!ASSERT_GT(jited_len, 0, "jited_len"))
		return;
	image = malloc(jited_len);
	if (!ASSERT_OK_PTR(image, "jited_image"))
		return;
	info.jited_prog_len = jited_len;
	info.jited_prog_insns = ptr_to_u64(image);
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (!ASSERT_OK(err, "jited_prog_info"))
		goto out;
#if defined(__x86_64__)
	ASSERT_TRUE(memmem(image, jited_len, save, sizeof(save)), "native_irq_save");
	ASSERT_TRUE(memmem(image, jited_len, restore, sizeof(restore)), "native_irq_restore");
#else
	ASSERT_TRUE(memmem(image, jited_len, save, sizeof(save)) ||
		    memmem(image, jited_len, pmr_save, sizeof(pmr_save)), "native_irq_save");
	ASSERT_TRUE(memmem(image, jited_len, restore, sizeof(restore)) ||
		    memmem(image, jited_len, pmr_restore, sizeof(pmr_restore)), "native_irq_restore");
#endif
out:
	free(image);
#endif
}

static void check_irq_insns(int prog_fd, bool expect_inline)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_insn *insns;
	__u32 xlated_len;
	int save_count = 0, restore_count = 0;
	int err;

	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (!ASSERT_OK(err, "prog_info"))
		return;
	xlated_len = info.xlated_prog_len;
	insns = malloc(xlated_len);
	if (!ASSERT_OK_PTR(insns, "xlated_insns"))
		return;
	memset(&info, 0, sizeof(info));
	info.xlated_prog_len = xlated_len;
	info.xlated_prog_insns = ptr_to_u64(insns);
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (!ASSERT_OK(err, "xlated_prog_info"))
		goto out;
	for (size_t insn_idx = 0; insn_idx < info.xlated_prog_len / sizeof(*insns); insn_idx++) {
		struct bpf_insn *insn = &insns[insn_idx];

		if (insn->code != (BPF_ST | 0xe0))
			continue;
		ASSERT_EQ((__u32)insn->dst_reg, BPF_REG_1, "flags_reg");
		ASSERT_EQ((__u32)insn->src_reg, 0, "reserved_src_reg");
		ASSERT_EQ(insn->off, 0, "reserved_off");
		if (insn->imm == 0)
			save_count++;
		else if (insn->imm == 1)
			restore_count++;
		else
			ASSERT_FAIL("unexpected IRQ operation %d", insn->imm);
	}
	ASSERT_EQ(save_count, expect_inline ? 2 : 0, "save_count");
	ASSERT_EQ(restore_count, expect_inline ? 2 : 0, "restore_count");
	if (expect_inline)
		check_irq_native(prog_fd, info.jited_prog_len);
out:
	free(insns);
}

void test_irq_jit(void)
{
	struct irq_jit *skel;
	const char *harden = "/proc/sys/net/core/bpf_jit_harden";
	char old_harden[32];
	int err;

	if (sysctl_set_or_fail(harden, old_harden, "2"))
		return;
	skel = irq_jit__open_and_load();
	if (!ASSERT_OK_PTR(skel, "irq_jit_open_and_load"))
		goto restore_harden;
	for (int prog_idx = 0; prog_idx < 2; prog_idx++) {
		struct bpf_program *prog = prog_idx ? skel->progs.irq_jit_subprog :
						    skel->progs.irq_jit_basic;
		LIBBPF_OPTS(bpf_test_run_opts, opts,
			.data_in = &pkt_v4,
			.data_size_in = sizeof(pkt_v4),
			.repeat = 16,
		);

		if (!test__start_subtest(bpf_program__name(prog)))
			continue;
		err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
		if (!ASSERT_OK(err, "test_run"))
			continue;
		ASSERT_LE(opts.retval, 1, "test_retval");
		check_irq_insns(bpf_program__fd(prog), opts.retval == 0);
	}
	irq_jit__destroy(skel);
restore_harden:
	sysctl_set_or_fail(harden, NULL, old_harden);
}
