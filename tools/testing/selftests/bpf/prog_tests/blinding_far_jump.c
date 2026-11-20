// SPDX-License-Identifier: GPL-2.0
/* A far jump in a prog whose constants are blinded */

#include <test_progs.h>
#include <linux/filter.h>
#include "sysctl_helpers.h"

#define NR_CONSTS 11000

/*
 * A prog of one function gets its constants blinded when its runtime is
 * selected. Each 'r0 += 1' becomes 3 insns, which pushes the jump over them
 * out of its 16-bit range. Serial, because it sets bpf_jit_harden.
 */
void serial_test_blinding_far_jump(void)
{
	const char *harden = "/proc/sys/net/core/bpf_jit_harden";
	char old[16] = {}, pkt[64] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts, .data_in = pkt, .data_size_in = sizeof(pkt));
	struct bpf_insn *insns;
	int i, cnt = 0, fd;

	if (!is_jit_enabled()) {
		printf("%s:SKIP:JIT is disabled\n", __func__);
		test__skip();
		return;
	}

	insns = calloc(NR_CONSTS + 3, sizeof(*insns));
	if (!ASSERT_OK_PTR(insns, "insns"))
		return;

	/* mark is 0 */
	insns[cnt++] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, offsetof(struct __sk_buff, mark));
	insns[cnt++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, NR_CONSTS);
	for (i = 0; i < NR_CONSTS; i++)
		insns[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 1);
	insns[cnt++] = BPF_EXIT_INSN();

	if (sysctl_set_or_fail(harden, old, "2"))
		goto out;
	fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, NULL, "GPL", insns, cnt, NULL);
	sysctl_set_or_fail(harden, NULL, old);
	if (!ASSERT_OK_FD(fd, "load"))
		goto out;
	if (ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "run"))
		ASSERT_EQ(opts.retval, NR_CONSTS, "retval");
	close(fd);
out:
	free(insns);
}
