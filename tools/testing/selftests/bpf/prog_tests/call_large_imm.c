// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "call_large_imm.skel.h"

void test_call_large_imm(void)
{
	struct call_large_imm *skel;
	int err, prog_fd;

	LIBBPF_OPTS(bpf_test_run_opts, opts);

	skel = call_large_imm__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	err = call_large_imm__load(skel);

	if (!ASSERT_OK(err, "load_should_succeed"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.call_large_imm_test);
	err = bpf_prog_test_run_opts(prog_fd, &opts);

	if (ASSERT_OK(err, "prog_run_success"))
		ASSERT_EQ(opts.retval, 3, "prog_retval");

cleanup:
	call_large_imm__destroy(skel);
}
