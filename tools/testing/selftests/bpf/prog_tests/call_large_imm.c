// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "call_large_imm.skel.h"

/*
 * This test dynamically adapts to the current environment, and will succeed
 * whether JIT is enabled or not.
 * 1. If JIT is enabled: The test case will successfully load and return
 *    the expected value.
 * 2. If JIT is disabled: It asserts that the verifier cleanly rejects the
 *    program with -EINVAL (or -ENOSPC) and outputs the expected error log.
 */

void test_call_large_imm(void)
{
	struct call_large_imm *skel;
	int err, prog_fd;
	char log_buf[4096];

	LIBBPF_OPTS(bpf_test_run_opts, opts);

	skel = call_large_imm__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	if (!env.jit_enabled)
		bpf_program__set_log_buf(skel->progs.call_large_imm_test,
					 log_buf, sizeof(log_buf));

	err = call_large_imm__load(skel);

	if (env.jit_enabled) {
		if (!ASSERT_OK(err, "load_should_succeed_with_jit"))
			goto cleanup;

		prog_fd = bpf_program__fd(skel->progs.call_large_imm_test);
		err = bpf_prog_test_run_opts(prog_fd, &opts);

		if (ASSERT_OK(err, "prog_run_success"))
			ASSERT_EQ(opts.retval, 3, "prog_retval");

	} else {
		ASSERT_ERR(err, "load_should_fail_in_interpreter");
		ASSERT_TRUE(err == -EINVAL || err == -ENOSPC, "err_should_be_einval_or_enospc");

		if (!ASSERT_OK_PTR(strstr(log_buf, "bpf-to-bpf call offset out of range for interpreter"),
				   "check_verifier_log_msg")) {
			printf("Actual verifier log:\n%s\n", log_buf);
		}
	}

cleanup:
	call_large_imm__destroy(skel);
}
