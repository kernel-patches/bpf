// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "lsm_kfuncs.skel.h"
#include "lsm_kfuncs_fail.skel.h"

void test_lsm_kfuncs(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct lsm_kfuncs *skel;

	RUN_TESTS(lsm_kfuncs_fail);

	skel = lsm_kfuncs__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;
	if (!ASSERT_OK(lsm_kfuncs__attach(skel), "attach"))
		goto out;

	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.query),
					      &opts), "test_run"))
		goto out;
	ASSERT_EQ(skel->data->ret_clear, 0, "not locked down");
	ASSERT_EQ(skel->data->ret_denied, -EPERM, "locked down");
	ASSERT_EQ(skel->data->ret_invalid_low, -EINVAL, "LOCKDOWN_NONE invalid");
	ASSERT_EQ(skel->data->ret_invalid_high, -EINVAL, "CONFIDENTIALITY_MAX invalid");
out:
	lsm_kfuncs__destroy(skel);
}
