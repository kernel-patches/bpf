// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "get_func_ip_test.skel.h"

void test_get_func_ip_test(void)
{
	struct get_func_ip_test *skel = NULL;
	__u32 duration = 0, retval;
	int err, prog_fd, i;
	__u64 *result;

	skel = get_func_ip_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "get_func_ip_test__open_and_load"))
		goto cleanup;

	err = get_func_ip_test__attach(skel);
	if (!ASSERT_OK(err, "get_func_ip_test__attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.test1);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");

	prog_fd = bpf_program__fd(skel->progs.fmod_ret_test);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);

	ASSERT_OK(err, "test_run");

	result = (__u64 *)skel->bss;
	for (i = 0; i < sizeof(*skel->bss) / sizeof(__u64); i++) {
		if (!ASSERT_EQ(result[i], 1, "fentry_result"))
			break;
	}

	get_func_ip_test__detach(skel);

cleanup:
	get_func_ip_test__destroy(skel);
}
