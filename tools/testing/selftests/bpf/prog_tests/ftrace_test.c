// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "ftrace_test.skel.h"

void test_ftrace_test(void)
{
	struct ftrace_test *ftrace_skel = NULL;
	__u32 duration = 0, retval;
	int err, prog_fd;
	__u64 *ips;
	int idx, i;

	ftrace_skel = ftrace_test__open_and_load();
	if (!ASSERT_OK_PTR(ftrace_skel, "ftrace_skel_load"))
		goto cleanup;

	err = ftrace_test__attach(ftrace_skel);
	if (!ASSERT_OK(err, "ftrace_attach"))
		goto cleanup;

	prog_fd = bpf_program__fd(ftrace_skel->progs.test);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0,
				NULL, NULL, &retval, &duration);
	ASSERT_OK(err || retval, "test_run");

	ips = ftrace_skel->bss->ips;
	idx = ftrace_skel->bss->idx;

	if (!ASSERT_EQ(idx, 8, "idx"))
		goto cleanup;

	for (i = 0; i < 8; i++) {
		unsigned long long addr;
		char func[50];

		snprintf(func, sizeof(func), "bpf_fentry_test%d", i + 1);

		err = kallsyms_find(func, &addr);
		if (!ASSERT_OK(err, "kallsyms_find"))
			goto cleanup;

		if (!ASSERT_EQ(ips[i],  addr, "ips_addr"))
			goto cleanup;
	}

cleanup:
	ftrace_test__destroy(ftrace_skel);
}
