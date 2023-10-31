// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Hengqi Chen */

#include <test_progs.h>
#include <linux/seccomp.h>
#include "test_seccomp.skel.h"

static int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}

void test_seccomp(void)
{
	struct test_seccomp *skel;
	int fd, flags, ret;

	skel = test_seccomp__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->rodata->seccomp_syscall_nr = __NR_seccomp;
	skel->rodata->seccomp_errno = 99;

	ret = test_seccomp__load(skel);
	if (!ASSERT_OK(ret, "skel_load"))
		goto cleanup;

	fd = bpf_program__fd(skel->progs.seccomp_prog);
	flags = SECCOMP_FILTER_FLAG_BPF_PROG_FD;
	ret = seccomp(SECCOMP_SET_MODE_FILTER, flags, &fd);
	ASSERT_OK(ret, "seccomp_set_bpf_prog");
	ret = seccomp(SECCOMP_SET_MODE_FILTER, flags, &fd);
	ASSERT_EQ(ret, -1, "seccomp should fail");
	ASSERT_EQ(errno, 99, "errno not equal to 99");

cleanup:
	test_seccomp__destroy(skel);
}
