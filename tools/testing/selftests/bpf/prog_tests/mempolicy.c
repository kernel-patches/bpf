// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <numaif.h>
#include <test_progs.h>
#include "test_mempolicy.skel.h"

#define SIZE 4096

static void mempolicy_bind(bool success)
{
	unsigned long mask = 1;
	char *addr;
	int err;

	addr = mmap(NULL, SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_OK_PTR(addr, "mmap"))
		return;

	err = mbind(addr, SIZE, MPOL_BIND, &mask, sizeof(mask), 0);
	if (success)
		ASSERT_OK(err, "mbind_success");
	else
		ASSERT_ERR(err, "mbind_fail");

	munmap(addr, SIZE);
}

static void mempolicy_default(void)
{
	char *addr;
	int err;

	addr = mmap(NULL, SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_OK_PTR(addr, "mmap"))
		return;

	err = mbind(addr, SIZE, MPOL_DEFAULT, NULL, 0, 0);
	ASSERT_OK(err, "mbind_success");

	munmap(addr, SIZE);
}
void test_mempolicy(void)
{
	struct test_mempolicy *skel;
	int err;

	skel = test_mempolicy__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;

	skel->bss->target_pid = getpid();

	err = test_mempolicy__load(skel);
	if (!ASSERT_OK(err, "load"))
		goto destroy;

	/* Attach LSM prog first */
	err = test_mempolicy__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto destroy;

	/* syscall to adjust memory policy */
	if (test__start_subtest("MPOL_BIND_with_lsm"))
		mempolicy_bind(false);
	if (test__start_subtest("MPOL_DEFAULT_with_lsm"))
		mempolicy_default();

destroy:
	test_mempolicy__destroy(skel);

	if (test__start_subtest("MPOL_BIND_without_lsm"))
		mempolicy_bind(true);
	if (test__start_subtest("MPOL_DEFAULT_without_lsm"))
		mempolicy_default();
}
