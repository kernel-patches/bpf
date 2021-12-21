// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Hengqi Chen */

#include <test_progs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "test_kprobe_syscall.skel.h"

void test_kprobe_syscall(void)
{
	struct test_kprobe_syscall *skel;
	int err, fd = 0;

	skel = test_kprobe_syscall__open();
	if (!ASSERT_OK_PTR(skel, "could not open BPF object"))
		return;

	skel->rodata->my_pid = getpid();

	err = test_kprobe_syscall__load(skel);
	if (!ASSERT_OK(err, "could not load BPF object"))
		goto cleanup;

	err = test_kprobe_syscall__attach(skel);
	if (!ASSERT_OK(err, "could not attach BPF object"))
		goto cleanup;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);

	ASSERT_GT(fd, 0, "socket failed");
	ASSERT_EQ(skel->bss->domain, AF_UNIX, "BPF_KPROBE_SYSCALL failed");
	ASSERT_EQ(skel->bss->type, SOCK_STREAM, "BPF_KPROBE_SYSCALL failed");
	ASSERT_EQ(skel->bss->protocol, 0, "BPF_KPROBE_SYSCALL failed");
	ASSERT_EQ(skel->bss->fd, fd, "BPF_KRETPROBE_SYSCALL failed");

cleanup:
	if (fd)
		close(fd);
	test_kprobe_syscall__destroy(skel);
}
