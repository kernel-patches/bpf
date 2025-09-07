// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <sys/socket.h>

#include "bpf_termination.skel.h"

void test_loop_termination(void)
{
	struct bpf_termination *skel;
	int err;
	
	skel = bpf_termination__open();
	if (!ASSERT_OK_PTR(skel, "bpf_termination__open"))
	        return;
	
	err = bpf_termination__load(skel);
	if (!ASSERT_OK(err, "bpf_termination__load"))
	        goto out;
	
	skel->bss->pid = getpid();
	err = bpf_termination__attach(skel);
	if (!ASSERT_OK(err, "bpf_termination__attach"))
	        goto out;
	
	/* Triggers long running BPF program */
	socket(AF_UNSPEC, SOCK_DGRAM, 0);

	/* If the program is not terminated, it doesn't reach this point */
	ASSERT_TRUE(true, "Program is terminated");
out:
       bpf_termination__destroy(skel);
}

void test_bpf_termination(void)
{
	if (test__start_subtest("bpf_termination"))
		test_loop_termination();
}
