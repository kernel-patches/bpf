// SPDX-License-Identifier: GPL-2.0
/* An extension of a global function of an fmod_ret program, see prog_tests/modify_return.c */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("freplace")
int replace_global(int x)
{
	return 7;
}
