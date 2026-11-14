// SPDX-License-Identifier: GPL-2.0
/* Extensions for the main program of an fmod_ret program, see prog_tests/fmodret_retval.c */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("freplace")
int plain_ctx(unsigned long long *ctx)
{
	return 7;
}

SEC("freplace")
int arg_ctx(unsigned long long *ctx __arg_ctx)
{
	return 7;
}
