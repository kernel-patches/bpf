// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "err.h"

char _license[] SEC("license") = "GPL";

SEC("fmod_ret/bpf_testmod_modify_return_ptr")
__load_if_JITed()
__success
void *BPF_PROG(error)
{
	return ERR_PTR(-EINVAL);
}

/* For the extension of prog_tests/modify_return.c */
__noinline int global_func(int x)
{
	/*
	 * The barrier here is needed because otherwise clang can drop
	 * the call, and there is nothing to replace
	 */
	barrier_var(x);
	return x;
}

SEC("fmod_ret/bpf_testmod_modify_return_ptr")
__load_if_JITed()
__success
void *BPF_PROG(calls_global)
{
	return global_func(0) ? ERR_PTR(-EINVAL) : NULL;
}

SEC("fmod_ret/bpf_testmod_modify_return_ptr")
__failure __msg("should have been in [-4095, 0]")
void *BPF_PROG(not_an_error)
{
	return (void *)1;
}
