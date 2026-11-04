// SPDX-License-Identifier: GPL-2.0
/*
 * An extension of fmod_ret programs, see prog_tests/fmodret_retval.c. The
 * return values of the program on bpf_testmod_retval_constant() are restricted
 * by its "bpf_fmodret_retval:" tag, those of the program on the declared target
 * are not. An extension cannot replace the main function of a tracing program,
 * so each of them calls a global function which the extension replaces.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* Keeps clang from folding the calls */
int value_bias;

__noinline int restricted_value(int value)
{
	return value + value_bias;
}

__noinline int unrestricted_value(int value)
{
	return value + value_bias;
}

SEC("fmod_ret/bpf_testmod_retval_constant")
int BPF_PROG(restricted, int ret)
{
	int zero;

	if (restricted_value(ret))
		return -22;
	/*
	 * fmodret BPF progs must return only allowed values. If this zero is
	 * not forced here, the function, compiled with GCC, will return R0
	 * which is a scalar in [S32_MIN, S32_MAX]: a sign-extended copy of the
	 * result of restricted_value() made before the result is tested for 0.
	 */
	asm volatile("%[z] = 0" : [z]"=r"(zero));
	return zero;
}

SEC("fmod_ret/bpf_testmod_retval_declared")
int BPF_PROG(unrestricted, int ret)
{
	return unrestricted_value(ret);
}

SEC("freplace")
int extension(int value)
{
	return -1;
}
