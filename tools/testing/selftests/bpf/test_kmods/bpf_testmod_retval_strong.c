// SPDX-License-Identifier: GPL-2.0
/*
 * Replaces the weak bpf_testmod_retval_overridden() of bpf_testmod_retval.c.
 * This definition returns no errors, so the function must not become an
 * fmod_ret target, see prog_tests/fmodret_retval.c.
 *
 * The weak bpf_testmod_retval_two_weak() here loses the link to the one of
 * bpf_testmod_retval.c, so its error must not make the function a target
 * either.
 */
#include <linux/compiler.h>
#include <linux/errno.h>

int bpf_testmod_retval_overridden(void);

noinline __attribute__((btf_decl_tag("test_retval:")))
int bpf_testmod_retval_overridden(void)
{
	return 0;
}

int bpf_testmod_retval_two_weak(void);

__weak noinline __attribute__((btf_decl_tag("test_retval:")))
int bpf_testmod_retval_two_weak(void)
{
	return -EINVAL;
}
