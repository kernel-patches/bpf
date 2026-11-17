// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

/* the old prototype of bpf_kfunc_flavor(), under local flavors */
extern int bpf_kfunc_flavor___old(int a) __ksym;
extern int bpf_kfunc_flavor___v1___local(int a) __ksym;
/* a prototype that no member of the family has */
extern int bpf_kfunc_flavor___none(void) __weak __ksym;

char _license[] SEC("license") = "GPL";

/* bpf_kfunc_flavor binds itself, though its alias ___v2 matches too */
SEC("syscall")
__retval(3)
int exact_name(void *ctx)
{
	return bpf_kfunc_flavor(1, 2);
}

/* the old prototype under a local flavor binds ___v1 */
SEC("syscall")
__retval(1)
int local_flavor(void *ctx)
{
	return bpf_kfunc_flavor___old(1);
}

/* so does the kernel name, which strips to bpf_kfunc_flavor */
SEC("syscall")
__retval(1)
int kernel_flavor(void *ctx)
{
	return bpf_kfunc_flavor___v1(1);
}

/* a local flavor on top of the kernel name binds ___v1 by name */
SEC("syscall")
__retval(1)
int stacked_flavor(void *ctx)
{
	return bpf_kfunc_flavor___v1___local(1);
}

/* a __weak kfunc that matches no member stays unresolved */
SEC("syscall")
__retval(0)
int no_match(void *ctx)
{
	return bpf_ksym_exists(bpf_kfunc_flavor___none);
}
