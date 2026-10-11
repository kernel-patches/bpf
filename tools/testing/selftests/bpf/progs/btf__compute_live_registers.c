// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* Use both parameters so clang keeps them in the static functions' BTF. */
static __noinline __used int static_two(int a, int b)
{
	return a + b;
}

static __noinline __used int static_three(int a, int b)
{
	return a + b;
}

__noinline __used int global_two(int a, int b)
{
	return a;
}
