// SPDX-License-Identifier: GPL-2.0-only
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

__weak
void foo(void)
{
}

SEC("tc")
__failure __msg("!read_ok")
int global_func18(struct __sk_buff *skb)
{
	foo();

	asm volatile(
		"r1 = r0;"
		:::
	);

	return 0;
}
