// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

SEC("tp_btf/sched_pi_setprio")
__xlated("1: if r2 == 0x0 goto pc+2")
__xlated("3: goto pc+1")
__xlated("4: r0 = 2")
__success
__naked
int nullable(void *ctx)
{
	asm volatile (
	"r2 = *(u64 *)(r1 + 8);"
	"if r2 == 0x0 goto 2;"
	"r0 = 1;"
	"goto 1;"
	"r0 = 2;"
	"exit;");
}
