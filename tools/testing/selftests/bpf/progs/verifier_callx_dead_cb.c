// SPDX-License-Identifier: GPL-2.0
/* libbpf appends all functions of the table to the prog, hence a file of its own. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#ifdef CAN_USE_CALLX

__naked __noinline __used static int live_func(void)
{
	asm volatile ("r0 = 3; exit;");
}

__naked __noinline __used static int dead_cb(void)
{
	asm volatile ("r0 = 0; exit;");
}

/* The loop has no iterations. The callback is the last function and it is removed. */
SEC("socket")
__success __retval(3)
__naked void loop_with_dead_callback(void)
{
	asm volatile (
	".pushsection .rodata,\"a\",@progbits;"
	".balign 8;"
"funcs_%=:"
	".quad live_func;"
	".quad dead_cb;"
	".type funcs_%=, @object;"
	".size funcs_%=, .-funcs_%=;"
	".popsection;"
	"r6 = funcs_%= ll;"
	"r1 = 0;"
	"r2 = *(u64 *)(r6 + 8);"
	"r3 = 0;"
	"r4 = 0;"
	"call %[bpf_loop];"
	"r2 = *(u64 *)(r6 + 0);"
	"callx r2;"
	"exit;"
	:
	: __imm(bpf_loop)
	: __clobber_all);
}

#else

SEC("socket")
__skip("callx needs arch JIT and compiler support")
__success
int dummy(void *ctx)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
