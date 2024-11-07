#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__xlated("0: r1 = 1")
__xlated("1: r0 = 42")
__xlated("2: r0 = 24")
__xlated("3: exit")
__success
__retval(24)
__naked void cond_always_false(void)
{
	asm volatile (
		"r1 = 1;"
		"r0 = 42;"
		"if r1 != 1 goto +1;"
		"r0 = 24;"
		"exit;"
		::: __clobber_all
	);
}

SEC("socket")
__xlated("0: r1 = 2")
__xlated("1: r0 = 42")
__xlated("2: exit")
__success
__retval(42)
__naked void cond_always_true(void)
{
	asm volatile (
		"r1 = 2;"
		"r0 = 42;"
		"if r1 != 1 goto +1;"
		"r0 = 24;"
		"exit;"
		::: __clobber_all
	);
}

SEC("socket")
__xlated("0: call")
__xlated("1: r1 = r0")
__xlated("2: r0 = 42")
__xlated("3: if r1 != 0x1 goto pc+1")
__xlated("4: r0 = 24")
__xlated("5: exit")
__success
__naked void cond_unknown(void)
{
	asm volatile (
		"call %[bpf_get_prandom_u32];"
		"r1 = r0;"
		"r0 = 42;"
		"if r1 != 1 goto +1;"
		"r0 = 24;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}
