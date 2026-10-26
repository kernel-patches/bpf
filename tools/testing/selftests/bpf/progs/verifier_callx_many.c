// SPDX-License-Identifier: GPL-2.0
/*
 * callx through a table of many functions. libbpf appends the functions that read-only
 * data points to to every prog of the object that has callx, hence a file of its own.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../../../include/linux/filter.h"

/* gcc doesn't support indirect calls */
#if defined(__clang__) && (defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64) || \
    (defined(__TARGET_ARCH_riscv) && __riscv_xlen == 64))

/*
 * Read-only data with pointers to functions, where the compiler puts tables
 * of functions, structures of operations and vtables. libbpf resolves
 * a pointer to the offset of the function in the program and the kernel
 * recognizes it by that value.
 */
#define DATA(SECTION, NAME, ...)				\
	".pushsection " SECTION ",@progbits;"			\
	".balign 8;"						\
	#NAME "_%=:"						\
	__VA_ARGS__						\
	".type " #NAME "_%=, @object;"				\
	".size " #NAME "_%=, .-" #NAME "_%=;"			\
	".popsection;"

#define RODATA(NAME, ...) DATA(".rodata,\"a\"", NAME, __VA_ARGS__)

#define REP10(M, p) M(p##0) M(p##1) M(p##2) M(p##3) M(p##4) M(p##5) M(p##6) M(p##7) M(p##8) M(p##9)
#define REP100(M, p) REP10(M, p##0) REP10(M, p##1) REP10(M, p##2) REP10(M, p##3) REP10(M, p##4) \
		     REP10(M, p##5) REP10(M, p##6) REP10(M, p##7) REP10(M, p##8) REP10(M, p##9)
#define REP400(M) REP100(M, 0) REP100(M, 1) REP100(M, 2) REP100(M, 3)

#define MANY_FUNC(n)						\
__naked __noinline __used static unsigned long many##n(void)	\
{								\
	asm volatile ("r0 = r1; r0 += 1; exit;");		\
}
#define MANY_QUAD(n) ".quad many" #n ";"

REP400(MANY_FUNC)

/* 3 states that have no join get to a table of 400 functions: 3 states, and not 1200 */
SEC("socket")
__success __retval(11)
__naked void callx_rodata_400_functions(void)
{
	asm volatile (
		RODATA(big, REP400(MANY_QUAD))
		"r7 = r1;"
		"call %[bpf_get_prandom_u32];"
		"if r0 == 1 goto 1f;"
		"r7 = r10;"
		"if r0 == 2 goto 1f;"
		"r7 = 0;"
	"1:"
		"call %[bpf_get_prandom_u32];"
		"if r0 > 399 goto 2f;"
		"r0 <<= 3;"
		"r2 = big_%= ll;"
		"r2 += r0;"
		"r2 = *(u64 *)(r2 + 0);"
		"r1 = 10;"
		"callx r2;"
		"if r7 != 0 goto +0;"
		"exit;"
	"2:"
		"r0 = 11;"
		"exit;"
		:
		: __imm(bpf_get_prandom_u32)
		: __clobber_all);
}

#else

SEC("socket")
__success
int dummy(void *ctx)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
