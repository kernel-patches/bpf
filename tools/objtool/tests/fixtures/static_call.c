// SPDX-License-Identifier: GPL-2.0
/*
 * Static call site in a patched function, laid out by hand as for
 * jump_label.c.  MODNAME selects whether the key belongs to vmlinux or a
 * module.
 */

#ifndef MODNAME
#define MODNAME "vmlinux"
#endif

static const char __modinfo[]
	__attribute__((section(".modinfo"), used, aligned(1))) = "\0name=" MODNAME;

long __SCK__klp_test_call = 0;

int target(int x)
{
	__asm__ volatile(
		"1:	nop						\n\t"
		".pushsection	.static_call_sites, \"aw\"		\n\t"
		".balign	8					\n\t"
		"912:							\n\t"
		".pushsection	.discard.annotate_data, \"M\", @progbits, 8\n\t"
		".long		912b - ., 1				\n\t"
		".popsection						\n\t"
		".long		1b - ., %c0 - .				\n\t"
		".popsection						\n\t"
		:: "i" (&__SCK__klp_test_call));
#ifdef PATCHED
	return x + 2;
#else
	return x + 1;
#endif
}
