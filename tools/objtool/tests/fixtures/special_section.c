// SPDX-License-Identifier: GPL-2.0
/*
 * Special section entry with no ANNOTATE_DATA_SPECIAL annotation and a local
 * label at offset 0, the shape Clang produces for .kcfi_traps.
 */

static const char __modinfo[]
	__attribute__((section(".modinfo"), used, aligned(1))) = "\0name=vmlinux";

int target(int x)
{
	asm volatile(
		"1:						\n\t"
		".pushsection	.smp_locks, \"a\"		\n\t"
		".balign	4				\n\t"
		"sl_marker:					\n\t"
		".long		1b - .				\n\t"
		".popsection					\n\t");
#ifdef PATCHED
	return x + 2;
#else
	return x + 1;
#endif
}
