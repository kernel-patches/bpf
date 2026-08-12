// SPDX-License-Identifier: GPL-2.0
/*
 * Static branch in a patched function.  The jump table entry is written out by
 * hand, mirroring JUMP_TABLE_ENTRY(), so the fixture builds without kernel
 * headers.  The key is an STT_OBJECT; anything else is ignored by
 * validate_special_section_klp_reloc().
 *
 * MODNAME selects whether the key is taken to belong to vmlinux or a module.
 */

#ifndef MODNAME
#define MODNAME "vmlinux"
#endif

static const char __modinfo[]
	__attribute__((section(".modinfo"), used, aligned(1))) = "\0name=" MODNAME;

long klp_test_key = 0;

int target(int x)
{
	int r = x;

	asm goto(
		"1:	nop						\n\t"
		".pushsection	__jump_table, \"aw\"			\n\t"
		".balign	8					\n\t"
		"912:							\n\t"
		".pushsection	.discard.annotate_data, \"M\", @progbits, 8\n\t"
		".long		912b - ., 1				\n\t"
		".popsection						\n\t"
		".long		1b - ., %l[l_yes] - .			\n\t"
		".quad		%c0 - .					\n\t"
		".popsection						\n\t"
		: : "i" (&klp_test_key) : : l_yes);

	r += 1;
	goto out;
l_yes:
	r += 2;
out:
#ifdef PATCHED
	return r + 100;
#else
	return r;
#endif
}
