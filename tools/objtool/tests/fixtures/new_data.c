// SPDX-License-Identifier: GPL-2.0
/* Data introduced by the patch. */

static const char __modinfo[]
	__attribute__((section(".modinfo"), used, aligned(1))) = "\0name=vmlinux";

#ifdef PATCHED
static const int klp_new_data[4] = { 1, 2, 3, 4 };
#endif

int target(int x)
{
#ifdef PATCHED
	return x + klp_new_data[x & 3];
#else
	return x;
#endif
}
