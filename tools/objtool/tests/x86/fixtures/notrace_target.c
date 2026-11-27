// SPDX-License-Identifier: GPL-2.0
/* PATCH_<name> changes <name> in the patched build. */
#define notrace __attribute__((__no_instrument_function__))

static const char __modinfo[]
	__attribute__((section(".modinfo"), used, aligned(1))) = "\0name=vmlinux";

#ifndef PATCHED
#undef PATCH_OUTLINED
#undef PATCH_NOTRACE
#undef PATCH_INLINED
#undef PATCH_TRACED
#endif

#ifdef PATCH_OUTLINED
#define OUTLINED_K 2
#else
#define OUTLINED_K 1
#endif

#ifdef PATCH_NOTRACE
#define NOTRACE_K 2
#else
#define NOTRACE_K 1
#endif

#ifdef PATCH_INLINED
#define INLINED_K 2
#else
#define INLINED_K 1
#endif

#ifdef PATCH_TRACED
#define TRACED_K 2
#else
#define TRACED_K 1
#endif

int sink;

/* Address taken, so emitted out of line. */
static inline notrace int outlined(int x)
{
	int i;

	for (i = 0; i < x; i++)
		sink += i * OUTLINED_K;
	return sink;
}

int (*outlined_ptr)(int) = outlined;

notrace int notrace_fn(int x)
{
	return x * 3 + NOTRACE_K;
}

static inline int inlined(int x)
{
	return x + INLINED_K;
}

int inlined_user(int x)
{
	return inlined(x) * 5;
}

int traced(int x)
{
	return x * 7 + TRACED_K;
}
