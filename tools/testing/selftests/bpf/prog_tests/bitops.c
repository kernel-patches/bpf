// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "bitops.skel.h"

struct bitops_case {
	__u64 x;
	__u64 s;
	__u64 exp;
};

static struct bitops_case cases[] = {
	{ 0x0ULL, 0, 0 },
	{ 0x1ULL, 1, 0 },
	{ 0x8000000000000000ULL, 63, 0 },
	{ 0xffffffffffffffffULL, 64, 0 },
	{ 0x0123456789abcdefULL, 65, 0 },
	{ 0x0000000100000000ULL, 127, 0 },
};

static __u64 clz64(__u64 x, __u64 s)
{
	(void)s;
	return x ? __builtin_clzll(x) : 64;
}

static __u64 ctz64(__u64 x, __u64 s)
{
	(void)s;
	return x ? __builtin_ctzll(x) : 64;
}

static __u64 ffs64(__u64 x, __u64 s)
{
	(void)s;
	return x ? (__u64)__builtin_ctzll(x) + 1 : 0;
}

static __u64 fls64(__u64 x, __u64 s)
{
	(void)s;
	return x ? 64 - __builtin_clzll(x) : 0;
}

static __u64 popcnt64(__u64 x, __u64 s)
{
	(void)s;
	return __builtin_popcountll(x);
}

static __u64 bitrev64(__u64 x, __u64 s)
{
	__u64 y = 0;
	int i;

	(void)s;

	for (i = 0; i < 64; i++) {
		y <<= 1;
		y |= x & 1;
		x >>= 1;
	}
	return y;
}

static __u64 rol64(__u64 x, __u64 s)
{
	s &= 63;
	return (x << s) | (x >> ((-s) & 63));
}

static __u64 ror64(__u64 x, __u64 s)
{
	s &= 63;
	return (x >> s) | (x << ((-s) & 63));
}

static void test_bitops_case(const char *prog_name)
{
	struct bpf_program *prog;
	struct bitops *skel;
	size_t i;
	int err;
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel = bitops__open();
	if (!ASSERT_OK_PTR(skel, "bitops__open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto cleanup;

	bpf_program__set_autoload(prog, true);

	err = bitops__load(skel);
	if (!ASSERT_OK(err, "bitops__load"))
		goto cleanup;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		skel->bss->in_x = cases[i].x;
		skel->bss->in_s = cases[i].s;
		err = bpf_prog_test_run_opts(bpf_program__fd(prog), &topts);
		if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
			goto cleanup;

		if (!ASSERT_OK(topts.retval, "retval"))
			goto cleanup;

		ASSERT_EQ(skel->bss->out, cases[i].exp, "out");
	}

cleanup:
	bitops__destroy(skel);
}

#define RUN_BITOPS_CASE(_bitops, _prog)					\
	do {								\
		for (size_t i = 0; i < ARRAY_SIZE(cases); i++)		\
			cases[i].exp = _bitops(cases[i].x, cases[i].s);	\
		test_bitops_case(_prog);				\
	} while (0)

static void test_clz64(void)
{
	RUN_BITOPS_CASE(clz64, "bitops_clz64");
}

static void test_ctz64(void)
{
	RUN_BITOPS_CASE(ctz64, "bitops_ctz64");
}

static void test_ffs64(void)
{
	RUN_BITOPS_CASE(ffs64, "bitops_ffs64");
}

static void test_fls64(void)
{
	RUN_BITOPS_CASE(fls64, "bitops_fls64");
}

static void test_bitrev64(void)
{
	RUN_BITOPS_CASE(bitrev64, "bitops_bitrev");
}

static void test_popcnt64(void)
{
	RUN_BITOPS_CASE(popcnt64, "bitops_popcnt");
}

static void test_rol64(void)
{
	RUN_BITOPS_CASE(rol64, "bitops_rol64");
}

static void test_ror64(void)
{
	RUN_BITOPS_CASE(ror64, "bitops_ror64");
}

void test_bitops(void)
{
	if (test__start_subtest("clz64"))
		test_clz64();
	if (test__start_subtest("ctz64"))
		test_ctz64();
	if (test__start_subtest("ffs64"))
		test_ffs64();
	if (test__start_subtest("fls64"))
		test_fls64();
	if (test__start_subtest("bitrev64"))
		test_bitrev64();
	if (test__start_subtest("popcnt64"))
		test_popcnt64();
	if (test__start_subtest("rol64"))
		test_rol64();
	if (test__start_subtest("ror64"))
		test_ror64();
}
