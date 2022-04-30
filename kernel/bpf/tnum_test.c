// SPDX-License-Identifier: GPL-2.0-or-later
/* Soundness tests for tnums.
 *
 * Its important that tnums (and other BPF verifier analyses) soundly
 * overapproximate the runtime values of registers. If they fail to do so, then
 * kernel memory corruption may result (see e.g., CVE-2020-8835 and
 * CVE-2021-3490 for examples where unsound bounds tracking led to exploitable
 * bugs).
 *
 * The implementations of some tnum arithmetic operations have been proven
 * sound, see "Sound, Precise, and Fast Abstract Interpretation with Tristate
 * Numbers" (https://arxiv.org/abs/2105.05398). These tests corroborate these
 * results on actual machine hardware, protect against regressions if the
 * implementations change, and provide a template for testing new abstract
 * operations.
 */

#include <kunit/test.h>
#include <linux/tnum.h>

/* Some number of test cases, particular values not super important but chosen
 * to be most likely to trigger edge cases.
 */
static u64 interesting_ints[] = { S64_MIN, S32_MIN, -1,	     0,
				  1,	   2,	    U32_MAX, U64_MAX };

typedef struct tnum (*tnum_binop_fun)(struct tnum a, struct tnum b);
typedef u64 (*u64_binop_fun)(u64 a, u64 b);

struct tnum_binop {
	tnum_binop_fun tnum_binop;
	u64_binop_fun u64_binop;
};

static u64 u64_add(u64 a, u64 b)
{
	return a + b;
}
static u64 u64_sub(u64 a, u64 b)
{
	return a - b;
}
static u64 u64_mul(u64 a, u64 b)
{
	return a * b;
}
static u64 u64_and(u64 a, u64 b)
{
	return a & b;
}
static u64 u64_or(u64 a, u64 b)
{
	return a | b;
}
static u64 u64_xor(u64 a, u64 b)
{
	return a ^ b;
}

static const struct tnum_binop ADD_BINOP = { .tnum_binop = tnum_add,
					     .u64_binop = u64_add };

static const struct tnum_binop SUB_BINOP = { .tnum_binop = tnum_sub,
					     .u64_binop = u64_sub };

static const struct tnum_binop MUL_BINOP = { .tnum_binop = tnum_mul,
					     .u64_binop = u64_mul };

static const struct tnum_binop AND_BINOP = { .tnum_binop = tnum_and,
					     .u64_binop = u64_and };

static const struct tnum_binop OR_BINOP = { .tnum_binop = tnum_or,
					    .u64_binop = u64_or };

static const struct tnum_binop XOR_BINOP = { .tnum_binop = tnum_xor,
					     .u64_binop = u64_xor };

static struct tnum *test_tnums;

#define NUM_TEST_TNUMS (1 + ARRAY_SIZE(interesting_ints))

/* Test setup: Generate some number of tnums to be used in test cases, store
 * them in test_tnums.
 */
static int tnum_test_init(struct kunit *test)
{
	struct tnum *tests;

	test_tnums = kunit_kmalloc_array(test, NUM_TEST_TNUMS,
					 sizeof(struct tnum), GFP_KERNEL);
	tests = test_tnums;

	*tests = tnum_unknown;
	tests++;
	for (int i = 0; i < ARRAY_SIZE(interesting_ints); i++) {
		*tests = tnum_const(interesting_ints[i]);
		tests++;
	}
	return 0;
}

static void tnum_test_exit(struct kunit *test)
{
	kfree(test_tnums);
}

static int valid(struct tnum t)
{
	return (t.value & t.mask) == 0;
}

/* Check whether a number is in the set of numbers represented by a tnum. */
static int member(struct tnum t, u64 x)
{
	return valid(t) ? (x & (~t.mask)) == t.value : 0;
}

static void test_tnum_valid(struct kunit *test)
{
	for (int i = 0; i < NUM_TEST_TNUMS; i++)
		KUNIT_EXPECT_EQ(test, 1, valid(test_tnums[i]));
}

/* Check that a binary operation (binop) on tnums soundly overapproximates the
 * corresponding operation on u64s.
 *
 * These tests are not exhaustive - they only check that applying the u64 binop
 * in question to the minimum and maximum u64s represented by the tnum (in
 * either order) results in a u64 that is represented by the result of the
 * corresponding tnum binop.
 *
 * Also checks that each operation takes valid tnums to valid tnums.
 */
static void tnum_binop_test(struct kunit *test, struct tnum_binop binop)
{
	u64 ll;
	u64 lu;
	u64 ul;
	u64 uu;
	struct tnum x;
	struct tnum y;
	struct tnum result;

	for (int i = 0; i < NUM_TEST_TNUMS; i++) {
		for (int j = 0; j < NUM_TEST_TNUMS; j++) {
			x = test_tnums[i];
			y = test_tnums[j];
			result = binop.tnum_binop(x, y);

			KUNIT_EXPECT_EQ(test, 1, valid(result));

			ll = binop.u64_binop(x.value, y.value);
			lu = binop.u64_binop(x.value, (y.value | y.mask));
			ul = binop.u64_binop((x.value | x.mask), y.value);
			uu = binop.u64_binop((x.value | x.mask),
					     (y.value | y.mask));
			KUNIT_EXPECT_EQ(test, 1, member(result, ll));
			KUNIT_EXPECT_EQ(test, 1, member(result, lu));
			KUNIT_EXPECT_EQ(test, 1, member(result, ul));
			KUNIT_EXPECT_EQ(test, 1, member(result, uu));
		}
	}
}

static void test_tnum_add(struct kunit *test)
{
	tnum_binop_test(test, ADD_BINOP);
}

static void test_tnum_sub(struct kunit *test)
{
	tnum_binop_test(test, SUB_BINOP);
}

static void test_tnum_mul(struct kunit *test)
{
	tnum_binop_test(test, MUL_BINOP);
}

static void test_tnum_and(struct kunit *test)
{
	tnum_binop_test(test, AND_BINOP);
}

static void test_tnum_or(struct kunit *test)
{
	tnum_binop_test(test, OR_BINOP);
}

static void test_tnum_xor(struct kunit *test)
{
	tnum_binop_test(test, XOR_BINOP);
}

static struct kunit_case tnum_test_cases[] = {
	KUNIT_CASE(test_tnum_valid), KUNIT_CASE(test_tnum_add),
	KUNIT_CASE(test_tnum_sub),   KUNIT_CASE(test_tnum_mul),
	KUNIT_CASE(test_tnum_and),   KUNIT_CASE(test_tnum_or),
	KUNIT_CASE(test_tnum_xor),   {}
};

static struct kunit_suite tnum_test_suite = {
	.name = "tnum",
	.init = tnum_test_init,
	.exit = tnum_test_exit,
	.test_cases = tnum_test_cases,
};
kunit_test_suite(tnum_test_suite);
