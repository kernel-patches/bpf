/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Data Access Monitor Unit Tests
 */

#ifdef CONFIG_DAMON_PADDR_KUNIT_TEST

#ifndef _DAMON_PADDR_TEST_H
#define _DAMON_PADDR_TEST_H

#include <kunit/test.h>

static void damon_test_pa_phys_addr(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, damon_pa_phys_addr(0x1000, 1), 0x1000);
	KUNIT_EXPECT_EQ(test, damon_pa_phys_addr(0x40000, 0x1000), 0x40000000);
}

static void damon_test_pa_core_addr(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, damon_pa_core_addr(0x1000000, 0x1000), 0x1000);
	/* The conversion rounds down. */
	KUNIT_EXPECT_EQ(test, damon_pa_core_addr(0x1fff, 0x1000), 1);
	KUNIT_EXPECT_EQ(test, damon_pa_core_addr(0xfff, 0x1000), 0);
}

static void damon_test_pa_addr_over_4g(struct kunit *test)
{
	unsigned long addr = 0xffffffffUL;
	unsigned long addr_unit = 0x1000;
	u64 pa = 0xffffffff000ULL;

	if (!IS_ENABLED(CONFIG_PHYS_ADDR_T_64BIT))
		kunit_skip(test, "phys_addr_t is 32-bit");

	KUNIT_EXPECT_EQ(test, damon_pa_phys_addr(addr, addr_unit), pa);
	KUNIT_EXPECT_EQ(test, damon_pa_core_addr(pa, addr_unit), addr);
}

static struct kunit_case damon_paddr_test_cases[] = {
	KUNIT_CASE(damon_test_pa_phys_addr),
	KUNIT_CASE(damon_test_pa_core_addr),
	KUNIT_CASE(damon_test_pa_addr_over_4g),
	{},
};

static struct kunit_suite damon_paddr_test_suite = {
	.name = "damon-paddr",
	.test_cases = damon_paddr_test_cases,
};
kunit_test_suite(damon_paddr_test_suite);

#endif /* _DAMON_PADDR_TEST_H */

#endif	/* CONFIG_DAMON_PADDR_KUNIT_TEST */
