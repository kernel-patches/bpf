// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests exercising smp_cond_load_relaxed_timeout().
 *
 * Copyright (c) 2026, Oracle Corp.
 * Author: Ankur Arora <ankur.a.arora@oracle.com>
 */

#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/sched/clock.h>
#include <linux/delay.h>
#include <asm/barrier.h>
#include <kunit/test.h>
#include <kunit/visibility.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

struct clock_state {
	s64	start_time;
	s64	end_time;
};

#define TIMEOUT_MSEC	2
#define TEST_FLAG_VAL	BIT(2)
static unsigned int flag;

static s64 basic_clock(struct clock_state *clk)
{
	clk->end_time = local_clock();
	return clk->end_time;
}

static void update_flags(void)
{
	WRITE_ONCE(flag, TEST_FLAG_VAL);
}

static s64 mocked_clock(struct clock_state *clk)
{
	s64 clk_mid = clk->start_time + (TIMEOUT_MSEC * NSEC_PER_MSEC)/2;

	clk->end_time = local_clock();
	if (clk->end_time >= clk_mid)
		update_flags();
	return clk->end_time;
}

typedef s64 (*clkfn_t)(struct clock_state *);
struct smp_cond_update_params {
	clkfn_t	clock;
	bool	acquire;
	bool	succeeds;
};

static const struct smp_cond_update_params update_params_list[] = {
	/* mocked-clock updates flag inline. */
	{ .clock = &mocked_clock, .succeeds = true, .acquire = false, },
	{ .clock = &mocked_clock, .succeeds = true, .acquire = true,  },

	/* basic-clock doesn't update flag. */
	{ .clock = &basic_clock, .succeeds = false,  .acquire = true, },
	{ .clock = &basic_clock, .succeeds = false,  .acquire = false, },
};

static void param_to_desc(const struct smp_cond_update_params *p, char *desc)
{
	char *clk = NULL, *update = NULL;

	if (p->clock == &mocked_clock) {
		clk = "mocked";
		update = "inline";
	} else if (p->clock == &basic_clock) {
		clk = "basic";
		update = "none";
	}

	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "smp_cond_%s_timeout: clock=%s, update=%s",
		p->acquire ? "acquire" : "relaxed", clk, update);
}

KUNIT_ARRAY_PARAM(smp_cond_update_params, update_params_list, param_to_desc);

static void test_smp_cond_timeout(struct kunit *test)
{
	const struct smp_cond_update_params *p = test->param_value;
	struct clock_state clk = {
		.start_time = local_clock(),
		.end_time = local_clock(),
	};
	s64 runtime, timeout_ns = TIMEOUT_MSEC * NSEC_PER_MSEC;
	unsigned int result;

	flag = 0;
	if (p->acquire) {
		result = smp_cond_load_acquire_timeout(&flag,
						       (VAL & TEST_FLAG_VAL),
						       p->clock(&clk),
						       timeout_ns);
	} else {
		result = smp_cond_load_relaxed_timeout(&flag,
						       (VAL & TEST_FLAG_VAL),
						       p->clock(&clk),
						       timeout_ns);
	}

	runtime = clk.end_time - clk.start_time;
	KUNIT_EXPECT_EQ(test, (bool)(result & TEST_FLAG_VAL), p->succeeds);
	if (!p->succeeds)
		KUNIT_EXPECT_GE(test, runtime, timeout_ns);
}

static struct kunit_case barrier_timeout_test_cases[] = {
	KUNIT_CASE_PARAM(test_smp_cond_timeout, smp_cond_update_params_gen_params),
	{}
};

static struct kunit_suite barrier_timeout_test_suite = {
	.name = "smp-cond-load-*-timeout",
	.test_cases = barrier_timeout_test_cases,
};

kunit_test_suite(barrier_timeout_test_suite);

MODULE_DESCRIPTION("KUnit tests for smp_cond_load_relaxed_timeout()");
MODULE_LICENSE("GPL");
