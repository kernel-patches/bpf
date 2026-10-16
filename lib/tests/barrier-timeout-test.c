// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests exercising smp_cond_load_{relaxed,acquire}_timeout().
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
	s64	extra;
	u32	niters;
};

#define TIMEOUT_MSEC	2
#define TEST_FLAG_VAL	BIT(17)
static unsigned int scu_flag;

static s64 basic_clock(struct clock_state *clk)
{
	clk->end_time = local_clock();
	return clk->end_time;
}

static void update_flags(void)
{
	WRITE_ONCE(scu_flag, TEST_FLAG_VAL);
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
	s64 runtime, timeout_ns = TIMEOUT_MSEC * NSEC_PER_MSEC;
	struct clock_state clk;
	unsigned int result;

	scu_flag = 0;

	preempt_disable();
	clk.start_time = clk.end_time = local_clock();

	if (p->acquire) {
		result = smp_cond_load_acquire_timeout(&scu_flag,
						       (VAL & TEST_FLAG_VAL),
						       p->clock(&clk),
						       timeout_ns);
	} else {
		result = smp_cond_load_relaxed_timeout(&scu_flag,
						       (VAL & TEST_FLAG_VAL),
						       p->clock(&clk),
						       timeout_ns);
	}
	preempt_enable();

	runtime = clk.end_time - clk.start_time;
	KUNIT_EXPECT_EQ(test, result, scu_flag);
	KUNIT_EXPECT_EQ(test, (bool)(result & TEST_FLAG_VAL), p->succeeds);
	if (!p->succeeds)
		KUNIT_EXPECT_GE(test, runtime, timeout_ns);
}

static s64 synthetic_clock(struct clock_state *clk)
{
	clk->end_time += clk->extra;
	clk->niters++;

	return clk->end_time;
}

struct smp_cond_expiry_params {
	char	*desc;
	u64	timeout_ns;
	s64	clk_unit;
	s64	miniters;
	s64	maxiters;
};

static const struct smp_cond_expiry_params expiry_params_list[] = {
	/* timeout_ns is invalid/out-of-range */
	{ .clk_unit = 0, .timeout_ns = -1LL,	.miniters = -1, .maxiters = 0, .desc = "invalid (-1LL)", },
	{ .clk_unit = 0, .timeout_ns = ~0ULL,	.miniters = -1, .maxiters = 0, .desc = "invalid (~0ULL)", },
	{ .clk_unit = 0, .timeout_ns = S64_MAX+1ULL, .miniters = -1, .maxiters = 0, .desc = "out-of-range (S64_MAX+1)", },
	{ .clk_unit = 0, .timeout_ns = U64_MAX,	.miniters = -1, .maxiters = 0, .desc = "out-of-range (U64_MAX)", },
	{ .clk_unit = 0, .timeout_ns = 0,	.miniters = -1, .maxiters = 1, .desc = "degenerate (0)",    },

	/* timeout_ns is valid */
	{ .clk_unit = (0x1ULL << 28), .timeout_ns = 1,		    .miniters = 1,	      .maxiters = -1, .desc = "1",    },
	{ .clk_unit = (0x1ULL << 28), .timeout_ns = (0x1ULL << 30), .miniters = 1 << (30-28), .maxiters = -1, .desc = "1<<30",   },
	{ .clk_unit = (0x1ULL << 28), .timeout_ns = S32_MAX,	    .miniters = 1 << (31-28), .maxiters = -1, .desc = "S32_MAX", },
	{ .clk_unit = (0x1ULL << 28), .timeout_ns = U32_MAX,	    .miniters = 1 << (32-28), .maxiters = -1, .desc = "U32_MAX", },
	{ .clk_unit = (0x1ULL << 28), .timeout_ns = (0x1ULL << 33), .miniters = 1 << (33-28), .maxiters = -1, .desc = "1<<33",   },
};

static void expiry_param_to_desc(const struct smp_cond_expiry_params *p, char *desc)
{
	char iters[32] = "";

	if (p->miniters != -1)
		snprintf(iters, 32, ">= %llx", (u64)p->miniters);
	else if (p->maxiters != -1)
		snprintf(iters, 32, "%s %llx", p->maxiters == 0 ? "==" : "<=", (u64)p->maxiters);

	snprintf(desc, KUNIT_PARAM_DESC_SIZE,
		 "smp_cond_*_timeout: clock=%s,  timeout=%s, iterations %s",
		 "synthetic/failing", p->desc, iters);
}

static char *expiry_skip_test(const struct smp_cond_expiry_params *p)
{
#ifdef CONFIG_ARM64

	/*
	 * WFXT waits for the full p->timeout_ns so limit it to a reasonable
	 * duration.
	 */
	if (alternative_has_cap_unlikely(ARM64_HAS_WFXT) &&
	    p->timeout_ns >= NSEC_PER_SEC) {

		return "runtime duration too long";
	}
#endif
	return NULL;
}

static void test_smp_cond_relaxed(struct kunit *test)
{
	const struct smp_cond_expiry_params *p = test->param_value;
	struct clock_state clk = {
		.start_time = 0,
		.end_time = 0,
		.extra = p->clk_unit,
		.niters = 0,
	};
	unsigned int result;
	s64 runtime;
	char *reason;

	reason = expiry_skip_test(p);
	if (reason)
		kunit_skip(test, "%s", reason);

	scu_flag = 0;

	preempt_disable();
	result = smp_cond_load_relaxed_timeout(&scu_flag,
						0,
						synthetic_clock(&clk),
						p->timeout_ns);
	preempt_enable();

	runtime = (u64)clk.end_time - (u64)clk.start_time;

	KUNIT_EXPECT_EQ(test, result, scu_flag);
	/*
	 * Check if we do the expected number of iterations.
	 */
	if (p->miniters != -1)
		KUNIT_EXPECT_GE(test, clk.niters, p->miniters);
	if (p->maxiters != -1)
		KUNIT_EXPECT_LE(test, clk.niters, p->maxiters);

	/*
	 * maxiters == 0 means that the timeout is invalid/out-of-range.
	 * When not, we cannot return with runtime < timeout_ns.
	 */
	if (p->maxiters != 0)
		KUNIT_EXPECT_GE(test, runtime, p->timeout_ns);
}

/*
 * Use a clock similar to the one used in rqspinlock where it start
 * returning failure value once it goes beyond the timeout.
 */
static s64 failing_clock(const struct smp_cond_expiry_params *p,
			 struct clock_state *clk)
{
	clk->end_time += clk->extra;
	clk->niters++;

	if ((u64)clk->end_time >= (u64)p->timeout_ns)
		return -ETIMEDOUT;

	return clk->end_time;
}

static void test_smp_cond_acquire_error(struct kunit *test)
{
	const struct smp_cond_expiry_params *p = test->param_value;
	struct clock_state clk = {
		.start_time = 0,
		.end_time = 0,
		.extra = p->clk_unit,
		.niters = 0,
	};
	unsigned int result;
	s64 ret = -ETIMEDOUT;
	char *reason;

	reason = expiry_skip_test(p);
	if (reason)
		kunit_skip(test, "%s", reason);

	scu_flag = 0;

	preempt_disable();
	result = smp_cond_load_acquire_timeout(&scu_flag,
						0,
						(ret = failing_clock(p, &clk)),
						p->timeout_ns);
	preempt_enable();

	KUNIT_EXPECT_EQ(test, result, scu_flag);
	if (p->miniters != -1)
		KUNIT_EXPECT_GE(test, clk.niters, p->miniters);
	if (p->maxiters != -1)
		KUNIT_EXPECT_LE(test, clk.niters, p->maxiters);

	/*
	 * scu_flag is never updated so the clock should eventually
	 * hit the timeout and error out.
	 */
	KUNIT_EXPECT_EQ(test, ret, -ETIMEDOUT);
}

KUNIT_ARRAY_PARAM(smp_cond_expiry_params, expiry_params_list, expiry_param_to_desc);
static struct kunit_case barrier_timeout_test_cases[] = {
	KUNIT_CASE_PARAM(test_smp_cond_timeout, smp_cond_update_params_gen_params),
	KUNIT_CASE_PARAM(test_smp_cond_relaxed, smp_cond_expiry_params_gen_params),
	KUNIT_CASE_PARAM(test_smp_cond_acquire_error, smp_cond_expiry_params_gen_params),
	{}
};

static struct kunit_suite barrier_timeout_test_suite = {
	.name = "smp-cond-load-*-timeout",
	.test_cases = barrier_timeout_test_cases,
};

kunit_test_suite(barrier_timeout_test_suite);

MODULE_DESCRIPTION("KUnit tests for smp_cond_load_{relaxed,acquire}_timeout()");
MODULE_LICENSE("GPL");
