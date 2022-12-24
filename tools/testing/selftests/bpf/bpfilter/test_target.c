// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <linux/bpfilter.h>
#include <linux/netfilter/x_tables.h>

#include "../../kselftest_harness.h"

#include "context.h"
#include "logger.h"
#include "target.h"

#include "bpfilter_util.h"

FIXTURE(test_standard_target)
{
	struct context ctx;
	struct xt_standard_target ipt_target;
	struct target target;
};

FIXTURE_VARIANT(test_standard_target)
{
	int verdict;
};

FIXTURE_VARIANT_ADD(test_standard_target, accept) {
	.verdict = -BPFILTER_NF_ACCEPT - 1,
};

FIXTURE_VARIANT_ADD(test_standard_target, drop) {
	.verdict = -BPFILTER_NF_DROP - 1,
};

FIXTURE_SETUP(test_standard_target)
{
	logger_set_file(stderr);
	ASSERT_EQ(0, create_context(&self->ctx));

	memset(&self->ipt_target, 0, sizeof(self->ipt_target));
	init_standard_target(&self->ipt_target, 0, variant->verdict);
}

FIXTURE_TEARDOWN(test_standard_target)
{
	free_context(&self->ctx);
}

TEST_F(test_standard_target, init)
{
	ASSERT_EQ(0, init_target(&self->ctx, (const struct bpfilter_ipt_target *)&self->ipt_target,
				 &self->target));
}

FIXTURE(test_error_target)
{
	struct context ctx;
	struct xt_error_target ipt_target;
	struct target target;
};

FIXTURE_SETUP(test_error_target)
{
	logger_set_file(stderr);
	ASSERT_EQ(0, create_context(&self->ctx));

	memset(&self->ipt_target, 0, sizeof(self->ipt_target));
	init_error_target(&self->ipt_target, 0, "x");
}

FIXTURE_TEARDOWN(test_error_target)
{
	free_context(&self->ctx);
}

TEST_F(test_error_target, init)
{
	ASSERT_EQ(0, init_target(&self->ctx, (const struct bpfilter_ipt_target *)&self->ipt_target,
				 &self->target));
}

TEST_HARNESS_MAIN
