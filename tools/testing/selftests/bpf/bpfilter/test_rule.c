// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include "rule.h"

#include <linux/bpfilter.h>
#include <linux/err.h>

#include <linux/netfilter_ipv4/ip_tables.h>

#include <stdio.h>
#include <stdlib.h>

#include "../../kselftest_harness.h"

#include "context.h"
#include "logger.h"
#include "rule.h"

#include "bpfilter_util.h"

FIXTURE(test_standard_rule)
{
	struct context ctx;
	struct {
		struct ipt_entry entry;
		struct xt_standard_target target;
	} entry;
	struct rule rule;
};

FIXTURE_SETUP(test_standard_rule)
{
	const int verdict = BPFILTER_NF_ACCEPT;

	logger_set_file(stderr);
	ASSERT_EQ(create_context(&self->ctx), 0);

	init_standard_entry(&self->entry.entry, 0);
	init_standard_target(&self->entry.target, 0, -verdict - 1);
}

FIXTURE_TEARDOWN(test_standard_rule)
{
	free_rule(&self->rule);
	free_context(&self->ctx);
}

TEST_F(test_standard_rule, init)
{
	ASSERT_EQ(0, init_rule(&self->ctx, (const struct bpfilter_ipt_entry *)&self->entry.entry,
			       &self->rule));
}

TEST_HARNESS_MAIN
