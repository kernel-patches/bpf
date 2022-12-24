// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_tcpudp.h>

#include "../../kselftest_harness.h"

#include "context.h"
#include "logger.h"
#include "match.h"

#include "bpfilter_util.h"

FIXTURE(test_xt_udp)
{
	struct context ctx;
	struct {
		struct xt_entry_match match;
		struct xt_udp udp;

	} ipt_match;
	struct match match;
};

FIXTURE_SETUP(test_xt_udp)
{
	logger_set_file(stderr);
	ASSERT_EQ(0, create_context(&self->ctx));
};

FIXTURE_TEARDOWN(test_xt_udp)
{
	free_context(&self->ctx);
};

TEST_F(test_xt_udp, init)
{
	init_entry_match((struct xt_entry_match *)&self->ipt_match,
			 sizeof(self->ipt_match), 0, "udp");
	ASSERT_EQ(init_match(&self->ctx,
			     (const struct bpfilter_ipt_match *)&self->ipt_match,
			     &self->match),
		 0);
}

TEST_HARNESS_MAIN
