// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_tcpudp.h>

#include "../../kselftest_harness.h"

#include "context.h"
#include "logger.h"
#include "match.h"

#include "bpfilter_util.h"

/**
 * struct udp_match - Dummy test structure.
 *
 * This structure provides enough space to allow for name too long, so it
 * doesn't overwrite anything.
 */
struct udp_match {
	struct xt_entry_match ipt_match;
	char placeholder[32];
};

FIXTURE(test_match_init)
{
	struct context ctx;
	struct udp_match udp_match;
	struct match match;
};

FIXTURE_SETUP(test_match_init)
{
	logger_set_file(stderr);
	ASSERT_EQ(0, create_context(&self->ctx));
};

FIXTURE_TEARDOWN(test_match_init)
{
	free_context(&self->ctx);
}

TEST_F(test_match_init, name_too_long)
{
	init_entry_match(&self->udp_match.ipt_match, sizeof(self->udp_match), 0,
			 "this match name is supposed to be way too long...");

	ASSERT_EQ(init_match(&self->ctx,
			     (const struct bpfilter_ipt_match *)&self->udp_match
				     .ipt_match,
			     &self->match),
		  -EINVAL);
}

TEST_F(test_match_init, not_found)
{
	init_entry_match(&self->udp_match.ipt_match, sizeof(self->udp_match), 0,
			 "doesn't exist");

	ASSERT_EQ(init_match(&self->ctx,
			     (const struct bpfilter_ipt_match *)&self->udp_match
				     .ipt_match,
			     &self->match),
		  -ENOENT);
}

TEST_HARNESS_MAIN
