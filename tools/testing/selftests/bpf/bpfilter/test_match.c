// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include "context.h"
#include "match.h"

#include <linux/bpfilter.h>
#include <linux/err.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_tcpudp.h>

#include <stdio.h>

#include "../../kselftest_harness.h"

struct udp_match {
	struct xt_entry_match ipt_match;
	struct xt_udp udp;
};

FIXTURE(test_udp_match)
{
	struct context ctx;
	struct udp_match udp_match;
	struct match match;
};

FIXTURE_SETUP(test_udp_match)
{
	ASSERT_EQ(0, create_context(&self->ctx));
	self->ctx.log_file = stderr;

	memset(&self->udp_match, 0, sizeof(self->udp_match));
	snprintf(self->udp_match.ipt_match.u.user.name,
		 sizeof(self->udp_match.ipt_match.u.user.name), "udp");
	self->udp_match.ipt_match.u.user.match_size = sizeof(struct udp_match);
	self->udp_match.ipt_match.u.user.revision = 0;
};

FIXTURE_TEARDOWN(test_udp_match)
{
	free_context(&self->ctx);
}

TEST_F(test_udp_match, init)
{
	self->udp_match.udp.spts[0] = 1;
	self->udp_match.udp.spts[1] = 2;
	self->udp_match.udp.dpts[0] = 3;
	self->udp_match.udp.dpts[1] = 4;
	self->udp_match.udp.invflags = 0;

	ASSERT_EQ(init_match(&self->ctx,
			     (const struct bpfilter_ipt_match *)&self->udp_match
				     .ipt_match,
			     &self->match),
		  0);
}

TEST_HARNESS_MAIN
