// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Ibrahim Zein <zeroxjacks@gmail.com> */
#include <test_progs.h>
#include "test_snprintf_ip.skel.h"

#define EXP_IP4_OUT  "192.168.1.1"
#define EXP_IP4_RET  sizeof(EXP_IP4_OUT)

#define EXP_WORST_IP4_OUT  "255.255.255.255"
#define EXP_WORST_IP4_RET  sizeof(EXP_WORST_IP4_OUT)

#define EXP_IP6_OUT  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
#define EXP_IP6_RET  sizeof(EXP_IP6_OUT)

void test_snprintf_ip(void)
{
	struct test_snprintf_ip *skel;

	skel = test_snprintf_ip__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	skel->bss->pid = getpid();

	if (!ASSERT_OK(test_snprintf_ip__attach(skel), "skel_attach"))
		goto cleanup;

	/* trigger tracepoint */
	usleep(1);

	/* Test 1: normal IPv4 */
	ASSERT_STREQ(skel->bss->ip4_out, EXP_IP4_OUT, "ip4_out");
	ASSERT_EQ(skel->bss->ip4_ret, EXP_IP4_RET, "ip4_ret");

	/* Test 2: normal IPv6 */
	ASSERT_STREQ(skel->bss->ip6_out, EXP_IP6_OUT, "ip6_out");
	ASSERT_EQ(skel->bss->ip6_ret, EXP_IP6_RET, "ip6_ret");

	/* Test 3: worst-case IPv4 "255.255.255.255" */
	ASSERT_STREQ(skel->bss->worst_ip4_out, EXP_WORST_IP4_OUT,
		     "worst_ip4_out");
	ASSERT_EQ(skel->bss->worst_ip4_ret, EXP_WORST_IP4_RET,
		  "worst_ip4_ret");

	/*
	 * Test 4: near-overflow scenario.
	 * Before fix: tmp_buf overflows, kernel may crash or corrupt memory.
	 * After fix: returns valid length without overflow.
	 */
	ASSERT_GE(skel->bss->near_overflow_ret, 0, "near_overflow_ret");

cleanup:
	test_snprintf_ip__destroy(skel);
}
