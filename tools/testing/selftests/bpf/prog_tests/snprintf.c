// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */

#include <test_progs.h>
#include "test_snprintf.skel.h"

static int duration;

#define EXP_NUM_OUT  "-8 9 96 -424242 1337 DABBAD00"
#define EXP_NUM_RET  sizeof(EXP_NUM_OUT)

#define EXP_IP_OUT   "127.000.000.001 0000:0000:0000:0000:0000:0000:0000:0001"
#define EXP_IP_RET   sizeof(EXP_IP_OUT)

/* The third specifier, %pB, depends on compiler inlining so don't check it */
#define EXP_SYM_OUT  "schedule schedule+0x0/"
#define MIN_SYM_RET  sizeof(EXP_SYM_OUT)

/* The third specifier, %p, is a hashed pointer which changes on every reboot */
#define EXP_ADDR_OUT "0000000000000000 ffff00000add4e55 "
#define EXP_ADDR_RET sizeof(EXP_ADDR_OUT "unknownhashedptr")

#define EXP_STR_OUT  "str1 longstr"
#define EXP_STR_RET  sizeof(EXP_STR_OUT)

#define EXP_OVER_OUT {'%', 'o', 'v', 'e', 'r'}
#define EXP_OVER_RET 10

void test_snprintf(void)
{
	char exp_addr_out[] = EXP_ADDR_OUT;
	char exp_over_out[] = EXP_OVER_OUT;
	char exp_sym_out[]  = EXP_SYM_OUT;
	struct test_snprintf *skel;
	int err;

	skel = test_snprintf__open_and_load();
	if (CHECK(!skel, "skel_open", "failed to open and load skeleton\n"))
		return;

	err = test_snprintf__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	/* trigger tracepoint */
	usleep(1);

	ASSERT_STREQ(skel->bss->num_out, EXP_NUM_OUT, "num_out");
	ASSERT_EQ(skel->bss->num_ret, EXP_NUM_RET, "num_ret");

	ASSERT_STREQ(skel->bss->ip_out, EXP_IP_OUT, "ip_out");
	ASSERT_EQ(skel->bss->ip_ret, EXP_IP_RET, "ip_ret");

	ASSERT_OK(memcmp(skel->bss->sym_out, exp_sym_out,
			 sizeof(exp_sym_out) - 1), "sym_out");
	ASSERT_LT(MIN_SYM_RET, skel->bss->sym_ret, "sym_ret");

	ASSERT_OK(memcmp(skel->bss->addr_out, exp_addr_out,
			 sizeof(exp_addr_out) - 1), "addr_out");
	ASSERT_EQ(skel->bss->addr_ret, EXP_ADDR_RET, "addr_ret");

	ASSERT_STREQ(skel->bss->str_out, EXP_STR_OUT, "str_out");
	ASSERT_EQ(skel->bss->str_ret, EXP_STR_RET, "str_ret");

	ASSERT_OK(memcmp(skel->bss->over_out, exp_over_out,
			 sizeof(exp_over_out)), "over_out");
	ASSERT_EQ(skel->bss->over_ret, EXP_OVER_RET, "over_ret");

cleanup:
	test_snprintf__destroy(skel);
}
