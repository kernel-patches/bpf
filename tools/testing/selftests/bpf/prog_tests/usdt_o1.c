// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Jiawei Zhao <phoenix500526@163.com>. */
#include <test_progs.h>

#include "../sdt.h"
#include "test_usdt_o1.skel.h"

#if (defined(__GNUC__) && !defined(__clang__))
#pragma GCC optimize("O1")
#else
#pragma message("non-gcc compiler: the correct probes might not be installed")
#endif


#define test_value 0xFEDCBA9876543210ULL
#define SEC(name) __attribute__((section(name), used))

int lets_test_this(int);
static volatile __u64 array[1] = {test_value};

static noinline void trigger_func(void)
{
#if defined(__x86_64__) || defined(__i386__)
	/* Base address + offset + (index * scale) */
	/* Force SIB addressing with inline assembly */
	const __u64 *base;
	__u32 idx;
	/* binding base to %rdx and idx to %rax */
	asm volatile("" : "=d"(base), "=a"(idx) : "0"(array), "1"((__u32)0) : "memory");
	STAP_PROBE1(test, usdt1, base[idx]);
#else
	STAP_PROBE1(test, usdt1, array[0]);
#endif
}

static void basic_sib_usdt(void)
{
	LIBBPF_OPTS(bpf_usdt_opts, opts);
	struct test_usdt_o1 *skel;
	struct test_usdt_o1__bss *bss;
	int err;

	skel = test_usdt_o1__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return;

	bss = skel->bss;
	bss->my_pid = getpid();

	err = test_usdt_o1__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto cleanup;

	/* usdt1 won't be auto-attached */
	opts.usdt_cookie = 0xcafedeadbeeffeed;
	skel->links.usdt1 = bpf_program__attach_usdt(skel->progs.usdt1,
						     0 /*self*/, "/proc/self/exe",
						     "test", "usdt1", &opts);
	if (!ASSERT_OK_PTR(skel->links.usdt1, "usdt1_link"))
		goto cleanup;

	trigger_func();

	ASSERT_EQ(bss->usdt1_called, 1, "usdt1_called");
	ASSERT_EQ(bss->usdt1_cookie, 0xcafedeadbeeffeed, "usdt1_cookie");
	ASSERT_EQ(bss->usdt1_arg_cnt, 1, "usdt1_arg_cnt");
	ASSERT_EQ(bss->usdt1_arg, test_value, "usdt1_arg");
	ASSERT_EQ(bss->usdt1_arg_ret, 0, "usdt1_arg_ret");
	ASSERT_EQ(bss->usdt1_arg_size, sizeof(array[0]), "usdt1_arg_size");

cleanup:
	test_usdt_o1__destroy(skel);
}

void test_usdt_o1(void)
{
#if !defined(__x86_64__) && !defined(__i386__)
	test__skip();
	return;
#endif
	basic_sib_usdt();
}
