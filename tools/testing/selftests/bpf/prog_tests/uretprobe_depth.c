// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include <unistd.h>
#include <setjmp.h>
#include <asm/ptrace.h>
#include <linux/compiler.h>
#include <linux/stringify.h>
#include "uretprobe_depth.skel.h"

#define RETVAL			0xFFFF
#define JMPVAL			0x4B1D
#define MAX_URETPROBE_DEPTH	64 // See include/linux/uprobes.h
#define NR_OMITTED_URETPROBE	16
static jmp_buf jmp;

unsigned long __uretprobe_longjmp(int nest, int jmpval, int retval)
{
	if (nest) {
		nest = ++retval < MAX_URETPROBE_DEPTH + NR_OMITTED_URETPROBE;
		return __uretprobe_longjmp(nest, jmpval, retval);
	}

	if (jmpval == JMPVAL) {
		longjmp(jmp, jmpval);
		return 0;
	} else
		return retval;
}

static void uretprobe_longjmp(void)
{
	if (setjmp(jmp) == JMPVAL) {
		__uretprobe_longjmp(0, 0, JMPVAL);
		return;
	}

	__uretprobe_longjmp(0, JMPVAL, RETVAL);
}

static void uretprobe_cleanup_return_instances(void)
{
	if (setjmp(jmp) == JMPVAL) {
		/*
		 * Cleanup these return instance data created before longjmp
		 * firstly. Then create 16 new return_instance data from here.
		 */
		__uretprobe_longjmp(1, 0, MAX_URETPROBE_DEPTH);
		return;
	}

	/* Create 8 return_instance data from here. */
	__uretprobe_longjmp(1, JMPVAL,
			    MAX_URETPROBE_DEPTH + NR_OMITTED_URETPROBE / 2);
}

static void uretprobe_reach_nestedness_limit(void)
{
	if (setjmp(jmp) == JMPVAL) {
		/*
		 * Due to uretprobe reach to the nestedness limit, it doesn't
		 * cleanup the return instance created before longjmp.
		 */
		__uretprobe_longjmp(1, 0, MAX_URETPROBE_DEPTH);
		return;
	}

	/* Create 64 return_instance from here. */
	__uretprobe_longjmp(1, JMPVAL, 0);
}

static void test_uretprobe_longjmp(void)
{
	struct uretprobe_depth *skel = NULL;
	int err;

	skel = uretprobe_depth__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uretprobe_depth__open_and_load"))
		goto cleanup;

	err = uretprobe_depth__attach(skel);
	if (!ASSERT_OK(err, "uretprobe_depth__attach"))
		goto cleanup;

	skel->bss->retval = -1;

	uretprobe_longjmp();

	ASSERT_EQ(skel->bss->retval, JMPVAL, "return value");

cleanup:
	uretprobe_depth__destroy(skel);
}

static void test_uretprobe_reach_nestedness_limit(void)
{
	struct uretprobe_depth *skel = NULL;
	int err;

	skel = uretprobe_depth__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uretprobe_depth__open_and_load"))
		goto cleanup;

	err = uretprobe_depth__attach(skel);
	if (!ASSERT_OK(err, "uretprobe_depth__attach"))
		goto cleanup;

	skel->bss->depth = 0;

	uretprobe_reach_nestedness_limit();

	ASSERT_EQ(skel->bss->depth, 0, "nest depth");

cleanup:
	uretprobe_depth__destroy(skel);
}

static void test_uretprobe_cleanup_return_instances(void)
{
	struct uretprobe_depth *skel = NULL;
	int err;

	skel = uretprobe_depth__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uretprobe_depth__open_and_load"))
		goto cleanup;

	err = uretprobe_depth__attach(skel);
	if (!ASSERT_OK(err, "uretprobe_depth__attach"))
		goto cleanup;

	skel->bss->depth = 0;

	uretprobe_cleanup_return_instances();

	ASSERT_EQ(skel->bss->depth, NR_OMITTED_URETPROBE + 1, "nest depth");

cleanup:
	uretprobe_depth__destroy(skel);
}

void test_uretprobe_return_instance(void)
{
	if (test__start_subtest("uretprobe_longjmp"))
		test_uretprobe_longjmp();
	if (test__start_subtest("uretprobe_cleanup_return_instances"))
		test_uretprobe_cleanup_return_instances();
	if (test__start_subtest("uretprobe_reach_nestedness_limit"))
		test_uretprobe_reach_nestedness_limit();
}
