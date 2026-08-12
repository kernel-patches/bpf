// SPDX-License-Identifier: GPL-2.0

/*
 * This program test's basic kernel shadow stack support. It enables shadow
 * stack manual via the arch_prctl(), instead of relying on glibc. It's
 * Makefile doesn't compile with shadow stack support, so it doesn't rely on
 * any particular glibc. As a result it can't do any operations that require
 * special glibc shadow stack support (longjmp(), swapcontext(), etc). Just
 * stick to the basics and hope the compiler doesn't do anything strange. It
 * uses the x86 specific interface for ARCH_PCTL, whereas
 * test_shadow_stack_prctl.c uses the generic PRCTL interface mixed with x86
 * specific code.
 */
#define _GNU_SOURCE

#include "shadow_stack.h"

int main(int argc, char *argv[])
{
	return shadow_stack_run_tests(SHADOW_STACK_TEST_ARCH_PRCTL);
}
