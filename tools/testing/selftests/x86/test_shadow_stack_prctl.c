// SPDX-License-Identifier: GPL-2.0

/*
 * Same as test_shadow_stack.c but uses the PRCTL interface
 * instead of ARCH_PRCTL.
 */
#include "shadow_stack.h"

int main(int argc, char *argv[])
{
	return shadow_stack_run_tests(SHADOW_STACK_TEST_PRCTL);
}
