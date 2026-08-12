// SPDX-License-Identifier: GPL-2.0

#ifndef TOOLS_TESTING_SELFTESTS_X86_SHADOW_STACK_H_
#define TOOLS_TESTING_SELFTESTS_X86_SHADOW_STACK_H_

enum shadow_stack_test {
	SHADOW_STACK_TEST_ARCH_PRCTL,
	SHADOW_STACK_TEST_PRCTL,
	SHADOW_STACK_TEST_COUNT,
};

int shadow_stack_run_tests(enum shadow_stack_test which_test);

#endif /* TOOLS_TESTING_SELFTESTS_X86_SHADOW_STACK_H_ */
