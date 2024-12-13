#include <test_progs.h>

#include "struct_ops_refcounted.skel.h"
#include "struct_ops_refcounted_fail__ref_leak.skel.h"
#include "struct_ops_refcounted_fail__global_subprog.skel.h"

/* Test that the verifier accepts a program that first acquires a referenced
 * kptr through context and then releases the reference
 */
static void refcounted(void)
{
	struct struct_ops_refcounted *skel;

	skel = struct_ops_refcounted__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open_and_load"))
		return;

	struct_ops_refcounted__destroy(skel);
}

/* Test that the verifier rejects a program that acquires a referenced
 * kptr through context without releasing the reference
 */
static void refcounted_fail__ref_leak(void)
{
	struct struct_ops_refcounted_fail__ref_leak *skel;

	skel = struct_ops_refcounted_fail__ref_leak__open_and_load();
	if (ASSERT_ERR_PTR(skel, "struct_ops_module_fail__open_and_load"))
		return;

	struct_ops_refcounted_fail__ref_leak__destroy(skel);
}

/* Test that the verifier rejects a program that contains a global
 * subprogram with referenced kptr arguments
 */
static void refcounted_fail__global_subprog(void)
{
	struct struct_ops_refcounted_fail__global_subprog *skel;

	skel = struct_ops_refcounted_fail__global_subprog__open_and_load();
	if (ASSERT_ERR_PTR(skel, "struct_ops_module_fail__open_and_load"))
		return;

	struct_ops_refcounted_fail__global_subprog__destroy(skel);
}

void test_struct_ops_refcounted(void)
{
	if (test__start_subtest("refcounted"))
		refcounted();
	if (test__start_subtest("refcounted_fail__ref_leak"))
		refcounted_fail__ref_leak();
	if (test__start_subtest("refcounted_fail__global_subprog"))
		refcounted_fail__global_subprog();
}

