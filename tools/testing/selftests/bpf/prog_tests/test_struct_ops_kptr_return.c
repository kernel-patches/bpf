#include <test_progs.h>

#include "struct_ops_kptr_return.skel.h"
#include "struct_ops_kptr_return_fail__wrong_type.skel.h"
#include "struct_ops_kptr_return_fail__invalid_scalar.skel.h"
#include "struct_ops_kptr_return_fail__nonzero_offset.skel.h"
#include "struct_ops_kptr_return_fail__local_kptr.skel.h"

/* Test that the verifier accepts a program that acquires a referenced
 * kptr and releases the reference through return
 */
static void kptr_return(void)
{
	struct struct_ops_kptr_return *skel;

	skel = struct_ops_kptr_return__open_and_load();
	if (!ASSERT_OK_PTR(skel, "struct_ops_module_open_and_load"))
		return;

	struct_ops_kptr_return__destroy(skel);
}

/* Test that the verifier rejects a program that returns a kptr of the
 * wrong type
 */
static void kptr_return_fail__wrong_type(void)
{
	struct struct_ops_kptr_return_fail__wrong_type *skel;

	skel = struct_ops_kptr_return_fail__wrong_type__open_and_load();
	if (ASSERT_ERR_PTR(skel, "struct_ops_module_fail__wrong_type__open_and_load"))
		return;

	struct_ops_kptr_return_fail__wrong_type__destroy(skel);
}

/* Test that the verifier rejects a program that returns a non-null scalar */
static void kptr_return_fail__invalid_scalar(void)
{
	struct struct_ops_kptr_return_fail__invalid_scalar *skel;

	skel = struct_ops_kptr_return_fail__invalid_scalar__open_and_load();
	if (ASSERT_ERR_PTR(skel, "struct_ops_module_fail__invalid_scalar__open_and_load"))
		return;

	struct_ops_kptr_return_fail__invalid_scalar__destroy(skel);
}

/* Test that the verifier rejects a program that returns kptr with non-zero offset */
static void kptr_return_fail__nonzero_offset(void)
{
	struct struct_ops_kptr_return_fail__nonzero_offset *skel;

	skel = struct_ops_kptr_return_fail__nonzero_offset__open_and_load();
	if (ASSERT_ERR_PTR(skel, "struct_ops_module_fail__nonzero_offset__open_and_load"))
		return;

	struct_ops_kptr_return_fail__nonzero_offset__destroy(skel);
}

/* Test that the verifier rejects a program that returns local kptr */
static void kptr_return_fail__local_kptr(void)
{
	struct struct_ops_kptr_return_fail__local_kptr *skel;

	skel = struct_ops_kptr_return_fail__local_kptr__open_and_load();
	if (ASSERT_ERR_PTR(skel, "struct_ops_module_fail__local_kptr__open_and_load"))
		return;

	struct_ops_kptr_return_fail__local_kptr__destroy(skel);
}

void test_struct_ops_kptr_return(void)
{
	if (test__start_subtest("kptr_return"))
		kptr_return();
	if (test__start_subtest("kptr_return_fail__wrong_type"))
		kptr_return_fail__wrong_type();
	if (test__start_subtest("kptr_return_fail__invalid_scalar"))
		kptr_return_fail__invalid_scalar();
	if (test__start_subtest("kptr_return_fail__nonzero_offset"))
		kptr_return_fail__nonzero_offset();
	if (test__start_subtest("kptr_return_fail__local_kptr"))
		kptr_return_fail__local_kptr();
}


