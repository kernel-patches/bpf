// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "struct_ops_trampoline.skel.h"

#if defined(__loongarch__) || defined(__riscv)
static void run_struct_ops_trampoline(void)
{
	struct struct_ops_trampoline *skel;
	struct bpf_link *link;
	int err;

	skel = struct_ops_trampoline__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_trampoline__open"))
		return;

	err = struct_ops_trampoline__load(skel);
	if (!ASSERT_OK(err, "struct_ops_trampoline__load"))
		goto cleanup;

	link = bpf_map__attach_struct_ops(skel->maps.testmod_trampoline);
	if (!ASSERT_OK_PTR(link, "attach_struct_ops"))
		goto cleanup;

	ASSERT_OK(trigger_module_test_read(256), "trigger_read");

	ASSERT_EQ(skel->bss->got_arg9, 9999, "check_stack_passed_arg9");

	bpf_link__destroy(link);
cleanup:
	struct_ops_trampoline__destroy(skel);
}
#endif

void test_struct_ops_trampoline(void)
{
#if defined(__loongarch__) || defined(__riscv)
	run_struct_ops_trampoline();
#else
	test__skip();
#endif
}
