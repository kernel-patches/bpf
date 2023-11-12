/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */

#include <test_progs.h>
#include <bpf/btf.h>

static const char *module_name = "bpf_testmod";
static const char *standalone_module_name = "bpf_testmod_standalone";
static const char *symbol_name = "bpf_testmod_test_read";
static const char *standalone_symbol_name = "bpf_testmod_standalone_test_read";

void test_btf_module()
{
	struct btf *vmlinux_btf, *module_btf, *standalone_module_btf = NULL;
	__s32 type_id;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	vmlinux_btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux_btf, "could not load vmlinux BTF"))
		return;

	module_btf = btf__load_module_btf(module_name, vmlinux_btf);
	if (!ASSERT_OK_PTR(module_btf, "could not load module BTF"))
		goto cleanup;

	type_id = btf__find_by_name(module_btf, symbol_name);
	if (!ASSERT_GT(type_id, 0, "func not found"))
		goto cleanup;

	if (!ASSERT_OK(load_bpf_testmod(standalone_module_name, false), "load standalone BTF module"))
		goto cleanup;

	standalone_module_btf = btf__load_module_btf(standalone_module_name, vmlinux_btf);
	if (!ASSERT_OK_PTR(standalone_module_btf, "could not load standalone module BTF"))
		goto cleanup;

	type_id = btf__find_by_name(standalone_module_btf, standalone_symbol_name);
	ASSERT_GT(type_id, 0, "func not found in standalone");

cleanup:
	btf__free(standalone_module_btf);
	btf__free(module_btf);
	btf__free(vmlinux_btf);
	unload_bpf_testmod(standalone_module_name, false);
}
