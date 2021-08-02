// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Hengqi Chen */

#include <test_progs.h>
#include <bpf/btf.h>

static const char *module_path = "/sys/kernel/btf/btrfs";
static const char *module_name = "btrfs";

void test_btf_module()
{
	struct btf *vmlinux_btf, *module_btf;
	__s32 type_id;

	if (access(module_path, F_OK))
		return;

	vmlinux_btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux_btf, "could not load vmlinux BTF"))
		return;

	module_btf = btf__load_module_btf(module_name, vmlinux_btf);
	if (!ASSERT_OK_PTR(module_btf, "could not load module BTF"))
		goto cleanup;

	type_id = btf__find_by_name(module_btf, "btrfs_file_open");
	ASSERT_GT(type_id, 0, "func btrfs_file_open not found");

cleanup:
	btf__free(module_btf);
	btf__free(vmlinux_btf);
}
