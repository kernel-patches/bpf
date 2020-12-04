// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/btf.h>
#include <bpf/btf.h>
#include "veth_stats_rx.skel.h"

#define VETH_NAME	"bpfveth0"

/* Demonstrate that bpf_snprintf_btf succeeds for both module-specific
 * and kernel-defined data structures; veth_stats_rx() is used as
 * it has both module-specific and kernel-defined data as arguments.
 * This test assumes that veth is built as a module and will skip if not.
 */
void test_snprintf_btf_mod(void)
{
	struct btf *vmlinux_btf = NULL, *veth_btf = NULL;
	struct veth_stats_rx *skel = NULL;
	struct veth_stats_rx__bss *bss;
	int err, duration = 0;
	__u32 id;

	err = system("ip link add name " VETH_NAME " type veth");
	if (CHECK(err, "system", "ip link add veth failed: %d\n", err))
		return;

	vmlinux_btf = btf__parse_raw("/sys/kernel/btf/vmlinux");
	err = libbpf_get_error(vmlinux_btf);
	if (CHECK(err, "parse vmlinux BTF", "failed parsing vmlinux BTF: %d\n",
		  err))
		goto cleanup;
	veth_btf = btf__parse_raw_split("/sys/kernel/btf/veth", vmlinux_btf);
	err = libbpf_get_error(veth_btf);
	if (err == -ENOENT) {
		printf("%s:SKIP:no BTF info for veth\n", __func__);
		test__skip();
		goto cleanup;
	}

	if (CHECK(err, "parse veth BTF", "failed parsing veth BTF: %d\n", err))
		goto cleanup;

	skel = veth_stats_rx__open();
	if (CHECK(!skel, "skel_open", "failed to open skeleton\n"))
		goto cleanup;

	err = veth_stats_rx__load(skel);
	if (CHECK(err, "skel_load", "failed to load skeleton: %d\n", err))
		goto cleanup;

	bss = skel->bss;

	/* This could all be replaced by __builtin_btf_type_id(); but need
	 * a way to determine if it supports object and type id.  In the
	 * meantime, look up type id for veth_stats and object id for veth.
	 */
	bss->veth_stats_btf_id = btf__find_by_name(veth_btf, "veth_stats");

	if (CHECK(bss->veth_stats_btf_id <= 0, "find 'struct veth_stats'",
		  "could not find 'struct veth_stats' in veth BTF: %d",
		  bss->veth_stats_btf_id))
		goto cleanup;

	bss->veth_obj_id = 0;

	for (id = 1; bpf_btf_get_next_id(id, &id) == 0; ) {
		struct bpf_btf_info info;
		__u32 len = sizeof(info);
		char name[64];
		int fd;

		fd = bpf_btf_get_fd_by_id(id);
		if (fd < 0)
			continue;

		memset(&info, 0, sizeof(info));
		info.name_len = sizeof(name);
		info.name = (__u64)name;
		if (bpf_obj_get_info_by_fd(fd, &info, &len) ||
		    strcmp((char *)info.name, "veth") != 0)
			continue;
		bss->veth_obj_id = info.id;
	}

	if (CHECK(bss->veth_obj_id == 0, "get obj id for veth module",
		  "could not get veth module id"))
		goto cleanup;

	err = veth_stats_rx__attach(skel);
	if (CHECK(err, "skel_attach", "skeleton attach failed: %d\n", err))
		goto cleanup;

	/* generate stats event, then delete; this ensures the program
	 * triggers prior to reading status.
	 */
	err = system("ethtool -S " VETH_NAME " > /dev/null");
	if (CHECK(err, "system", "ethtool -S failed: %d\n", err))
		goto cleanup;

	system("ip link delete " VETH_NAME);

	/* Make sure veth_stats_rx program was triggered and it set
	 * expected return values from bpf_trace_printk()s and all
	 * tests ran.
	 */
	if (CHECK(bss->ret <= 0,
		  "bpf_snprintf_btf: got return value",
		  "ret <= 0 %ld test %d\n", bss->ret, bss->ran_subtests))
		goto cleanup;

	if (CHECK(bss->ran_subtests == 0, "check if subtests ran",
		  "no subtests ran, did BPF program run?"))
		goto cleanup;

	if (CHECK(bss->num_subtests != bss->ran_subtests,
		  "check all subtests ran",
		  "only ran %d of %d tests\n", bss->num_subtests,
		  bss->ran_subtests))
		goto cleanup;

cleanup:
	system("ip link delete " VETH_NAME ">/dev/null 2>&1");
	if (skel)
		veth_stats_rx__destroy(skel);
}
