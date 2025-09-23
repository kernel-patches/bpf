// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "stacktrace_map.skel.h"

void test_stacktrace_map(void)
{
	struct stacktrace_map *skel;
	int stackid_hmap_fd, stackmap_fd, stack_amap_fd;
	int err, stack_trace_len;
	__u32 duration = 0;

	skel = stacktrace_map__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	/* find map fds */
	stackid_hmap_fd = bpf_map__fd(skel->maps.stackid_hmap);
	if (CHECK_FAIL(stackid_hmap_fd < 0))
		goto out;

	stackmap_fd = bpf_map__fd(skel->maps.stackmap);
	if (CHECK_FAIL(stackmap_fd < 0))
		goto out;

	stack_amap_fd = bpf_map__fd(skel->maps.stack_amap);
	if (CHECK_FAIL(stack_amap_fd < 0))
		goto out;

	err = stacktrace_map__attach(skel);
	if (!ASSERT_OK(err, "skel_attach"))
		goto out;
	/* give some time for bpf program run */
	sleep(1);

	/* disable stack trace collection */
	skel->bss->control = 1;

	/* for every element in stackid_hmap, we can find a corresponding one
	 * in stackmap, and vice versa.
	 */
	err = compare_map_keys(stackid_hmap_fd, stackmap_fd);
	if (CHECK(err, "compare_map_keys stackid_hmap vs. stackmap",
		  "err %d errno %d\n", err, errno))
		goto out;

	err = compare_map_keys(stackmap_fd, stackid_hmap_fd);
	if (CHECK(err, "compare_map_keys stackmap vs. stackid_hmap",
		  "err %d errno %d\n", err, errno))
		goto out;

	stack_trace_len = PERF_MAX_STACK_DEPTH * sizeof(__u64);
	err = compare_stack_ips(stackmap_fd, stack_amap_fd, stack_trace_len);
	if (CHECK(err, "compare_stack_ips stackmap vs. stack_amap",
		  "err %d errno %d\n", err, errno))
		goto out;

out:
	stacktrace_map__destroy(skel);
}
