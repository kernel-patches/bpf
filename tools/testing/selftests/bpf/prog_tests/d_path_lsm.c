// SPDX-License-Identifier: GPL-2.0-only
#include <test_progs.h>
#include "d_path_lsm.skel.h"

void test_d_path_lsm(void)
{
	struct d_path_lsm *skel = NULL;
	int err, map_fd, key = 0, val = 0;

	skel = d_path_lsm__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	err = d_path_lsm__attach(skel);
	if (!ASSERT_OK(err, "attach"))
		goto out;

	system("cp /bin/true /tmp/bpf_d_path_test 2>/dev/null || :");
	system("/tmp/bpf_d_path_test >/dev/null 2>&1");

	map_fd = bpf_map__fd(skel->maps.result);
	err = bpf_map_lookup_elem(map_fd, &key, &val);
	ASSERT_OK(err, "lookup_result");
	ASSERT_EQ(val, 1, "prefix_match");
out:
	d_path_lsm__destroy(skel);
}
