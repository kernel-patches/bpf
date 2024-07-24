// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "struct_ops_resize.skel.h"

static void resize_datasec(void)
{
	struct struct_ops_resize *skel;
	int err;

	skel = struct_ops_resize__open();
	if (!ASSERT_OK_PTR(skel, "struct_ops_resize__open"))
		return;

	err  = bpf_map__set_value_size(skel->maps.data_resizable, 1 << 15);
	if (!ASSERT_OK(err, "bpf_map__set_value_size"))
		goto cleanup;

	err = struct_ops_resize__load(skel);
	ASSERT_OK(err, "struct_ops_resize__load");

cleanup:
	struct_ops_resize__destroy(skel);
}

void test_struct_ops_resize(void)
{
	if (test__start_subtest("resize_datasec"))
		resize_datasec();
}
