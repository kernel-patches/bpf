// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "attach_test.skel.h"

void test_attach_test(void)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	struct attach_test *attach_skel = NULL;
	__u32 duration = 0;
	int err;

	opts.trampoline_attach_batch = true;
	attach_skel = attach_test__open_opts(&opts);
	if (CHECK(!attach_skel, "attach_test__open_opts", "open skeleton failed\n"))
		goto cleanup;

	err = attach_test__load(attach_skel);
	if (CHECK(err, "attach_skel_load", "attach skeleton failed\n"))
		goto cleanup;

	err = attach_test__attach(attach_skel);
	if (CHECK(err, "attach", "attach failed: %d\n", err))
		goto cleanup;

cleanup:
	attach_test__destroy(attach_skel);
}
