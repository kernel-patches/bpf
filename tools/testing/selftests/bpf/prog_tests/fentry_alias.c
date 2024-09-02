// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "fentry_alias.skel.h"

void test_fentry_alias(void)
{
	struct fentry_alias *fentry_skel = NULL;
	int err, prog_fd;
	__u64 key = 0, val;

	LIBBPF_OPTS(bpf_test_run_opts, opts);

	fentry_skel = fentry_alias__open_and_load();
	if (!ASSERT_OK_PTR(fentry_skel, "fentry_skel_load"))
		goto cleanup;

	err = fentry_alias__attach(fentry_skel);
	if (!ASSERT_OK(err, "fentry_attach"))
		goto cleanup;

	fentry_skel->bss->real_pid = getpid();

	prog_fd = bpf_program__fd(fentry_skel->progs.test1);
	err = bpf_prog_test_run_opts(prog_fd, &opts);

	ASSERT_EQ(fentry_skel->bss->test1_hit_cnt, 2,
		  "fentry_alias_test1_result");

	err = bpf_map__lookup_elem(fentry_skel->maps.map, &key, sizeof(key),
				   &val, sizeof(val), 0);
	ASSERT_OK(err, "hashmap lookup");
	ASSERT_EQ(val, 2, "fentry_alias_test2_result");

	ASSERT_EQ(fentry_skel->bss->test3_hit_cnt, 2,
		  "fentry_alias_test3_result");

	ASSERT_EQ(fentry_skel->bss->test4_hit_cnt, 2,
		  "fentry_alias_test4_result");
cleanup:
	fentry_alias__destroy(fentry_skel);
}
