// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/libbpf.h>
#include "css_iter.skel.h"

static void test_css_iter_next_after_drain(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	struct css_iter *skel;
	int err, fd;

	skel = css_iter__open_and_load();
	if (!ASSERT_OK_PTR(skel, "css_iter__open_and_load"))
		return;

	fd = bpf_program__fd(skel->progs.iter_css_next_after_drain);
	err = bpf_prog_test_run_opts(fd, &topts);
	if (!ASSERT_OK(err, "test_run_opts err"))
		goto out;
	if (!ASSERT_OK(topts.retval, "test_run_opts retval"))
		goto out;

	ASSERT_OK(skel->bss->new_ret, "new_ret");
	ASSERT_GT(skel->bss->css_count, 0, "css_count");
	ASSERT_EQ(skel->data->next_after_drain, 0, "next_after_drain");

out:
	css_iter__destroy(skel);
}

void test_css_iter(void)
{
	if (test__start_subtest("next_after_drain"))
		test_css_iter_next_after_drain();
}
