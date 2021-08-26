// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2020 Google LLC.
 */

#include <test_progs.h>
#include <bpf/btf.h>
#include "modify_return.skel.h"
#include "multi_modify_return.skel.h"

#define LOWER(x) ((x) & 0xffff)
#define UPPER(x) ((x) >> 16)


struct multi_data {
	struct multi_modify_return *skel;
	int link_fentry;
	int link_fexit;
	__u32 btf_ids[9];
};

static int multi_btf_ids(struct multi_data *md)
{
	__u32 i, nr_types, ids_cnt;
	struct btf *btf;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return -1;

	nr_types = btf__get_nr_types(btf);

	for (i = 1; i <= nr_types; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const char *name;
		bool match;

		if (!btf_is_func(t))
			continue;

		name = btf__name_by_offset(btf, t->name_off);
		if (!name)
			continue;
		match = strncmp(name, "bpf_modify_return_test",
				sizeof("bpf_modify_return_test") - 1) == 0;
		match |= strncmp(name, "bpf_fentry_test",
				 sizeof("bpf_fentry_test") - 1) == 0;
		if (!match)
			continue;

		md->btf_ids[ids_cnt] = i;
		ids_cnt++;
	}

	btf__free(btf);
	return ASSERT_EQ(ids_cnt, 9, "multi_btf_ids") ? 0 : -1;
}

static int multi_attach(struct multi_data *md)
{
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
	int prog_fd;

	md->skel = multi_modify_return__open_and_load();
	if (!ASSERT_OK_PTR(md->skel, "multi_attach_check__load"))
		return -1;

	opts.multi.btf_ids = md->btf_ids;
	opts.multi.btf_ids_cnt = 9;

	prog_fd = bpf_program__fd(md->skel->progs.test1);

	md->link_fentry = bpf_link_create(prog_fd, 0, BPF_TRACE_FENTRY, &opts);
	if (!ASSERT_GE(md->link_fentry, 0, "bpf_link_create"))
		goto cleanup;

	prog_fd = bpf_program__fd(md->skel->progs.test2);

	md->link_fexit = bpf_link_create(prog_fd, 0, BPF_TRACE_FEXIT, &opts);
	if (!ASSERT_GE(md->link_fexit, 0, "bpf_link_create"))
		goto cleanup_close;

	return 0;

cleanup_close:
	close(md->link_fentry);
cleanup:
	multi_modify_return__destroy(md->skel);
	return -1;
}

static void multi_detach(struct multi_data *md)
{
	close(md->link_fentry);
	close(md->link_fexit);
	multi_modify_return__destroy(md->skel);
}

static void run_test(__u32 input_retval, __u16 want_side_effect, __s16 want_ret,
		     struct multi_data *md)
{
	struct modify_return *skel = NULL;
	int err, prog_fd;
	__u32 duration = 0, retval;
	__u16 side_effect;
	__s16 ret;

	skel = modify_return__open_and_load();
	if (CHECK(!skel, "skel_load", "modify_return skeleton failed\n"))
		goto cleanup;

	err = modify_return__attach(skel);
	if (CHECK(err, "modify_return", "attach failed: %d\n", err))
		goto cleanup;

	if (md && !ASSERT_OK(multi_attach(md), "multi_attach"))
		goto cleanup;

	skel->bss->input_retval = input_retval;
	prog_fd = bpf_program__fd(skel->progs.fmod_ret_test);
	err = bpf_prog_test_run(prog_fd, 1, NULL, 0, NULL, 0,
				&retval, &duration);

	CHECK(err, "test_run", "err %d errno %d\n", err, errno);

	side_effect = UPPER(retval);
	ret  = LOWER(retval);

	CHECK(ret != want_ret, "test_run",
	      "unexpected ret: %d, expected: %d\n", ret, want_ret);
	CHECK(side_effect != want_side_effect, "modify_return",
	      "unexpected side_effect: %d\n", side_effect);

	CHECK(skel->bss->fentry_result != 1, "modify_return",
	      "fentry failed\n");
	CHECK(skel->bss->fexit_result != 1, "modify_return",
	      "fexit failed\n");
	CHECK(skel->bss->fmod_ret_result != 1, "modify_return",
	      "fmod_ret failed\n");

	if (md)
		multi_detach(md);
cleanup:
	modify_return__destroy(skel);
}

void test_modify_return(void)
{
	struct multi_data data = {};

	run_test(0 /* input_retval */,
		 1 /* want_side_effect */,
		 4 /* want_ret */,
		 NULL /* no multi func test */);
	run_test(-EINVAL /* input_retval */,
		 0 /* want_side_effect */,
		 -EINVAL /* want_ret */,
		 NULL /* no multi func test */);

	if (!ASSERT_OK(multi_btf_ids(&data), "multi_attach"))
		return;

	run_test(0 /* input_retval */,
		 1 /* want_side_effect */,
		 4 /* want_ret */,
		 &data);
	run_test(-EINVAL /* input_retval */,
		 0 /* want_side_effect */,
		 -EINVAL /* want_ret */,
		 &data);
}

