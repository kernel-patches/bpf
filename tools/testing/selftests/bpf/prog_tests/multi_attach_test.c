// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/btf_ids.h>
#include "multi_attach_test.skel.h"
#include <bpf/btf.h>

static __u32 btf_ids[8];

static int load_btf_ids(void)
{
	__u32 i, nr_types, cnt;
	struct btf *btf;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return -1;

	nr_types = btf__get_nr_types(btf);

	for (i = 1, cnt = 0; i <= nr_types && cnt < 8; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const char *name;

		if (!btf_is_func(t))
			continue;

		name = btf__name_by_offset(btf, t->name_off);
		if (!name)
			continue;
		if (strncmp(name, "bpf_fentry_test", sizeof("bpf_fentry_test") - 1))
			continue;

		btf_ids[cnt] = i;
		cnt++;
	}

	btf__free(btf);
	return ASSERT_EQ(cnt, 8, "bpf_fentry_test_cnt") ? 0 : -1;
}

static int link_prog_from_cnt(const struct bpf_program *prog, int from, int cnt)
{
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
	enum bpf_attach_type attach_type;
	int prog_fd, link_fd;

	opts.multi.btf_ids = btf_ids + (from - 1);
	opts.multi.btf_ids_cnt = cnt;

	prog_fd = bpf_program__fd(prog);
	if (!ASSERT_GE(prog_fd, 0, "link_from_to_prog_fd"))
		return -1;
	attach_type = bpf_program__get_expected_attach_type(prog);
	link_fd = bpf_link_create(prog_fd, 0, attach_type, &opts);
	if (!ASSERT_GE(link_fd, 0, "link_from_to_link_fd"))
		return -1;
	return link_fd;
}

static int prog_from_cnt(const struct bpf_program *prog, int *from, int *cnt)
{
	const char *sec;
	int err, to;

	sec = bpf_program__section_name(prog);
	sec = strchr(sec, '/');
	if (!sec)
		return -1;
	sec++;
	err = sscanf(sec, "bpf_fentry_test%d-%d", from, &to);
	if (err != 2)
		return -1;
	*cnt = to - *from + 1;
	return 0;
}

static int link_test(const struct bpf_program *prog1,
		     const struct bpf_program *prog2,
		     __u64 *test_result1, __u64 *test_result2,
		     bool do_close, int link_fd[2])
{
	int from1, cnt1, from2, cnt2, err;
	__u32 duration = 0, retval;

	if (!ASSERT_OK(prog_from_cnt(prog1, &from1, &cnt1), "prog_from_cnt__prog1"))
		return -1;

	if (!ASSERT_OK(prog_from_cnt(prog2, &from2, &cnt2), "prog_from_cnt__prog2"))
		return -1;

	link_fd[0] = link_prog_from_cnt(prog1, from1, cnt1);
	if (link_fd[0] < 0)
		return -1;

	link_fd[1] = link_prog_from_cnt(prog2, from2, cnt2);
	if (link_fd[1] < 0)
		return -1;

	*test_result1 = 0;
	*test_result2 = 0;

	err = bpf_prog_test_run(bpf_program__fd(prog1), 1, NULL, 0,
				NULL, NULL, &retval, &duration);

	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");
	ASSERT_EQ(*test_result1, cnt1, "test_result");
	ASSERT_EQ(*test_result2, cnt2, "test_result");

	if (do_close) {
		close(link_fd[0]);
		close(link_fd[1]);
	}
	return err;
}

void test_multi_attach_test(void)
{
	struct bpf_link *link7 = NULL, *link8 = NULL;
	int link_fd[6] = { -1 }, i, err;
	struct multi_attach_test *skel;
	__u32 duration = 0, retval;

	for (i = 0; i < 6; i++)
		link_fd[i] = -1;

	skel = multi_attach_test__open_and_load();
	if (!ASSERT_OK_PTR(skel, "multi_attach__load"))
		return;

	if (!ASSERT_OK(load_btf_ids(), "load_btf_ids"))
		goto cleanup;

#define LINK_TEST(__prog1, __prog2, __close)			\
	err = link_test(skel->progs.test ## __prog1,		\
			skel->progs.test ## __prog2,		\
			&skel->bss->test_result ## __prog1,	\
			&skel->bss->test_result ## __prog2,	\
			__close, link_fd + __prog1 - 1);	\
	if (err)						\
		goto cleanup;

	LINK_TEST(1, 2, true);
	LINK_TEST(3, 4, true);
	LINK_TEST(1, 3, true);
	LINK_TEST(2, 4, true);

	LINK_TEST(1, 2, false);
	LINK_TEST(3, 4, false);
	LINK_TEST(5, 6, false);

#undef LINK_TEST

	link7 = bpf_program__attach(skel->progs.test7);
	if (!ASSERT_OK_PTR(link7, "multi_attach_check__test1_attach"))
		goto cleanup;

	link8 = bpf_program__attach(skel->progs.test8);
	if (!ASSERT_OK_PTR(link7, "multi_attach_check__test2_attach"))
		goto cleanup;

	err = bpf_prog_test_run(bpf_program__fd(skel->progs.test7), 1, NULL, 0,
				NULL, NULL, &retval, &duration);

	ASSERT_OK(err, "test_run");
	ASSERT_EQ(retval, 0, "test_run");
	ASSERT_EQ(skel->bss->test_result7, 1, "test_result7");
	ASSERT_EQ(skel->bss->test_result8, 1, "test_result8");

cleanup:
	bpf_link__destroy(link8);
	bpf_link__destroy(link7);
	for (i = 0; i < 6; i++)
		close(link_fd[i]);
	multi_attach_test__destroy(skel);
}
