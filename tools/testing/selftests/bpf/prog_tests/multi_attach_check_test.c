// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <linux/btf_ids.h>
#include "multi_attach_check.skel.h"
#include "multi_attach_check_extra1.skel.h"
#include "multi_attach_check_extra2.skel.h"
#include <bpf/btf.h>

static __u32 btf_ids[7];

static int load_btf_ids(void)
{
	__u32 i, nr_types, cnt;
	struct btf *btf;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return -1;

	nr_types = btf__get_nr_types(btf);

	for (i = 1, cnt = 0; i <= nr_types && cnt < 7; i++) {
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
	return ASSERT_EQ(cnt, 7, "bpf_fentry_test_cnt") ? 0 : -1;
}

void test_multi_attach_check_test(void)
{
	struct bpf_link *link1 = NULL, *link2 = NULL, *link3 = NULL;
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
	struct multi_attach_check_extra1 *skel_extra1 = NULL;
	struct multi_attach_check_extra2 *skel_extra2 = NULL;
	struct multi_attach_check *skel;
	int link_fd, prog_fd;

	/* Load/attach standard trampolines and on top of it multi
	 * func program. It should succeed.
	 */
	skel = multi_attach_check__open_and_load();
	if (!ASSERT_OK_PTR(skel, "multi_attach_check__load"))
		return;

	link1 = bpf_program__attach(skel->progs.test1);
	if (!ASSERT_OK_PTR(link1, "multi_attach_check__test1_attach"))
		goto cleanup;

	link2 = bpf_program__attach(skel->progs.test2);
	if (!ASSERT_OK_PTR(link2, "multi_attach_check__test2_attach"))
		goto cleanup;

	link3 = bpf_program__attach(skel->progs.test3);
	if (!ASSERT_OK_PTR(link3, "multi_attach_check__test3_attach"))
		goto cleanup;

	if (!ASSERT_OK(load_btf_ids(), "load_btf_ids"))
		goto cleanup;

	/* There's 8 bpf_fentry_test* functions, get BTF ids for 7 of them
	 * and try to load/link multi func program with them. It should fail
	 * both for fentry.multi ...
	 */
	opts.multi.btf_ids = btf_ids;
	opts.multi.btf_ids_cnt = 7;

	prog_fd = bpf_program__fd(skel->progs.test4);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_FENTRY, &opts);
	if (!ASSERT_LT(link_fd, 0, "bpf_link_create"))
		goto cleanup;

	close(link_fd);

	/* ... and fexit.multi */
	prog_fd = bpf_program__fd(skel->progs.test5);

	link_fd = bpf_link_create(prog_fd, 0, BPF_TRACE_FEXIT, &opts);
	if (!ASSERT_LT(link_fd, 0, "bpf_link_create"))
		goto cleanup;

	close(link_fd);

	/* Try to load/attach extra programs on top of multi func programs,
	 * it should fail for both fentry ...
	 */
	skel_extra1 = multi_attach_check_extra1__open_and_load();
	if (!ASSERT_ERR_PTR(skel_extra1, "multi_attach_check_extra1__load"))
		multi_attach_check_extra1__destroy(skel_extra1);

	/* ... and fexit */
	skel_extra2 = multi_attach_check_extra2__open_and_load();
	if (!ASSERT_ERR_PTR(skel_extra2, "multi_attach_check_extra2__load"))
		multi_attach_check_extra2__destroy(skel_extra2);

cleanup:
	bpf_link__destroy(link1);
	bpf_link__destroy(link2);
	bpf_link__destroy(link3);
	multi_attach_check__destroy(skel);
}
