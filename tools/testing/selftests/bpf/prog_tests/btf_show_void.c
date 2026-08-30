// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_show_void.skel.h"

/*
 * bpf_snprintf_btf() with the type_id of a "const void" (a modifier that
 * resolves to void, present in the vmlinux BTF) used to NULL-deref in
 * btf_modifier_show(). A fixed kernel prints the "<unsupported kind:0>"
 * placeholder; on an unfixed kernel this oopses the task (and panics it under
 * panic_on_oops), so it doubles as a reproducer.
 */
void test_btf_show_void(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	const struct btf_type *t;
	struct btf_show_void *skel;
	int i, n, cv = 0, err;
	char ctx[16] = {};
	struct btf *btf;

	btf = btf__parse("/sys/kernel/btf/vmlinux", NULL);
	if (!ASSERT_OK_PTR(btf, "btf__parse vmlinux"))
		return;

	n = btf__type_cnt(btf);
	for (i = 1; i < n; i++) {
		t = btf__type_by_id(btf, i);
		if (btf_kind(t) == BTF_KIND_CONST && t->type == 0) {
			cv = i;
			break;
		}
	}
	if (!ASSERT_GT(cv, 0, "find const void in vmlinux BTF"))
		goto out_btf;

	skel = btf_show_void__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto out_btf;
	skel->rodata->const_void_id = cv;
	if (!ASSERT_OK(btf_show_void__load(skel), "skel_load"))
		goto out_skel;

	topts.ctx_in = ctx;
	topts.ctx_size_in = sizeof(ctx);
	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.dump_const_void),
				     &topts);
	if (!ASSERT_OK(err, "test_run"))
		goto out_skel;

	ASSERT_EQ(skel->bss->ret, sizeof("<unsupported kind:0>") - 1, "ret");
	ASSERT_STREQ(skel->bss->out, "<unsupported kind:0>", "placeholder");
out_skel:
	btf_show_void__destroy(skel);
out_btf:
	btf__free(btf);
}
