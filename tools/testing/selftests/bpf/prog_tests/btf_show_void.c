// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include "btf_show_void.skel.h"

/*
 * bpf_snprintf_btf() renders a type_id taken straight from the vmlinux BTF.
 * Two such type_ids used to NULL-deref in the BTF show path:
 *   - a "const void" (a modifier resolving to void) in btf_modifier_show()
 *   - a BTF_KIND_VAR in btf_var_show() (base BTF has no resolved_ids)
 * A fixed kernel renders both without crashing.
 */
static long run(struct btf_show_void *skel, __u32 type_id)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts);
	char ctx[8] = {};

	skel->bss->type_id = type_id;
	topts.ctx_in = ctx;
	topts.ctx_size_in = sizeof(ctx);
	if (!ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(skel->progs.dump_type),
					      &topts), "test_run"))
		return -1;
	return skel->bss->ret;
}

void test_btf_show_void(void)
{
	const struct btf_type *t;
	struct btf_show_void *skel;
	int i, n, cv = 0, var = 0;
	struct btf *btf;

	btf = btf__parse("/sys/kernel/btf/vmlinux", NULL);
	if (!btf) {
		test__skip();
		return;
	}

	skel = btf_show_void__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto out_btf;

	n = btf__type_cnt(btf);
	for (i = 1; i < n && !(cv && var); i++) {
		t = btf__type_by_id(btf, i);
		if (!cv && btf_kind(t) == BTF_KIND_CONST && t->type == 0)
			cv = i;
		/* Pick a VAR small enough to render from the program's buffer. */
		if (!var && btf_kind(t) == BTF_KIND_VAR) {
			long sz = btf__resolve_size(btf, t->type);

			if (sz > 0 && sz <= (long)sizeof(skel->bss->obj))
				var = i;
		}
	}

	/* "const void" renders the "<unsupported kind:0>" placeholder. */
	if (test__start_subtest("const_void")) {
		if (cv) {
			ASSERT_EQ(run(skel, cv),
				  sizeof("<unsupported kind:0>") - 1, "ret");
			ASSERT_STREQ(skel->bss->out, "<unsupported kind:0>",
				     "placeholder");
		} else {
			test__skip();
		}
	}

	/* A BTF_KIND_VAR must resolve and render without error. */
	if (test__start_subtest("var")) {
		if (var)
			ASSERT_GT(run(skel, var), 0, "ret");
		else
			test__skip();
	}

	btf_show_void__destroy(skel);
out_btf:
	btf__free(btf);
}
