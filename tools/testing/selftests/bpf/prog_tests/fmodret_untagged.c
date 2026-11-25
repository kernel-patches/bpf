// SPDX-License-Identifier: GPL-2.0
/* Functions which return errors, but which the build must not tag as fmod_ret targets */
#include <test_progs.h>
#include <bpf/btf.h>

#define TAG "bpf_fmodret_retval:"

static const char * const funcs[] = {
	/* They work on BPF objects */
	"tracing_iter_filter",
	"btf_kfunc_check_flag",
	"bpf_mprog_detach",
	/* A kfunc and a helper */
	"bpf_sock_destroy",
	"bpf_skb_load_bytes",
	/* Of kernel/bpf */
	"bpf_tramp_ftrace_ops_func",
	/* By name */
	"copy_from_kernel_nofault",
	"bpf_set_dentry_xattr_locked",
	"bpf_remove_dentry_xattr_locked",
};

/* Has the build tagged the function FUNC_ID, or any function if FUNC_ID is 0? */
static bool tagged(const struct btf *btf, int func_id)
{
	int id;

	for (id = 1; id < btf__type_cnt(btf); id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);
		const char *name = btf__name_by_offset(btf, t->name_off);

		if (btf_is_decl_tag(t) && (!func_id || t->type == func_id) &&
		    !strncmp(name, TAG, strlen(TAG)))
			return true;
	}
	return false;
}

void test_fmodret_untagged(void)
{
	struct btf *btf;
	int i, id;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return;
	if (!tagged(btf, 0)) {
		printf("%s:SKIP:no CONFIG_BPF_FMODRET_SCAN\n", __func__);
		test__skip();
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(funcs); i++) {
		id = btf__find_by_name_kind(btf, funcs[i], BTF_KIND_FUNC);
		if (ASSERT_GT(id, 0, funcs[i]))
			ASSERT_FALSE(tagged(btf, id), funcs[i]);
	}
out:
	btf__free(btf);
}
