// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <linux/filter.h>
#include <bpf/btf.h>

#define TAG_FMODRET		"bpf_fmodret"
#define TAG_FMODRET_SLEEPABLE	"bpf_fmodret_sleepable"

static bool func_has_tag(const struct btf *btf, const char *func, const char *tag)
{
	int func_id, id, nr_types;

	func_id = btf__find_by_name_kind(btf, func, BTF_KIND_FUNC);
	if (func_id < 0)
		return false;

	nr_types = btf__type_cnt(btf);
	for (id = 1; id < nr_types; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (!btf_is_decl_tag(t) || t->type != func_id ||
		    btf_decl_tag(t)->component_idx != -1)
			continue;
		if (!strcmp(btf__name_by_offset(btf, t->name_off), tag))
			return true;
	}

	return false;
}

static void test_vmlinux_tags(void)
{
	struct btf *btf;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return;

	ASSERT_TRUE(func_has_tag(btf, "bpf_modify_return_test", TAG_FMODRET), "modify_return_test");
	ASSERT_TRUE(func_has_tag(btf, "bpf_modify_return_test2", TAG_FMODRET),
		    "modify_return_test2");
	ASSERT_TRUE(func_has_tag(btf, "bpf_modify_return_test_tp", TAG_FMODRET),
		    "modify_return_test_tp");
	ASSERT_TRUE(func_has_tag(btf, "bpf_fentry_test1", TAG_FMODRET), "fentry_test1");
	ASSERT_TRUE(func_has_tag(btf, "update_socket_protocol", TAG_FMODRET),
		    "update_socket_protocol");

	/* Only bpf_fentry_test1 is a sleepable target */
	ASSERT_TRUE(func_has_tag(btf, "bpf_fentry_test1", TAG_FMODRET_SLEEPABLE),
		    "fentry_test1_sleepable");
	ASSERT_FALSE(func_has_tag(btf, "bpf_modify_return_test", TAG_FMODRET_SLEEPABLE),
		     "modify_return_test_sleepable");
	ASSERT_FALSE(func_has_tag(btf, "bpf_modify_return_test2", TAG_FMODRET_SLEEPABLE),
		     "modify_return_test2_sleepable");
	ASSERT_FALSE(func_has_tag(btf, "bpf_modify_return_test_tp", TAG_FMODRET_SLEEPABLE),
		     "modify_return_test_tp_sleepable");
	ASSERT_FALSE(func_has_tag(btf, "update_socket_protocol", TAG_FMODRET_SLEEPABLE),
		     "update_socket_protocol_sleepable");

	/* A function which is not a target has no tag */
	ASSERT_GT(btf__find_by_name_kind(btf, "bpf_fentry_test2", BTF_KIND_FUNC), 0,
		  "fentry_test2_exists");
	ASSERT_FALSE(func_has_tag(btf, "bpf_fentry_test2", TAG_FMODRET), "fentry_test2");
	ASSERT_FALSE(func_has_tag(btf, "bpf_fentry_test2", TAG_FMODRET_SLEEPABLE),
		     "fentry_test2_sleepable");

	btf__free(btf);
}

static void test_module_tags(void)
{
	struct btf *vmlinux_btf, *module_btf;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	vmlinux_btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux_btf, "btf__load_vmlinux_btf"))
		return;
	module_btf = btf__load_module_btf("bpf_testmod", vmlinux_btf);
	if (!module_btf && errno == ENOENT) {
		printf("%s:SKIP:bpf_testmod has no BTF\n", __func__);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK_PTR(module_btf, "btf__load_module_btf"))
		goto out;

	ASSERT_TRUE(func_has_tag(module_btf, "bpf_testmod_trampoline_count_test", TAG_FMODRET),
		    "trampoline_count_test");
	ASSERT_FALSE(func_has_tag(module_btf, "bpf_testmod_trampoline_count_test",
				  TAG_FMODRET_SLEEPABLE), "trampoline_count_test_sleepable");
	ASSERT_FALSE(func_has_tag(module_btf, "bpf_testmod_fentry_test1", TAG_FMODRET),
		     "testmod_fentry_test1");

	btf__free(module_btf);
out:
	btf__free(vmlinux_btf);
}

/* Load a minimal fmod_ret program which attaches to function BTF_ID */
static int load_fmod_ret(int btf_id, __u32 prog_flags)
{
	struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.expected_attach_type = BPF_MODIFY_RETURN,
		.prog_flags = prog_flags,
		.attach_btf_id = btf_id,
	);

	return bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", insns, ARRAY_SIZE(insns), &opts);
}

static void check_load(const char *func, __u32 prog_flags, bool allowed, const char *name)
{
	int btf_id, fd;

	btf_id = libbpf_find_vmlinux_btf_id(func, BPF_MODIFY_RETURN);
	if (!ASSERT_GT(btf_id, 0, func))
		return;
	fd = load_fmod_ret(btf_id, prog_flags);
	if (allowed)
		ASSERT_GE(fd, 0, name);
	else
		ASSERT_LT(fd, 0, name);
	if (fd >= 0)
		close(fd);
}

static void test_attach_permission(void)
{
	check_load("bpf_modify_return_test", 0, true, "target");
	check_load("bpf_fentry_test1", 0, true, "sleepable_target");
	check_load("bpf_fentry_test2", 0, false, "not_a_target");

	check_load("bpf_fentry_test1", BPF_F_SLEEPABLE, true, "sleepable_prog_sleepable_target");
	check_load("bpf_modify_return_test", BPF_F_SLEEPABLE, false,
		   "sleepable_prog_nonsleepable_target");
}

void test_fmodret_tags(void)
{
	if (test__start_subtest("vmlinux"))
		test_vmlinux_tags();
	if (test__start_subtest("module"))
		test_module_tags();
	if (test__start_subtest("attach_permission"))
		test_attach_permission();
}
