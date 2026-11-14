// SPDX-License-Identifier: GPL-2.0
/* The functions which the build tags as fmod_ret targets, because they return errors */
#include <test_progs.h>
#include <bpf/btf.h>
#include "fmodret_retval.skel.h"
#include "fmodret_retval_ext.skel.h"

#define TAG	"bpf_fmodret_retval:"

/* The functions of test_kmods/bpf_testmod_retval.c and the errors in their tags */
static const struct {
	const char *func, *errors;
} fixtures[] = {
	{ "bpf_testmod_retval_called",		"-27,-22" },
	{ "bpf_testmod_retval_long",		"-28,-14" },
	{ "bpf_testmod_retval_zero_extended",	"" },
	{ "bpf_testmod_retval_minus_one",	"" },
	{ "bpf_testmod_retval_eperm",		"-2,-1" },
	{ "bpf_testmod_retval_denied",		"-13" },
	{ "bpf_testmod_retval_effect",		"-22" },
	{ "bpf_testmod_retval_effect_late",	"-22" },
	{ "bpf_testmod_retval_effect_two_regs",	"-22" },
	{ "bpf_testmod_retval_no_effect",	"-28,-22,-16" },
	{ "bpf_testmod_retval_err_ptr",		"-34,-14" },
	{ "bpf_testmod_retval_no_branch",	"-14" },
	{ "bpf_testmod_retval_pointer",		"" },
	{ "bpf_testmod_retval_argument",	"" },
	{ "bpf_testmod_retval_notrace",		"" },
	{ "bpf_testmod_retval_variadic",	"" },
	{ "bpf_testmod_retval_init",		"" },
};

/* Return the errors in the tag of FUNC, or NULL */
static const char *tagged_errors(const struct btf *btf, const char *func)
{
	int id, func_id = btf__find_by_name_kind(btf, func, BTF_KIND_FUNC);

	if (!ASSERT_GT(func_id, 0, func))
		return NULL;
	for (id = btf__type_cnt(btf__base_btf(btf)); id < btf__type_cnt(btf); id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);
		const char *name = btf__name_by_offset(btf, t->name_off);

		if (btf_is_decl_tag(t) && t->type == func_id && !strncmp(name, TAG, strlen(TAG)))
			return name + strlen(TAG);
	}
	return NULL;
}

static int write_errno(int len)
{
	int fd = open("/sys/kernel/bpf_testmod", O_WRONLY), err;
	char buf[8] = {};

	if (!ASSERT_GE(fd, 0, "open"))
		return 0;
	err = write(fd, buf, len) < 0 ? -errno : 0;
	close(fd);
	return err;
}

/* bpf_testmod_test_write() returns the error of the target, or -EIO */
static void test_run(void)
{
	struct fmodret_retval *skel;
	struct bpf_program *prog;

	skel = fmodret_retval__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, prog == skel->progs.called);
	if (!ASSERT_OK(fmodret_retval__load(skel), "load"))
		goto out;
	skel->bss->pid = getpid();

	ASSERT_EQ(write_errno(7), -EFBIG, "before");
	if (!ASSERT_OK(fmodret_retval__attach(skel), "attach"))
		goto out;
	ASSERT_EQ(write_errno(7), -EFBIG, "called");
	skel->bss->deny = true;
	ASSERT_EQ(write_errno(7), -EINVAL, "skipped");
	fmodret_retval__detach(skel);
	ASSERT_EQ(write_errno(7), -EFBIG, "after");
out:
	fmodret_retval__destroy(skel);
}

/*
 * What an extension returns is not checked against the tag, and an extension of
 * the main program would return to the trampoline. Today none has the type of
 * the main program of a tracing program. Whatever the reason is, it must not load.
 */
static void test_extension(void)
{
	struct bpf_program *prog, *main_prog, *ext_prog;
	struct fmodret_retval_ext *ext;
	struct fmodret_retval *skel;
	int i;

	skel = fmodret_retval__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		return;
	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, prog == skel->progs.called ||
						prog == skel->progs.tagged_ctx);
	if (!ASSERT_OK(fmodret_retval__load(skel), "load"))
		goto out;
	for (i = 0; i < 4; i++) {
		ext = fmodret_retval_ext__open();
		if (!ASSERT_OK_PTR(ext, "open extension"))
			break;
		main_prog = i & 1 ? skel->progs.called : skel->progs.tagged_ctx;
		ext_prog = i & 2 ? ext->progs.plain_ctx : ext->progs.arg_ctx;
		bpf_object__for_each_program(prog, ext->obj)
			bpf_program__set_autoload(prog, prog == ext_prog);
		ASSERT_OK(bpf_program__set_attach_target(ext_prog, bpf_program__fd(main_prog),
							 bpf_program__name(main_prog)),
			  "set_attach_target");
		ASSERT_ERR(fmodret_retval_ext__load(ext), "load extension");
		fmodret_retval_ext__destroy(ext);
	}
out:
	fmodret_retval__destroy(skel);
}

void test_fmodret_retval(void)
{
	struct btf *vmlinux_btf, *btf = NULL;
	int i;

	vmlinux_btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux_btf, "btf__load_vmlinux_btf"))
		return;
	btf = btf__load_module_btf("bpf_testmod", vmlinux_btf);
	if (!ASSERT_OK_PTR(btf, "btf__load_module_btf"))
		goto out;
	if (!tagged_errors(btf, fixtures[0].func)) {
		printf("%s:SKIP:no CONFIG_BPF_FMODRET_SCAN\n", __func__);
		test__skip();
		goto out;
	}
	if (test__start_subtest("tags"))
		for (i = 0; i < ARRAY_SIZE(fixtures); i++)
			ASSERT_STREQ(tagged_errors(btf, fixtures[i].func) ?: "", fixtures[i].errors,
				     fixtures[i].func);
	if (test__start_subtest("run"))
		test_run();
	if (test__start_subtest("extension"))
		test_extension();
	RUN_TESTS(fmodret_retval);
out:
	btf__free(btf);
	btf__free(vmlinux_btf);
}
