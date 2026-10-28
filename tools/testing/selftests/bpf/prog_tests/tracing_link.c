// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include "fentry_recursive.skel.h"
#include "priv_freplace_prog.skel.h"
#include "xdp_dummy.skel.h"
#include "kprobe_write_ctx.skel.h"
#include "tracing_link_ctx.skel.h"
#include "tracing_link_multi.skel.h"

static void test_fentry_link_create_log(int target_fd, __u32 target_btf_id, int cookie,
					enum bpf_attach_type attach_type,
					bool reattach, const char *msg)
{
	struct fentry_recursive *skel = NULL;
	struct xdp_dummy *target;
	char log_buf[128] = {};
	int err, fd, prog_fd;
	LIBBPF_OPTS(bpf_log_opts, log_opts,
		    .buf = log_buf,
		    .size = sizeof(log_buf),
		    .level = 1,
	);
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .log_opts = &log_opts,
		    .target_btf_id = target_btf_id,
		    .tracing.cookie = cookie,
	);

	target = xdp_dummy__open_and_load();
	if (!ASSERT_OK_PTR(target, "xdp_dummy__open_and_load"))
		return;

	skel = fentry_recursive__open();
	if (!ASSERT_OK_PTR(skel, "fentry_recursive__open"))
		goto out;

	err = bpf_program__set_attach_target(skel->progs.recursive_attach,
					     bpf_program__fd(target->progs.xdp_dummy_prog),
					     "xdp_dummy_prog");
	if (!ASSERT_OK(err, "bpf_program__set_attach_target"))
		goto out;

	err = fentry_recursive__load(skel);
	if (!ASSERT_OK(err, "fentry_recursive__load"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.recursive_attach);
	if (reattach) {
		/* Consume the initial target saved when the program was loaded. */
		fd = bpf_link_create(prog_fd, 0, BPF_TRACE_FENTRY, &opts);
		if (!ASSERT_GE(fd, 0, "bpf_link_create first"))
			goto out;

		close(fd);
		memset(log_buf, 0, sizeof(log_buf));
		log_opts.true_size = 0;
	}

	fd = bpf_link_create(prog_fd, target_fd, attach_type, &opts);
	if (!ASSERT_LT(fd, 0, "bpf_link_create")) {
		close(fd);
		goto out;
	}

	ASSERT_EQ(fd, -EINVAL, "err");
	ASSERT_STREQ(log_buf, msg, "log_buf");
	ASSERT_EQ(log_opts.true_size, strlen(msg) + 1, "log_size");

out:
	fentry_recursive__destroy(skel);
	xdp_dummy__destroy(target);
}

static void test_log_invalid_attach_type(void)
{
	const char *msg = "attach_type is not expected_attach_type of the prog.\n";

	test_fentry_link_create_log(0, 0, 0, BPF_TRACE_FEXIT, false, msg);
}

static void test_log_tgt_prog_fd_only(void)
{
	const char *msg = "target_fd and target_btf_id must be both set or both unset.\n";

	test_fentry_link_create_log(-1, 0, 1, BPF_TRACE_FENTRY, false, msg);
}

static void test_log_tgt_prog_fd_disallowed(void)
{
	const char *msg = "target_fd is only allowed for freplace prog.\n";

	test_fentry_link_create_log(-1, 1, 0, BPF_TRACE_FENTRY, false, msg);
}

static void test_log_invalid_attach_btf(void)
{
	const char *msg = "Cannot re-attach a prog that was attached to a bpf prog.\n";

	test_fentry_link_create_log(0, 0, 1, BPF_TRACE_FENTRY, true, msg);
}

static void test_freplace_link_create_log(int target_fd, __u32 target_btf_id, int err_exp,
					  bool reattach, const char *msg)
{
	struct priv_freplace_prog *skel = NULL;
	char log_buf[256] = {};
	struct xdp_dummy *xdp;
	int err, fd, prog_fd;
	LIBBPF_OPTS(bpf_log_opts, log_opts,
		    .buf = log_buf,
		    .size = sizeof(log_buf),
		    .level = 1,
	);
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .log_opts = &log_opts,
		    .target_btf_id = target_btf_id,
	);

	xdp = xdp_dummy__open_and_load();
	if (!ASSERT_OK_PTR(xdp, "xdp_dummy__open_and_load"))
		return;

	skel = priv_freplace_prog__open();
	if (!ASSERT_OK_PTR(skel, "priv_freplace_prog__open"))
		goto out;

	err = bpf_program__set_attach_target(skel->progs.new_xdp_prog2,
					     bpf_program__fd(xdp->progs.xdp_dummy_prog),
					     "xdp_dummy_prog");
	if (!ASSERT_OK(err, "bpf_program__set_attach_target"))
		goto out;

	err = priv_freplace_prog__load(skel);
	if (!ASSERT_OK(err, "priv_freplace_prog__load"))
		goto out;

	prog_fd = bpf_program__fd(skel->progs.new_xdp_prog2);
	if (reattach) {
		/* Consume the initial target saved when the program was loaded. */
		fd = bpf_link_create(prog_fd, 0, 0, &opts);
		if (!ASSERT_GE(fd, 0, "bpf_link_create first"))
			goto out;

		close(fd);
		memset(log_buf, 0, sizeof(log_buf));
		log_opts.true_size = 0;
	}

	if (!target_fd && target_btf_id)
		target_fd = bpf_program__fd(xdp->progs.xdp_dummy_prog);

	fd = bpf_link_create(prog_fd, target_fd, 0, &opts);
	if (!ASSERT_LT(fd, 0, "bpf_link_create")) {
		close(fd);
		goto out;
	}

	ASSERT_EQ(fd, err_exp, "err");
	ASSERT_STREQ(log_buf, msg, "log_buf");
	ASSERT_EQ(log_opts.true_size, strlen(msg) + 1, "log_size");

out:
	priv_freplace_prog__destroy(skel);
	xdp_dummy__destroy(xdp);
}

static void test_log_invalid_target_fd(void)
{
	const char *msg = "Invalid tgt_fd.\n";

	test_freplace_link_create_log(-1, 1, -EBADF, false, msg);
}

static void test_log_reattach_without_target(void)
{
	const char *msg = "Re-attach of freplace prog needs target_fd and target_btf_id.\n";

	test_freplace_link_create_log(0, 0, -EINVAL, true, msg);
}

static void test_log_invalid_target_btf_id(void)
{
	const char *msg = "attach_btf_id 4294967295 is invalid\n";

	test_freplace_link_create_log(0, ~0U, -EINVAL, false, msg);
}

#ifdef __x86_64__
static void test_log_invalid_kprobe_write_ctx(void)
{
	const char *msg = "Only one of freplace prog and its target writes to pt_regs.\n";
	struct kprobe_write_ctx *skel_kprobe, *skel_freplace = NULL;
	struct bpf_program *prog_kprobe, *prog_freplace;
	int err, prog_fd, btf_id, fd;
	char log_buf[128] = {};
	LIBBPF_OPTS(bpf_log_opts, log_opts,
		    .buf = log_buf,
		    .size = sizeof(log_buf),
		    .level = 1,
	);
	LIBBPF_OPTS(bpf_link_create_opts, link_opts,
		    .log_opts = &log_opts,
	);

	skel_kprobe = kprobe_write_ctx__open();
	if (!ASSERT_OK_PTR(skel_kprobe, "kprobe_write_ctx__open kprobe"))
		return;

	prog_kprobe = skel_kprobe->progs.kprobe_dummy;
	bpf_program__set_autoload(prog_kprobe, true);

	err = kprobe_write_ctx__load(skel_kprobe);
	if (!ASSERT_OK(err, "kprobe_write_ctx__load kprobe"))
		goto out;

	skel_freplace = kprobe_write_ctx__open();
	if (!ASSERT_OK_PTR(skel_freplace, "kprobe_write_ctx__open freplace"))
		goto out;

	prog_freplace = skel_freplace->progs.freplace_kprobe;
	bpf_program__set_autoload(prog_freplace, true);

	prog_fd = bpf_program__fd(skel_kprobe->progs.kprobe_write_ctx);
	bpf_program__set_attach_target(prog_freplace, prog_fd, "kprobe_write_ctx");

	err = kprobe_write_ctx__load(skel_freplace);
	if (!ASSERT_OK(err, "kprobe_write_ctx__load freplace"))
		goto out;

	prog_fd = bpf_program__fd(prog_kprobe);
	btf_id = btf__find_by_name_kind(bpf_object__btf(skel_kprobe->obj), "kprobe_dummy",
					BTF_KIND_FUNC);
	if (!ASSERT_GT(btf_id, 0, "btf__find_by_name_kind"))
		goto out;

	link_opts.target_btf_id = btf_id;
	fd = bpf_link_create(bpf_program__fd(prog_freplace), prog_fd, 0, &link_opts);
	if (!ASSERT_LT(fd, 0, "bpf_link_create")) {
		close(fd);
		goto out;
	}

	ASSERT_EQ(fd, -EINVAL, "err");
	ASSERT_STREQ(log_buf, msg, "log_buf");
	ASSERT_EQ(log_opts.true_size, strlen(msg) + 1, "log_size");

out:
	kprobe_write_ctx__destroy(skel_freplace);
	kprobe_write_ctx__destroy(skel_kprobe);
}
#else
static void test_log_invalid_kprobe_write_ctx(void)
{
	test__skip();
}
#endif

static void test_log_freplace_ctx_size(void)
{
	const char *msg = "Freplace prog accesses more ctx than its target.\n";
	struct tracing_link_ctx *target, *skel = NULL;
	char log_buf[128] = {};
	int err, fd;
	LIBBPF_OPTS(bpf_log_opts, log_opts,
		    .buf = log_buf,
		    .size = sizeof(log_buf),
		    .level = 1,
	);
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .log_opts = &log_opts,
	);

	target = tracing_link_ctx__open_and_load();
	if (!ASSERT_OK_PTR(target, "tracing_link_ctx__open_and_load"))
		return;

	skel = tracing_link_ctx__open();
	if (!ASSERT_OK_PTR(skel, "tracing_link_ctx__open"))
		goto out;

	bpf_program__set_autoload(skel->progs.target, false);
	bpf_program__set_autoload(skel->progs.replacement, true);

	err = bpf_program__set_attach_target(skel->progs.replacement,
					     bpf_program__fd(target->progs.target), "target");
	if (!ASSERT_OK(err, "bpf_program__set_attach_target"))
		goto out;

	err = tracing_link_ctx__load(skel);
	if (!ASSERT_OK(err, "tracing_link_ctx__load"))
		goto out;

	fd = bpf_link_create(bpf_program__fd(skel->progs.replacement), 0, 0, &opts);
	if (!ASSERT_LT(fd, 0, "bpf_link_create")) {
		close(fd);
		goto out;
	}

	ASSERT_EQ(fd, -EINVAL, "err");
	ASSERT_STREQ(log_buf, msg, "log_buf");
	ASSERT_EQ(log_opts.true_size, strlen(msg) + 1, "log_size");

out:
	tracing_link_ctx__destroy(skel);
	tracing_link_ctx__destroy(target);
}

void test_tracing_link_log(void)
{
	if (test__start_subtest("invalid_attach_type"))
		test_log_invalid_attach_type();
	if (test__start_subtest("tgt_prog_fd_only"))
		test_log_tgt_prog_fd_only();
	if (test__start_subtest("tgt_prog_fd_disallowed"))
		test_log_tgt_prog_fd_disallowed();
	if (test__start_subtest("invalid_attach_btf"))
		test_log_invalid_attach_btf();
	if (test__start_subtest("invalid_target_fd"))
		test_log_invalid_target_fd();
	if (test__start_subtest("reattach_without_target"))
		test_log_reattach_without_target();
	if (test__start_subtest("invalid_target_btf_id"))
		test_log_invalid_target_btf_id();
	if (test__start_subtest("invalid_kprobe_write_ctx"))
		test_log_invalid_kprobe_write_ctx();
	if (test__start_subtest("freplace_ctx_size"))
		test_log_freplace_ctx_size();
}

static void test_tracing_multi_link_create_log(const char *prog_name, int target_fd,
					       struct bpf_link_create_opts *opts,
					       int err_exp, const char *msg)
{
	struct tracing_link_multi *skel;
	struct bpf_program *prog;
	char log_buf[128] = {};
	int err, fd;
	LIBBPF_OPTS(bpf_log_opts, log_opts,
		    .buf = log_buf,
		    .size = sizeof(log_buf),
		    .level = 1,
	);

	skel = tracing_link_multi__open();
	if (!ASSERT_OK_PTR(skel, "tracing_link_multi__open"))
		return;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!ASSERT_OK_PTR(prog, "bpf_object__find_program_by_name"))
		goto out;

	bpf_program__set_autoload(prog, true);
	err = tracing_link_multi__load(skel);
	if (!ASSERT_OK(err, "tracing_link_multi__load"))
		goto out;

	opts->log_opts = &log_opts;
	fd = bpf_link_create(bpf_program__fd(prog), target_fd,
			     bpf_program__expected_attach_type(prog), opts);
	opts->log_opts = NULL;
	if (!ASSERT_LT(fd, 0, "bpf_link_create")) {
		close(fd);
		goto out;
	}

	ASSERT_EQ(fd, err_exp, "err");
	ASSERT_STREQ(log_buf, msg, "log_buf");
	ASSERT_EQ(log_opts.true_size, msg[0] ? strlen(msg) + 1 : 0, "log_size");

out:
	tracing_link_multi__destroy(skel);
}

static void test_multi_log_excessive_count(void)
{
	const char *msg = "tracing_multi.cnt 2147483647 is above the limit 1048576.\n";
	__u32 id = 0;
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .tracing_multi.ids = &id,
		    .tracing_multi.cnt = INT_MAX,
	);

	test_tracing_multi_link_create_log("fentry", 0, &opts, -E2BIG, msg);
}

static void test_multi_log_invalid_flags(void)
{
	const char *msg = "flags must be zero.\n";
	__u32 id = 0;
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = 1,
		    .tracing_multi.ids = &id,
		    .tracing_multi.cnt = 1,
	);

	test_tracing_multi_link_create_log("fentry", 0, &opts, -EINVAL, msg);
}

static void test_multi_log_invalid_target_fd(void)
{
	const char *msg = "target_fd must be zero.\n";
	__u32 id = 0;
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .tracing_multi.ids = &id,
		    .tracing_multi.cnt = 1,
	);

	test_tracing_multi_link_create_log("fentry", -1, &opts, -EINVAL, msg);
}

static void test_multi_log_duplicate_ids(void)
{
	struct btf *btf;
	char msg[128];
	__u32 ids[2];
	int id;
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .tracing_multi.ids = ids,
		    .tracing_multi.cnt = ARRAY_SIZE(ids),
	);

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return;

	id = btf__find_by_name_kind(btf, "bpf_fentry_test1", BTF_KIND_FUNC);
	if (!ASSERT_GT(id, 0, "target_btf_id"))
		goto out;

	ids[0] = ids[1] = id;

	snprintf(msg, sizeof(msg), "id %u is in tracing_multi.ids more than once.\n", id);
	test_tracing_multi_link_create_log("fentry", 0, &opts, -EINVAL, msg);

out:
	btf__free(btf);
}

static void test_multi_log_target(struct btf *btf, const char *prog_name, const char *target,
				  int err_exp, const char *format)
{
	char msg[128];
	__u32 id;
	int ret;
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .tracing_multi.ids = &id,
		    .tracing_multi.cnt = 1,
	);

	ret = btf__find_by_name_kind(btf, target, BTF_KIND_FUNC);
	if (!ASSERT_GT(ret, 0, "target_btf_id"))
		return;

	id = ret;
	snprintf(msg, sizeof(msg), format, id, target);
	test_tracing_multi_link_create_log(prog_name, 0, &opts, err_exp, msg);
}

static void test_multi_log_vmlinux_target(const char *prog_name, const char *target,
					  int err_exp, const char *format)
{
	struct btf *btf;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return;

	test_multi_log_target(btf, prog_name, target, err_exp, format);
	btf__free(btf);
}

static void test_multi_log_module_target(const char *prog_name, const char *target,
					 int err_exp, const char *format)
{
	struct btf *vmlinux, *btf;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	vmlinux = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux, "btf__load_vmlinux_btf"))
		return;

	btf = btf__load_module_btf("bpf_testmod", vmlinux);
	if (!ASSERT_OK_PTR(btf, "btf__load_module_btf"))
		goto out;

	test_multi_log_target(btf, prog_name, target, err_exp, format);
	btf__free(btf);

out:
	btf__free(vmlinux);
}

static void test_multi_log_noreturn_fexit(void)
{
	const char *msg = "Cannot attach fexit/fsession_multi prog to noreturn target btf id %u.\n";

	test_multi_log_vmlinux_target("fexit", "do_exit", -EINVAL, msg);
}

static void test_multi_log_denylist(void)
{
	const char *msg = "Cannot attach to denylist btf id %u.\n";
	const char *target = "migrate_disable";
	struct btf *btf;

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return;

	/* migrate_disable is only in the denylist on SMP kernels. */
	if (btf__find_by_name_kind(btf, target, BTF_KIND_FUNC) == -ENOENT)
		test__skip();
	else
		test_multi_log_target(btf, "fentry", target, -EINVAL, msg);

	btf__free(btf);
}

static void test_multi_log_invalid_btf_id(void)
{
	const char *msg = "Cannot resolve target btf id 4294967295.\n";
	__u32 id = ~0U;
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .tracing_multi.ids = &id,
		    .tracing_multi.cnt = 1,
	);

	test_tracing_multi_link_create_log("fentry", 0, &opts, -EINVAL, msg);
}

static void test_multi_log_non_function(void)
{
	const char *target = "bpf_fentry_test_t";
	struct btf *btf;
	char msg[128];
	__u32 id;
	int ret;
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .tracing_multi.ids = &id,
		    .tracing_multi.cnt = 1,
	);

	btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(btf, "btf__load_vmlinux_btf"))
		return;

	ret = btf__find_by_name_kind(btf, target, BTF_KIND_STRUCT);
	if (!ASSERT_GT(ret, 0, "target_btf_id"))
		goto out;

	id = ret;
	snprintf(msg, sizeof(msg), "Target %u:%s is not a function.\n", id, target);
	test_tracing_multi_link_create_log("fentry", 0, &opts, -EINVAL, msg);

out:
	btf__free(btf);
}

static void test_multi_log_too_many_args(void)
{
	const char *msg = "The function bpf_trace_run12 has 13 arguments. Too many.\n";

	test_multi_log_vmlinux_target("fentry", "bpf_trace_run12", -EINVAL, msg);
}

static void test_multi_log_varargs(void)
{
	const char *msg = "The function _printk with variable args is unsupported.\n";

	test_multi_log_vmlinux_target("fentry", "_printk", -EINVAL, msg);
}

static void test_multi_log_large_return(void)
{
	const char *msg = "The function bpf_kfunc_call_test_ret_big return type STRUCT is unsupported.\n";

	test_multi_log_module_target("module_fentry", "bpf_kfunc_call_test_ret_big", -EINVAL, msg);
}

static void test_multi_log_large_arg(void)
{
	const char *msg = "The function bpf_testmod_large_arg arg0 type STRUCT is unsupported.\n";

	test_multi_log_module_target("module_fentry", "bpf_testmod_large_arg", -EINVAL, msg);
}

static void test_multi_log_large_return_fexit(void)
{
	const char *msg = "Attach to target %u:%s with a >8 byte return value is not supported for this attach type.\n";

	test_multi_log_module_target("module_fexit", "bpf_kfunc_call_test_ret_pair",
				     -EOPNOTSUPP, msg);
}

static void test_multi_log_notrace(void)
{
	const char *msg = "Target %u:%s is not ftrace attachable.\n";

	test_multi_log_vmlinux_target("fentry", "__bpf_tramp_enter", -ENOENT, msg);
}

static void test_multi_log_not_sleepable(void)
{
	const char *msg = "Target %u:%s is not sleepable.\n";

	test_multi_log_vmlinux_target("fentry_sleepable", "bpf_fentry_test2", -EINVAL, msg);
}

#ifndef __x86_64__
static void test_multi_log_kernel_unsupported(void)
{
	const char *msg = "This kernel does not support tracing_multi.\n";
	__u32 id = 0;
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .flags = 1,
		    .tracing_multi.ids = &id,
		    .tracing_multi.cnt = 1,
	);

	test_tracing_multi_link_create_log("fentry", 0, &opts, -EOPNOTSUPP, msg);
}
#endif

void test_tracing_multi_link_log(void)
{
#ifndef __x86_64__
	if (test__start_subtest("kernel_unsupported"))
		test_multi_log_kernel_unsupported();
	return;
#endif

	if (test__start_subtest("excessive_count"))
		test_multi_log_excessive_count();
	if (test__start_subtest("invalid_flags"))
		test_multi_log_invalid_flags();
	if (test__start_subtest("invalid_target_fd"))
		test_multi_log_invalid_target_fd();
	if (test__start_subtest("duplicate_ids"))
		test_multi_log_duplicate_ids();
	if (test__start_subtest("noreturn_fexit"))
		test_multi_log_noreturn_fexit();
	if (test__start_subtest("denylist"))
		test_multi_log_denylist();
	if (test__start_subtest("invalid_btf_id"))
		test_multi_log_invalid_btf_id();
	if (test__start_subtest("non_function"))
		test_multi_log_non_function();
	if (test__start_subtest("too_many_args"))
		test_multi_log_too_many_args();
	if (test__start_subtest("varargs"))
		test_multi_log_varargs();
	if (test__start_subtest("large_return"))
		test_multi_log_large_return();
	if (test__start_subtest("large_arg"))
		test_multi_log_large_arg();
	if (test__start_subtest("large_return_fexit"))
		test_multi_log_large_return_fexit();
	if (test__start_subtest("notrace"))
		test_multi_log_notrace();
	if (test__start_subtest("not_sleepable"))
		test_multi_log_not_sleepable();
}
