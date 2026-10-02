// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>
#include "fentry_recursive.skel.h"
#include "priv_freplace_prog.skel.h"
#include "xdp_dummy.skel.h"
#include "kprobe_write_ctx.skel.h"

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
	const char *msg = "Invalid attach_type.\n";

	test_fentry_link_create_log(0, 0, 0, BPF_XDP, false, msg);
}

static void test_log_tgt_prog_fd_only(void)
{
	const char *msg = "tgt_prog_fd and btf_id must be both set or both unset.\n";

	test_fentry_link_create_log(-1, 0, 1, BPF_TRACE_FENTRY, false, msg);
}

static void test_log_tgt_prog_fd_disallowed(void)
{
	const char *msg = "tgt_prog_fd is only allowed for freplace prog.\n";

	test_fentry_link_create_log(-1, 1, 0, BPF_TRACE_FENTRY, false, msg);
}

static void test_log_invalid_attach_btf(void)
{
	const char *msg = "Invalid attach_btf.\n";

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
	const char *msg = "Invalid tgt_prog_fd.\n";

	test_freplace_link_create_log(-1, 1, -EBADF, false, msg);
}

static void test_log_reattach_without_target(void)
{
	const char *msg = "Only allow re-attach for tracing and lsm progs.\n";

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
	struct kprobe_write_ctx *skel_kprobe, *skel_freplace = NULL;
	struct bpf_program *prog_kprobe, *prog_freplace;
	const char *msg = "Invalid kprobe_write_ctx.\n";
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
}
