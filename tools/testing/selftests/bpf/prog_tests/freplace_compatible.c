// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "freplace_compatible.skel.h"

static void test_xdp_has_frags(void)
{
	struct freplace_compatible *skel_xdp, *skel_ext = NULL;
	struct bpf_program *prog_xdp, *prog_ext;
	struct bpf_link *link = NULL;
	char buff[128] = {};
	int err, prog_fd;
	__u32 flags;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = buff,
		.data_size_in = sizeof(buff),
		.repeat = 1,
	);

	skel_xdp = freplace_compatible__open();
	if (!ASSERT_OK_PTR(skel_xdp, "freplace_compatible__open xdp"))
		return;

	prog_xdp = skel_xdp->progs.xdp;
	bpf_program__set_autoload(prog_xdp, true);

	err = freplace_compatible__load(skel_xdp);
	if (!ASSERT_OK(err, "freplace_compatible__load xdp"))
		goto out;

	skel_ext = freplace_compatible__open();
	if (!ASSERT_OK_PTR(skel_ext, "freplace_compatible__open ext"))
		goto out;

	prog_ext = skel_ext->progs.freplace_xdp;
	bpf_program__set_autoload(prog_ext, true);

	flags = bpf_program__flags(prog_ext) | BPF_F_XDP_HAS_FRAGS;
	bpf_program__set_flags(prog_ext, flags);

	prog_fd = bpf_program__fd(prog_xdp);
	bpf_program__set_attach_target(prog_ext, prog_fd, "xdp");

	err = freplace_compatible__load(skel_ext);
	ASSERT_ERR(err, "freplace_compatible__load ext");

	link = bpf_program__attach_freplace(prog_ext, prog_fd, "xdp");
	ASSERT_ERR_PTR(link, "bpf_program__attach_freplace");

	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		goto out;

	ASSERT_EQ(topts.retval, XDP_PASS, "xdp retval");

out:
	bpf_link__destroy(link);
	freplace_compatible__destroy(skel_ext);
	freplace_compatible__destroy(skel_xdp);
}

#ifdef __x86_64__
static void test_kprobe_write_ctx(void)
{
	struct freplace_compatible *skel_kprobe, *skel_ext = NULL;
	struct bpf_program *prog_kprobe, *prog_ext, *prog_fentry;
	struct bpf_link *link_kprobe = NULL, *link_ext = NULL;
	int err;
	LIBBPF_OPTS(bpf_kprobe_opts, kprobe_opts);
	LIBBPF_OPTS(bpf_test_run_opts, topts);

	skel_kprobe = freplace_compatible__open();
	if (!ASSERT_OK_PTR(skel_kprobe, "freplace_compatible__open kprobe"))
		return;

	prog_kprobe = skel_kprobe->progs.kprobe;
	bpf_program__set_autoload(prog_kprobe, true);

	prog_fentry = skel_kprobe->progs.fentry;
	bpf_program__set_autoload(prog_fentry, true);

	err = freplace_compatible__load(skel_kprobe);
	if (!ASSERT_OK(err, "freplace_compatible__load kprobe"))
		goto out;

	skel_ext = freplace_compatible__open();
	if (!ASSERT_OK_PTR(skel_ext, "freplace_compatible__open ext"))
		goto out;

	prog_ext = skel_ext->progs.freplace_kprobe;
	bpf_program__set_autoload(prog_ext, true);

	bpf_program__set_attach_target(prog_ext, bpf_program__fd(prog_kprobe), "kprobe");

	err = freplace_compatible__load(skel_ext);
	ASSERT_ERR(err, "freplace_compatible__load ext");

	link_ext = bpf_program__attach_freplace(prog_ext, 0, NULL);
	ASSERT_ERR_PTR(link_ext, "bpf_program__attach_freplace");

	link_kprobe = bpf_program__attach_kprobe_opts(prog_kprobe, "bpf_fentry_test1",
						      &kprobe_opts);
	if (!ASSERT_OK_PTR(link_kprobe, "bpf_program__attach_kprobe_opts"))
		goto out;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog_fentry), &topts);
	ASSERT_OK(err, "bpf_prog_test_run_opts");

out:
	bpf_link__destroy(link_ext);
	bpf_link__destroy(link_kprobe);
	freplace_compatible__destroy(skel_ext);
	freplace_compatible__destroy(skel_kprobe);
}
#endif

void test_freplace_compatible(void)
{
	if (test__start_subtest("xdp_has_frags"))
		test_xdp_has_frags();
#ifdef __x86_64__
	if (test__start_subtest("kprobe_write_ctx"))
		test_kprobe_write_ctx();
#endif
}
