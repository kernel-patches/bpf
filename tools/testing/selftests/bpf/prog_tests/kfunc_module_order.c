// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <testing_helpers.h>

#include "kfunc_module_order.skel.h"

static int load_test_modorder_modules(void)
{
	int fd, err;

	fd = open("bpf_test_modorder_x.ko", O_RDONLY);
	if (!ASSERT_GE(fd, 0, "open(bpf_test_modorder_x.ko)"))
		return -errno;

	err = finit_module(fd, "", 0);
	if (!ASSERT_OK(err, "Load bpf_test_modorder_x.ko module"))
		goto err_fd;
	close(fd);

	fd = open("bpf_test_modorder_y.ko", O_RDONLY);
	if (!ASSERT_GE(fd, 0, "open(bpf_test_modorder_y.ko)")) {
		err = -errno;
		goto err_modx;
	}

	err = finit_module(fd, "", 0);
	if (!ASSERT_OK(err, "Load bpf_test_modorder_y.ko"))
		goto err_modx;
	close(fd);

	return 0;

err_modx:
	delete_module("bpf_test_modorder_x", 0);
err_fd:
	if (fd)
		close(fd);
	return err;
}

static int unload_test_modorder_modules(void)
{
	int err1, err2;

	err1 = delete_module("bpf_test_modorder_x", 0);
	ASSERT_OK(err1, "Unloading bpf_test_modorder_x");

	err2 = delete_module("bpf_test_modorder_y", 0);
	ASSERT_OK(err2, "Unloading bpf_test_modorder_y");

	return err1 ?: err2;
}

static int test_run_prog(const struct bpf_program *prog,
			 struct bpf_test_run_opts *opts, int expect_val)
{
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), opts);
	if (!ASSERT_OK(err, "bpf_prog_test_run_opts"))
		return err;

	if (!ASSERT_EQ((int)opts->retval, expect_val, bpf_program__name(prog)))
		return -EINVAL;

	return 0;
}

void test_kfunc_module_order(void)
{
	struct kfunc_module_order *skel;
	char pkt_data[64] = { 0 };
	int err = 0;

	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, test_opts, .data_in = pkt_data,
			    .data_size_in = sizeof(pkt_data));

	err = load_test_modorder_modules();
	if (!ASSERT_OK(err, "Load bpf_test_modorder modules"))
		return;

	skel = kfunc_module_order__open_and_load();
	if (!ASSERT_OK_PTR(skel, "kfunc_module_order__open_and_load()")) {
		err = -EINVAL;
		goto exit_mods;
	}

	test_run_prog(skel->progs.call_kfunc_xy, &test_opts, 0);
	test_run_prog(skel->progs.call_kfunc_yx, &test_opts, 0);

	kfunc_module_order__destroy(skel);
exit_mods:
	unload_test_modorder_modules();
}
