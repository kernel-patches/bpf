// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <sys/syscall.h>
#include <bpf/bpf.h>

#include "bpf_goto_x.skel.h"

static void __test_run(struct bpf_program *prog, void *ctx_in, size_t ctx_size_in)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
			    .ctx_in = ctx_in,
			    .ctx_size_in = ctx_size_in,
		   );
	int err, prog_fd;

	prog_fd = bpf_program__fd(prog);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "test_run_opts err");
}

static void check_simple(struct bpf_goto_x *skel,
			 struct bpf_program *prog,
			 __u64 ctx_in,
			 __u64 expected)
{
	skel->bss->ret_user = 0;

	__test_run(prog, &ctx_in, sizeof(ctx_in));

	if (!ASSERT_EQ(skel->bss->ret_user, expected, "skel->bss->ret_user"))
		return;
}

static void check_simple_fentry(struct bpf_goto_x *skel,
				struct bpf_program *prog,
				__u64 ctx_in,
				__u64 expected)
{
	skel->bss->in_user = ctx_in;
	skel->bss->ret_user = 0;

	/* trigger */
	usleep(1);

	if (!ASSERT_EQ(skel->bss->ret_user, expected, "skel->bss->ret_user"))
		return;
}

static void check_goto_x_skel(struct bpf_goto_x *skel)
{
	int i;
	__u64 in[]   = {0, 1, 2, 3, 4,  5, 77};
	__u64 out[]  = {2, 3, 4, 5, 7, 19, 19};
	__u64 out2[] = {103, 104, 107, 205, 115, 1019, 1019};
	__u64 in3[]  = {0, 11, 27, 31, 22, 45, 99};
	__u64 out3[] = {2,  3,  4,  5, 19, 19, 19};
	__u64 in4[]  = {0, 1, 2, 3, 4,  5, 77};
	__u64 out4[] = {12, 15, 7 , 15, 12, 15, 15};

	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple(skel, skel->progs.simple_test, in[i], out[i]);

	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple(skel, skel->progs.simple_test2, in[i], out[i]);

	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple(skel, skel->progs.two_switches, in[i], out2[i]);

	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple(skel, skel->progs.big_jump_table, in3[i], out3[i]);

	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple(skel, skel->progs.one_jump_two_maps, in4[i], out4[i]);

	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple(skel, skel->progs.use_static_global1, in[i], out[i]);

	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple(skel, skel->progs.use_static_global2, in[i], out[i]);

	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple(skel, skel->progs.use_nonstatic_global1, in[i], out[i]);

	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple(skel, skel->progs.use_nonstatic_global2, in[i], out[i]);

	bpf_program__attach(skel->progs.simple_test_other_sec);
	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple_fentry(skel, skel->progs.simple_test_other_sec, in[i], out[i]);

	bpf_program__attach(skel->progs.use_static_global_other_sec);
	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple_fentry(skel, skel->progs.use_static_global_other_sec, in[i], out[i]);

	bpf_program__attach(skel->progs.use_nonstatic_global_other_sec);
	for (i = 0; i < ARRAY_SIZE(in); i++)
		check_simple_fentry(skel, skel->progs.use_nonstatic_global_other_sec, in[i], out[i]);
}

void goto_x_skel(void)
{
	struct bpf_goto_x *skel;
	int ret;

	skel = bpf_goto_x__open();
	if (!ASSERT_NEQ(skel, NULL, "bpf_goto_x__open"))
		return;

	ret = bpf_goto_x__load(skel);
	if (!ASSERT_OK(ret, "bpf_goto_x__load"))
		return;

	check_goto_x_skel(skel);

	bpf_goto_x__destroy(skel);
}

void test_bpf_goto_x(void)
{
	if (test__start_subtest("goto_x_skel"))
		goto_x_skel();
}
