// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <netinet/tcp.h>
#include <test_progs.h>
#include "network_helpers.h"
#include "bpf_smc.skel.h"

#define SOL_SMC 286
#define SMC_NEGOTIATOR 2
static const char name[] = "apps";

void run_smc(void)
{
	int fd, err;

	fd = socket(AF_SMC, SOCK_STREAM, 0);
	ASSERT_GT(fd, 0, "create smc socket");

	err = setsockopt(fd, SOL_SMC, SMC_NEGOTIATOR, name, sizeof(name) / sizeof(char));
	ASSERT_EQ(err, 0, "setsockopt");

	close(fd);
}

void test_load(void)
{
	struct bpf_smc *smc_skel;
	struct bpf_link *link;

	smc_skel = bpf_smc__open_and_load();
	if (!ASSERT_OK_PTR(smc_skel, "skel_open"))
		return;

	link = bpf_map__attach_struct_ops(smc_skel->maps.ops);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto error;

	bpf_link__destroy(link);
error:
	bpf_smc__destroy(smc_skel);
}

void test_update(void)
{
	struct bpf_smc *smc_skel;
	struct bpf_link *link;
	int err;

	smc_skel = bpf_smc__open_and_load();
	if (!ASSERT_OK_PTR(smc_skel, "skel_open"))
		return;

	link = bpf_map__attach_struct_ops(smc_skel->maps.accept);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto error;

	run_smc();
	ASSERT_EQ(smc_skel->bss->accept_cnt, 1, "accept_cnt");

	err = bpf_link__update_map(link, smc_skel->maps.drop);
	ASSERT_OK(err, "update_map");

	run_smc();
	ASSERT_EQ(smc_skel->bss->accept_cnt, 1, "accept_cnt");
	ASSERT_EQ(smc_skel->bss->drop_cnt, 1, "drop_cnt");

	bpf_link__destroy(link);
error:
	bpf_smc__destroy(smc_skel);
}

void test_ref(void)
{
	struct bpf_smc *smc_skel;
	struct bpf_link *link;
	int fd = 0, err;

	smc_skel = bpf_smc__open_and_load();
	if (!ASSERT_OK_PTR(smc_skel, "skel_open"))
		return;

	link = bpf_map__attach_struct_ops(smc_skel->maps.accept);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto error;

	fd = socket(AF_SMC, SOCK_STREAM, 0);
	ASSERT_GT(fd, 0, "create smc socket");
	err = setsockopt(fd, SOL_SMC, SMC_NEGOTIATOR, name, sizeof(name) / sizeof(char));
	ASSERT_EQ(err, 0, "setsockopt");
	bpf_link__destroy(link);
	if (fd > 0)
		close(fd);
	ASSERT_EQ(smc_skel->bss->accept_release_cnt, 1, "accept_release_cnt");
error:
	bpf_smc__destroy(smc_skel);
}

void test_bpf_smc(void)
{
	if (test__start_subtest("load"))
		test_load();
	if (test__start_subtest("update"))
		test_update();
	if (test__start_subtest("ref"))
		test_ref();
}
