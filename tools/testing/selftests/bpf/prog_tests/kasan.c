// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <linux/if_ether.h>
#include <test_progs.h>
#include "kasan.skel.h"

void test_kasan() {
	struct kasan *skel;
	uint8_t buf[ETH_HLEN];
	int ret;

	skel = kasan__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open and load prog"))
		return;

	LIBBPF_OPTS(bpf_test_run_opts, topts);
	memset(&topts, 0, sizeof(struct bpf_test_run_opts));
	topts.sz = sizeof(struct bpf_test_run_opts);
	topts.data_size_in = ETH_HLEN;
	topts.data_in = buf;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.bpf_kasan_uaf),
				     &topts);
	ASSERT_OK(ret, "run prog");

	kasan__destroy(skel);
}
