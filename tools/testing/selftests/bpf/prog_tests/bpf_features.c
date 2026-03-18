// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026, Oracle and/or its affiliates. */
#include <test_progs.h>
#include <linux/btf.h>
#include <bpf/libbpf_internal.h>

#include "kfree_skb.skel.h"

void test_btf_layout_feature(void)
{
	struct kfree_skb *skel = kfree_skb__open_and_load();

	if (ASSERT_OK_PTR(skel, "kfree_skb_skel")) {
		ASSERT_TRUE(kernel_supports(skel->obj, FEAT_BTF_LAYOUT),
		    "btf_layout_supported");
	}
	kfree_skb__destroy(skel);
}
