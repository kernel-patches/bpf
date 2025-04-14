// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

/*
 * Putting these tests in dynptr_fail.c causes other random tests to fail,
 * keep them in their isolated CU.
 */

SEC("?struct_ops")
__failure __msg("invalid mem access 'scalar'")
int BPF_PROG(test_dynptr_source_release, struct sk_buff *skb,
	     struct Qdisc *sch, struct bpf_sk_buff_ptr *to_free)
{
	struct bpf_dynptr dptr, dptr2;
	char buf[8], *data;

	bpf_dynptr_from_skb((struct __sk_buff *)skb, 0, &dptr);
	bpf_dynptr_read(buf, sizeof(buf), &dptr, 0, 0);
	bpf_dynptr_clone(&dptr, &dptr2);
	data = bpf_dynptr_slice(&dptr2, 0, buf, sizeof(buf));
	bpf_qdisc_skb_drop(skb, to_free);
	/* These reads/writes now succeed since dynptr is destroyed. */
	*(char *)&dptr = *(char *)&dptr2;
	return *data;
}

SEC("?.struct_ops")
struct Qdisc_ops test_dynptr_qdisc = {
	.enqueue   = (void *)test_dynptr_source_release,
	.id        = "bpf_fq",
};
