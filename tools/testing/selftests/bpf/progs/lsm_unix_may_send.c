// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

#ifndef EPERM
#define EPERM 1
#endif

SEC("lsm/unix_may_send")
int BPF_PROG(unix_scrub_scm_rights,
	     struct socket *sock, struct socket *other, struct sk_buff *skb)
{
	struct unix_skb_parms *cb;

	if (!skb)
		return 0;

	cb = (struct unix_skb_parms *)skb->cb;
	if (!cb->fp)
		return 0;

	if (bpf_unix_scrub_fds(skb))
		return -EPERM;

	return 0;
}

char _license[] SEC("license") = "GPL";
