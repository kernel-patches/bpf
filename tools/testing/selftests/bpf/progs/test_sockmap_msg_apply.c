// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, int);
} sock_map SEC(".maps");

#define MSG_MAGIC 0xbeefcafe

struct msg_hdr {
	__u32 magic;
	__u32 len;
};

int good_hdrs;
int bad_hdrs;

/*
 * Each message starts with a header. Apply the verdict to the whole
 * message, so the prog runs again at the next header.
 */
SEC("sk_msg")
int prog_msg_apply_redir(struct sk_msg_md *msg)
{
	struct msg_hdr *hdr;

	if (bpf_msg_pull_data(msg, 0, sizeof(*hdr), 0))
		goto bad;

	hdr = msg->data;
	if ((void *)(hdr + 1) > msg->data_end || hdr->magic != MSG_MAGIC)
		goto bad;

	good_hdrs++;
	bpf_msg_apply_bytes(msg, hdr->len);
	return bpf_msg_redirect_map(msg, &sock_map, 0, 0);
bad:
	bad_hdrs++;
	return SK_DROP;
}

char _license[] SEC("license") = "GPL";
