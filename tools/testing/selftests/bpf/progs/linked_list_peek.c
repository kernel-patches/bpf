// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

struct node_data {
	struct bpf_list_node l_node;
	int key;
};

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))
private(A) struct bpf_spin_lock glock;
private(A) struct bpf_list_head ghead __contains(node_data, l_node);

#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define NR_NODES 32

int zero = 0;

SEC("syscall")
__retval(0)
long list_peek(void *ctx)
{
	struct bpf_list_node *l_n;
	struct node_data *n;
	int i, err = 0;

	for (i = zero; i < NR_NODES && can_loop; i++) {
		n = bpf_obj_new(typeof(*n));
		if (!n)
			return __LINE__;
		n->key = i;
		bpf_spin_lock(&glock);
		err = bpf_list_push_back(&ghead, &n->l_node);
		bpf_spin_unlock(&glock);

		if (err)
			return __LINE__;
	}

	bpf_spin_lock(&glock);

	l_n = bpf_list_front(&ghead);
	if (!l_n) {
		err = __LINE__;
		goto done;
	}

	n = list_entry(l_n, struct node_data, l_node);
	if (n->key != 0) {
		err = __LINE__;
		goto done;
	}

	l_n = bpf_list_back(&ghead);
	if (!l_n) {
		err = __LINE__;
		goto done;
	}

	n = list_entry(l_n, struct node_data, l_node);
	if (n->key != NR_NODES - 1) {
		err = __LINE__;
		goto done;
	}

done:
	bpf_spin_unlock(&glock);
	return err;
}

char _license[] SEC("license") = "GPL";
