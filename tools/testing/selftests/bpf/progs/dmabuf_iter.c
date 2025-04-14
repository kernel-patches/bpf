// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Google LLC */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("iter/dmabuf")
int dmabuf_collector(struct bpf_iter__dmabuf *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	const struct dma_buf *dmabuf = ctx->dmabuf;

	if (dmabuf) {
		size_t size;
		unsigned long inode;
		const char *name, *exp_name;

		if (bpf_core_read(&size, sizeof(size), &dmabuf->size) ||
		    BPF_CORE_READ_INTO(&inode, dmabuf, file, f_inode, i_ino) ||
		    bpf_core_read(&name, sizeof(name), &dmabuf->name) ||
		    bpf_core_read(&exp_name, sizeof(exp_name), &dmabuf->exp_name))
			return 1;

		BPF_SEQ_PRINTF(seq, "ino:%lu size:%llu name:%s exp_name:%s\n",
			inode, size, name ? name : "", exp_name ? exp_name : "");
	}

	return 0;
}
