// SPDX-License-Identifier: GPL-2.0
#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>

SEC("iter/io_uring_buf")
int dump_io_uring_buf(struct bpf_iter__io_uring_buf *ctx)
{
	struct io_mapped_ubuf *ubuf = ctx->ubuf;
	struct seq_file *seq = ctx->meta->seq;
	unsigned int index = ctx->index;

	if (!ctx->meta->seq_num)
		BPF_SEQ_PRINTF(seq, "B\n");

	if (ubuf) {
		BPF_SEQ_PRINTF(seq, "%u:0x%lx:%lu\n", index, (unsigned long)ubuf->ubuf,
			       (unsigned long)ubuf->ubuf_end - ubuf->ubuf);
		BPF_SEQ_PRINTF(seq, "`-PFN for bvec[0]=%lu\n",
			       (unsigned long)bpf_page_to_pfn(ubuf->bvec[0].bv_page));
	} else {
		BPF_SEQ_PRINTF(seq, "E:%u\n", index);
	}
	return 0;
}

SEC("iter/io_uring_file")
int dump_io_uring_file(struct bpf_iter__io_uring_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	unsigned int index = ctx->index;
	struct file *file = ctx->file;
	char buf[256] = "";

	if (!ctx->meta->seq_num)
		BPF_SEQ_PRINTF(seq, "B\n");
	/* for io_uring_file iterator, this is the terminating condition */
	if (ctx->ctx->nr_user_files == index) {
		BPF_SEQ_PRINTF(seq, "E:%u\n", index);
		return 0;
	}
	if (file) {
		bpf_d_path(&file->f_path, buf, sizeof(buf));
		BPF_SEQ_PRINTF(seq, "%u:%s\n", index, buf);
	} else {
		BPF_SEQ_PRINTF(seq, "%u:<none>\n", index);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
