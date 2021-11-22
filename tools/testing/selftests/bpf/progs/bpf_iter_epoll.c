// SPDX-License-Identifier: GPL-2.0
#include "bpf_iter.h"
#include <bpf/bpf_helpers.h>

extern void pipefifo_fops __ksym;

SEC("iter/epoll")
int dump_epoll(struct bpf_iter__epoll *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct epitem *epi = ctx->epi;
	char sstr[] = "socket";
	char pstr[] = "pipe";

	if (!ctx->meta->seq_num) {
		BPF_SEQ_PRINTF(seq, "B\n");
	}
	if (epi) {
		struct file *f = epi->ffd.file;
		char *str;

		if (f->f_op == &pipefifo_fops)
			str = pstr;
		else
			str = sstr;
		BPF_SEQ_PRINTF(seq, "%s:%d\n", str, epi->ffd.fd);
	} else {
		BPF_SEQ_PRINTF(seq, "E\n");
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
