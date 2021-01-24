// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2017 Facebook

#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

int uprobe_res;

SEC("uprobe/func")
int BPF_KPROBE(uprobe, char *s, int len)
{
	/* This BPF program performs variable-offset reads and writes on a
	 * stack-allocated buffer.
	 */
	char buf[16];
	unsigned long idx;
	char out;

	/* Zero-out the buffer so we can read anywhere inside it. */
	__builtin_memset(&buf, 0, 16);
	/* Copy the contents of s from user-space. */
	len &= 0xf;
	if (bpf_probe_read_user(&buf, len, s)) {
		bpf_printk("error reading user mem\n");
		return 1;
	}
	/* Index into the buffer at an unknown offset that comes from the
	 * buffer itself. This is a variable-offset stack read.
	 */
	idx = buf[0];
	idx &= 0xf;
	out = buf[idx];
	/* Append something to the buffer. The position where we append it
	 * is unknown. This is a variable-offset stack write.
	 */
	buf[len] = buf[idx];
	uprobe_res = out;
	return 0;
}

char _license[] SEC("license") = "GPL";
