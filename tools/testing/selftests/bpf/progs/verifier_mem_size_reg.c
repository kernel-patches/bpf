// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

/*
 * The __szk size of a kfunc memory/size pair must be marked precise even when
 * the nullable buffer is passed as NULL. In that case check_mem_size_reg() -
 * which would otherwise mark the size precise - is skipped, so the size must be
 * marked precise through the scalar argument path instead. bpf_dynptr_slice()'s
 * buffer is nullable and its size (R4) is __szk.
 */
SEC("?tc")
__success __log_level(2)
__msg("mark_precise: frame0: regs=r4 stack= before")
int dynptr_slice_null_buf_size_precise(struct __sk_buff *skb)
{
	struct bpf_dynptr dptr;
	char *p;

	bpf_dynptr_from_skb(skb, 0, &dptr);
	/* NULL buffer: check_mem_size_reg() is skipped, but the __szk size must
	 * still be marked precise via the scalar arg path.
	 */
	p = bpf_dynptr_slice(&dptr, 0, NULL, 8);
	if (p)
		return p[0];
	return 0;
}
