// SPDX-License-Identifier: GPL-2.0

/* In linux/bpf.h __bpf_ctx macro is defined differently for BPF and
 * non-BPF targets:
 * - for BPF it is __attribute__((preserve_static_offset))
 * - for non-BPF it is __attribute__((btf_decl_tag("preserve_static_offset")))
 *
 * bpftool uses decl tag as a signal to emit preserve_static_offset,
 * thus additional declaration is needed in this test.
 */
#if __has_attribute(btf_decl_tag)
#define __decl_tag_bpf_ctx __attribute__((btf_decl_tag(("preserve_static_offset"))))
#endif

struct __decl_tag_bpf_ctx __sk_buff;

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* A dummy program that references __sk_buff type in it's BTF,
 * used by test_bpftool.py.
 */
SEC("tc")
int sk_buff_user(struct __sk_buff *skb)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
