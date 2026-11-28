// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_testmod_btf_type_tag_1 {
	int a;
};

struct bpf_testmod_btf_type_tag_4 {
	struct bpf_testmod_btf_type_tag_1 *p;
	int *q;
};

long g;

/* The argument is an __iomem pointer to a struct. */
SEC("fentry/bpf_testmod_test_btf_type_tag_iomem_1")
int BPF_PROG(test_iomem_arg, struct bpf_testmod_btf_type_tag_1 *arg)
{
	g = arg->a;
	return 0;
}

/* The member is an __iomem pointer to a struct. */
SEC("fentry/bpf_testmod_test_btf_type_tag_iomem_2")
int BPF_PROG(test_iomem_struct, struct bpf_testmod_btf_type_tag_4 *arg)
{
	g = arg->p->a;
	return 0;
}

/* The member is an __iomem pointer to an int. */
SEC("fentry/bpf_testmod_test_btf_type_tag_iomem_2")
int BPF_PROG(test_iomem_int, struct bpf_testmod_btf_type_tag_4 *arg)
{
	g = *arg->q;
	return 0;
}

/* The value of the pointers can still be read. */
SEC("fentry/bpf_testmod_test_btf_type_tag_iomem_2")
int BPF_PROG(test_iomem_value, struct bpf_testmod_btf_type_tag_4 *arg)
{
	g = (long)arg->p + (long)arg->q;
	return 0;
}

char _license[] SEC("license") = "GPL";
