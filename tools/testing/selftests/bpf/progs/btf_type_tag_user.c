// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#if __has_attribute(btf_type_tag)
volatile const bool skip_tests = false;
#else
volatile const bool skip_tests = true;
#endif

struct bpf_testmod_btf_type_tag {
	int a;
};

int g;

SEC("fentry/bpf_testmod_test_btf_type_tag_user")
int BPF_PROG(sub, struct bpf_testmod_btf_type_tag *arg)
{
  g = arg->a;
  return 0;
}
