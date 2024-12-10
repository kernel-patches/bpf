// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

/* Since we have a couple of cases, we just write this file by hand. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

SEC("tp_btf/mr_integ_alloc")
__failure __msg("R1 invalid mem access 'scalar'")
int test_raw_tp_scalar_mr_integ_alloc_arg_4(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +24); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}

SEC("tp_btf/cachefiles_lookup")
__failure __msg("R1 invalid mem access 'scalar'")
int test_raw_tp_scalar_cachefiles_lookup_arg_3(void *ctx) {
    asm volatile("r1 = *(u64 *)(r1 +16); r1 = *(u64 *)(r1 +0);" ::: __clobber_all);
    return 0;
}
