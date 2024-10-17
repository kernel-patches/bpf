// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BUFF_SZ 4096

/* Will be updated by benchmark before program loading */
const char buff[BUFF_SZ];
const volatile unsigned int buff_len = 4;

long hits = 0;
short result;

char _license[] SEC("license") = "GPL";

SEC("tc")
int compute_checksum(void *ctx)
{
	result = bpf_csum_diff(0, 0, (void *)buff, buff_len, 0);
	__sync_add_and_fetch(&hits, 1);
	return 0;
}

