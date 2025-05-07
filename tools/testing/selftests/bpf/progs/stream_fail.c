// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

SEC("syscall")
__failure __msg("R1 type=trusted_ptr_or_null_ expected=")
int stream_get_trusted(void *ctx) {
	struct bpf_stream *stream;

	stream = bpf_stream_get(BPF_STDOUT, NULL);
	bpf_this_cpu_ptr(stream);
	return 0;
}

SEC("tc")
__failure __msg("calling kernel function bpf_prog_stream_get is not allowed")
int stream_get_prog_fail(void *ctx) {
	struct bpf_stream *stream;

	stream = bpf_prog_stream_get(BPF_STDOUT, 0);
	if (!stream)
		return 0;
	bpf_this_cpu_ptr(stream);
	return 0;
}

SEC("syscall")
__failure __msg("R1 type=ptr_or_null_ expected=")
int stream_get_prog_trusted(void *ctx) {
	struct bpf_stream *stream;

	stream = bpf_prog_stream_get(BPF_STDOUT, 0);
	bpf_this_cpu_ptr(stream);
	return 0;
}

SEC("syscall")
__failure __msg("Unreleased reference")
int stream_get_put_missing(void *ctx) {
	struct bpf_stream *stream;

	stream = bpf_prog_stream_get(BPF_STDOUT, 0);
	if (!stream)
		return 0;
	return 0;
}

SEC("syscall")
__failure __msg("R1 must be referenced or trusted")
int stream_next_untrusted_arg(void *ctx)
{
	struct bpf_stream *stream;

	stream = bpf_core_cast((void *)0xdeadbeef, typeof(*stream));
	bpf_stream_next_elem(stream);
	return 0;
}

SEC("syscall")
__failure __msg("Possibly NULL pointer passed")
int stream_next_null_arg(void *ctx)
{
	bpf_stream_next_elem(NULL);
	return 0;
}

SEC("syscall")
__failure __msg("R1 must be referenced or trusted")
int stream_vprintk_untrusted_arg(void *ctx)
{
	struct bpf_stream *stream;

	stream = bpf_core_cast((void *)0xfaceb00c, typeof(*stream));
	bpf_stream_vprintk(stream, "", NULL, 0);
	return 0;
}

SEC("syscall")
__failure __msg("Possibly NULL pointer passed")
int stream_vprintk_null_arg(void *ctx)
{
	bpf_stream_vprintk(NULL, "", NULL, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
