// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2026 Red Hat, Inc
//
// Original file: kernel/kexec_bpf/template.c
//
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* Mark the bpf parser success */
#define KEXEC_BPF_CMD_DONE		0x1
#define KEXEC_BPF_CMD_DECOMPRESS	0x2
#define KEXEC_BPF_CMD_COPY		0x3
#define KEXEC_BPF_CMD_VERIFY_SIG	0x4

#define KEXEC_BPF_SUBCMD_KERNEL		0x1
#define KEXEC_BPF_SUBCMD_INITRD		0x2
#define KEXEC_BPF_SUBCMD_CMDLINE	0x3

#define KEXEC_BPF_PIPELINE_FILL		0x1

/*
 * The ringbufs can have different capacity. But only four ringbuf are provided.
 */
#ifndef RINGBUF1_SIZE
#define RINGBUF1_SIZE	4
#endif
#ifndef RINGBUF2_SIZE
#define RINGBUF2_SIZE	4
#endif
#ifndef RINGBUF3_SIZE
#define RINGBUF3_SIZE	4
#endif
#ifndef RINGBUF4_SIZE
#define RINGBUF4_SIZE	4
#endif

/* ringbuf is safe since the user space has no write access to them */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF1_SIZE);
} ringbuf_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF2_SIZE);
} ringbuf_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF3_SIZE);
} ringbuf_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF4_SIZE);
} ringbuf_4 SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

/*
 * This function ensures that the sections .rodata, .data, .rodata.str1.1 and .bss
 * are created for a bpf prog.
 */
static const char dummy_rodata[16] __attribute__((used)) = "rodata";
static char dummy_data[16] __attribute__((used)) = "data";
static char *dummy_mergeable_str  __attribute__((used)) = ".rodata.str1.1";
static char dummy_bss[16] __attribute__((used));

