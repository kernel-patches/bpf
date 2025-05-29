// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>


/* 1GB =  1^28 * sizeof(__uint) */
#define MAX_BUF_SIZE	(1 << 30)
/* 512MB is big enough to hold either kernel or initramfs */
#define MAX_RECORD_SIZE	(1 << 28)

#define KEXEC_RES_KERNEL_NAME "kernel"
#define KEXEC_RES_INITRD_NAME "initrd"
#define KEXEC_RES_CMDLINE_NAME "cmdline"

/* ringbuf is safe since the user space has no write access to them */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_BUF_SIZE >> 2);
} ringbuf_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_BUF_SIZE >> 2);
} ringbuf_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_BUF_SIZE >> 2);
} ringbuf_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_BUF_SIZE >> 2);
} ringbuf_4 SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

/*
 * This function ensures that the sections .rodata, .data .bss and .rodata.str1.1
 * are created for a bpf prog.
 */
__attribute__((used)) static int dummy(void)
{
	static const char res_kernel[16] __attribute__((used, section(".rodata"))) = KEXEC_RES_KERNEL_NAME;
	static char local_name[16] __attribute__((used, section(".data"))) = KEXEC_RES_CMDLINE_NAME;
	static char res_cmdline[16] __attribute__((used, section(".bss")));

	__builtin_memcpy(local_name, KEXEC_RES_INITRD_NAME, 16);
	return __builtin_memcmp(local_name, res_kernel, 4);
}

SEC("fentry.s/bpf_handle_pefile")
__attribute__((used)) int BPF_PROG(parse_pe, struct kexec_context *context)
{
	return 0;
}

SEC("fentry.s/bpf_post_handle_pefile")
__attribute__((used)) int BPF_PROG(post_parse_pe, struct kexec_context *context)
{
	return 0;
}
