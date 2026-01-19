// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2025, 2026 Red Hat, Inc
//
#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "image_size.h"

/* ringbuf 2,3,4 are useless */
#define MIN_BUF_SIZE 1
#define MAX_RECORD_SIZE (IMAGE_SIZE + 40960)
#define RINGBUF1_SIZE IMAGE_SIZE_POWER2_ALIGN
#define RINGBUF2_SIZE MIN_BUF_SIZE
#define RINGBUF3_SIZE MIN_BUF_SIZE
#define RINGBUF4_SIZE MIN_BUF_SIZE


#include "template.c"

/* see drivers/firmware/efi/libstub/zboot-header.S */
struct linux_pe_zboot_header {
	unsigned int mz_magic;
	char image_type[4];
	unsigned int payload_offset;
	unsigned int payload_size;
	unsigned int reserved[2];
	char comp_type[4];
	unsigned int linux_pe_magic;
	unsigned int pe_header_offset;
} __attribute__((packed));


SEC("fentry.s/kexec_image_parser_anchor")
int BPF_PROG(parse_pe, struct kexec_context *context, unsigned long parser_id)
{
	struct linux_pe_zboot_header *zboot_header;
	unsigned int image_sz;
	char *buf;
	int ret = 0;

	image_sz = context->kernel_sz;
	bpf_printk("begin parse PE\n");
	/* BPF verifier should know each variable initial state */
	if (!context->kernel || (image_sz > MAX_RECORD_SIZE)) {
		bpf_printk("Err: image size is greater than 0x%lx\n", MAX_RECORD_SIZE);
		return 0;
	}

	/* In order to access bytes not aligned on 2 order, copy into ringbuf.
	 * And allocate the memory all at once, later overwriting.
	 *
	 * R2 is ARG_CONST_ALLOC_SIZE_OR_ZERO, should be decided at compling time
	 */
	buf = (char *)bpf_ringbuf_reserve(&ringbuf_1, MAX_RECORD_SIZE, 0);
	if (!buf) {
	    	bpf_printk("Err: fail to reserve ringbuf to parse zboot header\n");
		return 0;
	}
	bpf_probe_read((void *)buf, sizeof(struct linux_pe_zboot_header), context->kernel);
	zboot_header = (struct linux_pe_zboot_header *)buf;
	if (!!__builtin_memcmp(&zboot_header->image_type, "zimg",
			sizeof(zboot_header->image_type))) {
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		bpf_printk("Err: image is not zboot image\n");
		return 0;
	}

	unsigned int payload_offset = zboot_header->payload_offset;
	unsigned int payload_size = zboot_header->payload_size;
	bpf_printk("zboot image payload offset=0x%x, size=0x%x\n", payload_offset, payload_size);
	/* sane check */
	if (payload_size > image_sz) {
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		bpf_printk("Invalid zboot image payload offset and size\n");
		return 0;
	}
	unsigned int max_payload = MAX_RECORD_SIZE - sizeof(struct cmd_hdr);
	if (payload_size >= max_payload) {
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		bpf_printk("Err: payload_size > MAX_RECORD_SIZE\n");
		return 0;
	}
	void *dst = (void *)buf + sizeof(struct cmd_hdr);
	/* Overwrite buf */
	struct cmd_hdr *cmd = (struct cmd_hdr *)buf;
	cmd->cmd = KEXEC_BPF_CMD_DECOMPRESS;
	cmd->subcmd = KEXEC_BPF_SUBCMD_KERNEL;
	/* 4 bytes original size is appended after vmlinuz.bin */
	cmd->payload_len = payload_size - 4;
	bpf_probe_read(dst, payload_size, context->kernel + payload_offset);
	if (payload_size < 4) {
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		return 0;
	}
	bpf_printk("Calling bpf_kexec_decompress()\n");
	struct bpf_parser_context *bpf = bpf_get_parser_context(parser_id);
	if (!bpf) {
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		bpf_printk("No parser in kernel\n");
		return 0;
	}
	ret = bpf_buffer_parser(buf, sizeof(struct cmd_hdr) + payload_size - 4, bpf);
	if (ret < 0) {
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		bpf_put_parser_context(bpf);
		bpf_printk("Decompression fails\n");
		return 0;
	}
	bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
	bpf_put_parser_context(bpf);

	return 0;
}
