// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2025, 2026 Red Hat, Inc
//
#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "image_size.h"

/* ringbuf 2,3,4 are useless */
#define MIN_BUF_SIZE    1
#define MAX_RECORD_SIZE (IMAGE_SIZE + 40960)
#define RINGBUF1_SIZE   IMAGE_SIZE_POWER2_ALIGN
#define RINGBUF2_SIZE   MIN_BUF_SIZE
#define RINGBUF3_SIZE   MIN_BUF_SIZE
#define RINGBUF4_SIZE   MIN_BUF_SIZE

#include "template.c"
#include "zboot_envelop.h"

#define ELF_SCAN_MAX 8

/* SHN_UNDEF is a uapi macro not exported via BTF/vmlinux.h */
#ifndef SHN_UNDEF
#define SHN_UNDEF 0
#endif

#ifndef EIO
#define EIO 5
#endif
#ifndef EINVAL
#define EINVAL 22
#endif

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

static const char linux_sect_name[] = KERNEL_SECT_NAME;
static const char initrd_sect_name[] = INITRD_SECT_NAME;
static const char cmdline_sect_name[] = CMDLINE_SECT_NAME;

/*
 * fill_cmd - overwrite the cmd_hdr at the start of @buf and copy @data_len
 *            bytes from @src into the payload area.
 *
 * num_chunks is reserved for future use and always set to 0.
 * payload_len directly describes the raw data length.
 *
 * Returns the total byte count to pass to bpf_buffer_parser().
 */
static int fill_cmd(char *buf, __u16 cmd, __u16 subcmd,
				    const char *src, __u32 data_len)
{
	struct cmd_hdr *hdr;
	char *payload;

	hdr              = (struct cmd_hdr *)buf;
	hdr->cmd         = cmd;
	hdr->subcmd      = subcmd;
	hdr->payload_len = data_len;
	hdr->num_chunks  = 0;

	payload = (char *)(hdr + 1);
	/* Only cmd, no payload */
	if (!src || !data_len)
		return sizeof(*hdr);
	if (data_len > MAX_RECORD_SIZE - sizeof(struct cmd_hdr))
		return 0;
	bpf_probe_read_kernel(payload, data_len, src);

	return sizeof(*hdr) + data_len;
}

/*
 * do_zboot_decompress - verify (if required) and decompress an arm64 zboot
 *                       PE image.
 *
 * @ringbuf:      preallocated ringbuf to use for commands
 * @pe_buf:       pointer to the start of the PE blob
 * @pe_sz:        size of the PE blob
 * @sig_mode: signature enforcement policy from kexec_context
 * @bpf:          parser context
 *
 * Returns 0 on success, negative errno otherwise.
 */
static int do_zboot_decompress(char *ringbuf, const char *pe_buf,
			       __u32 pe_sz,
			       kexec_sig_enforced sig_mode,
			       struct bpf_parser_context *bpf)
{
	struct linux_pe_zboot_header zboot_header;
	unsigned int payload_offset, payload_size, max_payload;
	int total, ret;

	if (pe_sz > MAX_RECORD_SIZE) {
		bpf_printk("do_zboot_decompress: PE image too large\n");
		return -EINVAL;
	}

	/*
	 * Verify PE signature before any further processing if
	 * signature enforcement is requested.
	 */
	if (sig_mode != SIG_ENFORCE_NONE) {
		total = fill_cmd(ringbuf,
				 KEXEC_BPF_CMD_VERIFY_SIG,
				 0,
				 pe_buf,
				 pe_sz);
		ret = bpf_buffer_parser(ringbuf, total, bpf);
		if (ret < 0) {
			bpf_printk("do_zboot_decompress: VERIFY_SIG failed: %d\n",
				   ret);
			return ret;
		}
	}

	/* Read and validate zboot header */
	if (bpf_probe_read_kernel(&zboot_header, sizeof(zboot_header),
				  pe_buf) < 0) {
		bpf_printk("do_zboot_decompress: failed to read zboot header\n");
		return -EIO;
	}

	if (__builtin_memcmp(&zboot_header.image_type, "zimg",
			     sizeof(zboot_header.image_type))) {
		bpf_printk("do_zboot_decompress: not a zboot image\n");
		return -EINVAL;
	}

	payload_offset = zboot_header.payload_offset;
	payload_size   = zboot_header.payload_size;
	bpf_printk("do_zboot_decompress: payload offset=0x%x size=0x%x\n",
		   payload_offset, payload_size);

	if (payload_size < 4) {
		bpf_printk("do_zboot_decompress: zboot payload too small\n");
		return -EINVAL;
	}
	if (payload_offset > pe_sz ||
	    payload_size   > pe_sz ||
	    payload_offset > pe_sz - payload_size) {
		bpf_printk("do_zboot_decompress: zboot payload out of bounds\n");
		return -EINVAL;
	}

	max_payload = MAX_RECORD_SIZE - sizeof(struct cmd_hdr);
	if (payload_size - 4 >= max_payload) {
		bpf_printk("do_zboot_decompress: zboot payload exceeds MAX_RECORD_SIZE\n");
		return -EINVAL;
	}

	/* 4 bytes original size is appended after vmlinuz.bin, strip them */
	total = fill_cmd(ringbuf,
			 KEXEC_BPF_CMD_DECOMPRESS,
			 KEXEC_BPF_SUBCMD_KERNEL,
			 pe_buf + payload_offset,
			 payload_size - 4);

	bpf_printk("do_zboot_decompress: calling bpf_buffer_parser() for DECOMPRESS\n");
	ret = bpf_buffer_parser(ringbuf, total, bpf);
	if (ret < 0) {
		bpf_printk("do_zboot_decompress: decompression failed: %d\n",
			   ret);
		return ret;
	}

	return 0;
}

SEC("fentry.s/kexec_image_parser_anchor")
int BPF_PROG(parse_zboot, struct kexec_context *context, unsigned long parser_id)
{
	kexec_sig_enforced sig_mode;
	struct bpf_parser_context *bpf = NULL;
	Elf64_Ehdr ehdr;
	Elf64_Shdr shstr_shdr;
	__u64 shstrtab_off, shstrtab_sz;
	unsigned long buf_sz;
	char *buf_elf;
	char *ringbuf;
	__u8 magic[4];
	int total, ret, i;

	buf_elf      = BPF_CORE_READ(context, parsing_buf[0]);
	buf_sz       = BPF_CORE_READ(context, parsing_buf_sz[0]);
	sig_mode = BPF_CORE_READ(context, sig_mode);

	if (!buf_elf || buf_sz < 4) {
		bpf_printk("parse_zboot: invalid parsing_buf[0]\n");
		return 0;
	}

	if (bpf_probe_read_kernel(magic, sizeof(magic), buf_elf) < 0) {
		bpf_printk("parse_zboot: failed to read magic\n");
		return 0;
	}

	ringbuf = (char *)bpf_ringbuf_reserve(&ringbuf_1, MAX_RECORD_SIZE, 0);
	if (!ringbuf) {
		bpf_printk("parse_zboot: failed to reserve ringbuf\n");
		return 0;
	}

	bpf = bpf_get_parser_context(parser_id);
	if (!bpf) {
		bpf_printk("parse_zboot: no parser context\n");
		goto discard;
	}

	/*
	 * Plain PE (zboot) path: parsing_buf[0] is a PE image directly.
	 * Mirrors the original parse_zboot behaviour.
	 */
	if (magic[0] == 'M' && magic[1] == 'Z') {
		ret = do_zboot_decompress(ringbuf, buf_elf, (__u32)buf_sz,
					  sig_mode, bpf);
		if (ret < 0)
			goto discard;

		goto done;
	}

	/*
	 * ELF container path: parsing_buf[0] is an ELF with .kernel,
	 * .initrd, .cmdline sections.  .kernel contains a PE zboot image.
	 */
	if (magic[0] != 0x7f || magic[1] != 'E' ||
	    magic[2] != 'L'  || magic[3] != 'F') {
		bpf_printk("parse_zboot: unrecognized format\n");
		goto discard;
	}

	if (buf_sz < sizeof(Elf64_Ehdr)) {
		bpf_printk("parse_zboot: ELF too small\n");
		goto discard;
	}

	if (bpf_probe_read_kernel(&ehdr, sizeof(ehdr), buf_elf) < 0) {
		bpf_printk("parse_zboot: failed to read ELF header\n");
		goto discard;
	}
	if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0 ||
	    ehdr.e_shstrndx == SHN_UNDEF) {
		bpf_printk("parse_zboot: invalid ELF section info\n");
		goto discard;
	}

	if (bpf_probe_read_kernel(&shstr_shdr, sizeof(shstr_shdr),
				  buf_elf + ehdr.e_shoff +
				  ehdr.e_shstrndx * sizeof(Elf64_Shdr)) < 0) {
		bpf_printk("parse_zboot: failed to read shstrtab shdr\n");
		goto discard;
	}
	shstrtab_off = shstr_shdr.sh_offset;
	shstrtab_sz  = shstr_shdr.sh_size;

	for (i = 1; i < ELF_SCAN_MAX; i++) {
		Elf64_Shdr shdr;
		char sec_name[16];
		__u64 name_off;

		if (i >= ehdr.e_shnum)
			break;

		if (bpf_probe_read_kernel(&shdr, sizeof(shdr),
					  buf_elf + ehdr.e_shoff +
					  i * sizeof(Elf64_Shdr)) < 0)
			continue;

		name_off = shstrtab_off + shdr.sh_name;
		if (name_off + sizeof(sec_name) > shstrtab_off + shstrtab_sz)
			continue;
		if (bpf_probe_read_kernel(sec_name, sizeof(sec_name),
					  buf_elf + name_off) < 0)
			continue;

		if (!shdr.sh_size || shdr.sh_offset + shdr.sh_size > buf_sz)
			continue;

		/* .initrd */
		if (__builtin_memcmp(sec_name, initrd_sect_name, sizeof(initrd_sect_name)) == 0) {
			total = fill_cmd(ringbuf,
					 KEXEC_BPF_CMD_COPY,
					 KEXEC_BPF_SUBCMD_INITRD,
					 buf_elf + shdr.sh_offset,
					 (__u32)shdr.sh_size);
			ret = bpf_buffer_parser(ringbuf, total, bpf);
			if (ret < 0) {
				bpf_printk("parse_zboot: COPY initrd failed: %d\n",
					   ret);
				goto discard;
			}
			continue;
		}

		/* .cmdline */
		if (__builtin_memcmp(sec_name, cmdline_sect_name, sizeof(cmdline_sect_name)) == 0) {
			total = fill_cmd(ringbuf,
					 KEXEC_BPF_CMD_COPY,
					 KEXEC_BPF_SUBCMD_CMDLINE,
					 buf_elf + shdr.sh_offset,
					 (__u32)shdr.sh_size);
			ret = bpf_buffer_parser(ringbuf, total, bpf);
			if (ret < 0) {
				bpf_printk("parse_zboot: COPY cmdline failed: %d\n",
					   ret);
				goto discard;
			}
			continue;
		}

		/* .kernel: vmlinuz.efi PE zboot image */
		if (__builtin_memcmp(sec_name, linux_sect_name, sizeof(linux_sect_name)) != 0)
			continue;

		ret = do_zboot_decompress(ringbuf,
					  buf_elf + shdr.sh_offset,
					  (__u32)shdr.sh_size,
					  sig_mode, bpf);
		if (ret < 0)
			goto discard;
	}

done:
	/* Notify kernel that this BPF prog completed successfully */
	total = fill_cmd(ringbuf, KEXEC_BPF_CMD_DONE, 0, NULL, 0);
	ret = bpf_buffer_parser(ringbuf, total, bpf);
	if (ret < 0) {
		bpf_printk("parse_zboot: KEXEC_BPF_CMD_DONE, failed: %d\n", ret);
		goto discard;
	}

discard:
	bpf_ringbuf_discard(ringbuf, BPF_RB_NO_WAKEUP);
	if (bpf)
		bpf_put_parser_context(bpf);
	return 0;
}
