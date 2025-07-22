// SPDX-License-Identifier: GPL-2.0
//
#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "image_size.h"

/* uncompressed vmlinux.bin plus 4KB */
#define MAX_RECORD_SIZE	(IMAGE_SIZE + 4096)
/* ringbuf 2,3,4 are useless */
#define MIN_BUF_SIZE 1

#define KEXEC_RES_KERNEL_NAME "kexec:kernel"
#define KEXEC_RES_INITRD_NAME "kexec:initrd"
#define KEXEC_RES_CMDLINE_NAME "kexec:cmdline"

/* ringbuf is safe since the user space has no write access to them */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF1_SIZE);
} ringbuf_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MIN_BUF_SIZE);
} ringbuf_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MIN_BUF_SIZE);
} ringbuf_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MIN_BUF_SIZE);
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

extern int bpf_copy_to_kernel(const char *name, char *buf, int size) __weak __ksym;
extern struct mem_range_result *bpf_decompress(char *image_gz_payload, int image_gz_sz) __weak __ksym;
extern int bpf_mem_range_result_put(struct mem_range_result *result) __weak __ksym;




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


SEC("fentry.s/bpf_handle_pefile")
int BPF_PROG(parse_pe, struct kexec_context *context)
{
	struct linux_pe_zboot_header *zboot_header;
	unsigned int image_sz;
	char *buf;
	char local_name[32];

	bpf_printk("begin parse PE\n");
	/* BPF verifier should know each variable initial state */
	if (!context->image || (context->image_sz > MAX_RECORD_SIZE)) {
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
	image_sz = context->image_sz;
	bpf_probe_read((void *)buf, sizeof(struct linux_pe_zboot_header), context->image);
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
	if (payload_size >= MAX_RECORD_SIZE ) {
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		bpf_printk("Err: payload_size > MAX_RECORD_SIZE\n");
		return 0;
	}
	/* Overwrite buf */
	bpf_probe_read((void *)buf, payload_size, context->image + payload_offset);
	bpf_printk("Calling bpf_kexec_decompress()\n");
	struct mem_range_result *r = bpf_decompress(buf, payload_size - 4);
	if (!r) {
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		bpf_printk("Err: fail to decompress\n");
		return 0;
	}

	image_sz = r->data_sz;
	if (image_sz > MAX_RECORD_SIZE) {
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		bpf_mem_range_result_put(r);
		bpf_printk("Err: decompressed size too big\n");
		return 0;
	}
	
	/* Since the decompressed size is bigger than original, no need to clean */
	bpf_probe_read((void *)buf, image_sz, r->buf);
	bpf_printk("Calling bpf_copy_to_kernel(), image_sz=0x%x\n", image_sz);
	/* Verifier is unhappy to expose .rodata.str1.1 'map' to kernel */
	__builtin_memcpy(local_name, KEXEC_RES_KERNEL_NAME, 32);
	const char *res_name = local_name;
	bpf_copy_to_kernel(res_name, buf, image_sz);
	bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
	bpf_mem_range_result_put(r);

	return 0;
}

SEC("fentry.s/bpf_post_handle_pefile")
int BPF_PROG(post_parse_pe, struct kexec_context *context)
{
	return 0;
}
