/*
 * Extract from linux kernel include/linux/pe.h
 */

#ifndef __PE_H__
#define __PE_H__

#define IMAGE_DOS_SIGNATURE	0x5a4d	/* "MZ" */
#define IMAGE_NT_SIGNATURE	0x00004550	/* "PE\0\0" */

struct mz_hdr {
	uint16_t magic;		/* MZ_MAGIC */
	uint16_t lbsize;	/* size of last used block */
	uint16_t blocks;	/* pages in file, 0x3 */
	uint16_t relocs;	/* relocations */
	uint16_t hdrsize;	/* header size in "paragraphs" */
	uint16_t min_extra_pps;	/* .bss */
	uint16_t max_extra_pps;	/* runtime limit for the arena size */
	uint16_t ss;		/* relative stack segment */
	uint16_t sp;		/* initial %sp register */
	uint16_t checksum;	/* word checksum */
	uint16_t ip;		/* initial %ip register */
	uint16_t cs;		/* initial %cs relative to load segment */
	uint16_t reloc_table_offset;	/* offset of the first relocation */
	uint16_t overlay_num;	/* overlay number.  set to 0. */
	uint16_t reserved0[4];	/* reserved */
	uint16_t oem_id;	/* oem identifier */
	uint16_t oem_info;	/* oem specific */
	uint16_t reserved1[10];	/* reserved */
	uint32_t peaddr;	/* address of pe header */
	char     message[];	/* message to print */
};

struct pe_hdr {
	uint32_t magic;		/* PE magic */
	uint16_t machine;	/* machine type */
	uint16_t sections;	/* number of sections */
	uint32_t timestamp;	/* time_t */
	uint32_t symbol_table;	/* symbol table offset */
	uint32_t symbols;	/* number of symbols */
	uint16_t opt_hdr_size;	/* size of optional header */
	uint16_t flags;		/* flags */
};

/* the fact that pe32 isn't padded where pe32+ is 64-bit means union won't
 * work right.  vomit. */
struct pe32_opt_hdr {
	/* "standard" header */
	uint16_t magic;		/* file type */
	uint8_t  ld_major;	/* linker major version */
	uint8_t  ld_minor;	/* linker minor version */
	uint32_t text_size;	/* size of text section(s) */
	uint32_t data_size;	/* size of data section(s) */
	uint32_t bss_size;	/* size of bss section(s) */
	uint32_t entry_point;	/* file offset of entry point */
	uint32_t code_base;	/* relative code addr in ram */
	uint32_t data_base;	/* relative data addr in ram */
	/* "windows" header */
	uint32_t image_base;	/* preferred load address */
	uint32_t section_align;	/* alignment in bytes */
	uint32_t file_align;	/* file alignment in bytes */
	uint16_t os_major;	/* major OS version */
	uint16_t os_minor;	/* minor OS version */
	uint16_t image_major;	/* major image version */
	uint16_t image_minor;	/* minor image version */
	uint16_t subsys_major;	/* major subsystem version */
	uint16_t subsys_minor;	/* minor subsystem version */
	uint32_t win32_version;	/* reserved, must be 0 */
	uint32_t image_size;	/* image size */
	uint32_t header_size;	/* header size rounded up to
				   file_align */
	uint32_t csum;		/* checksum */
	uint16_t subsys;	/* subsystem */
	uint16_t dll_flags;	/* more flags! */
	uint32_t stack_size_req;/* amt of stack requested */
	uint32_t stack_size;	/* amt of stack required */
	uint32_t heap_size_req;	/* amt of heap requested */
	uint32_t heap_size;	/* amt of heap required */
	uint32_t loader_flags;	/* reserved, must be 0 */
	uint32_t data_dirs;	/* number of data dir entries */
};

struct pe32plus_opt_hdr {
	uint16_t magic;		/* file type */
	uint8_t  ld_major;	/* linker major version */
	uint8_t  ld_minor;	/* linker minor version */
	uint32_t text_size;	/* size of text section(s) */
	uint32_t data_size;	/* size of data section(s) */
	uint32_t bss_size;	/* size of bss section(s) */
	uint32_t entry_point;	/* file offset of entry point */
	uint32_t code_base;	/* relative code addr in ram */
	/* "windows" header */
	uint64_t image_base;	/* preferred load address */
	uint32_t section_align;	/* alignment in bytes */
	uint32_t file_align;	/* file alignment in bytes */
	uint16_t os_major;	/* major OS version */
	uint16_t os_minor;	/* minor OS version */
	uint16_t image_major;	/* major image version */
	uint16_t image_minor;	/* minor image version */
	uint16_t subsys_major;	/* major subsystem version */
	uint16_t subsys_minor;	/* minor subsystem version */
	uint32_t win32_version;	/* reserved, must be 0 */
	uint32_t image_size;	/* image size */
	uint32_t header_size;	/* header size rounded up to
				   file_align */
	uint32_t csum;		/* checksum */
	uint16_t subsys;	/* subsystem */
	uint16_t dll_flags;	/* more flags! */
	uint64_t stack_size_req;/* amt of stack requested */
	uint64_t stack_size;	/* amt of stack required */
	uint64_t heap_size_req;	/* amt of heap requested */
	uint64_t heap_size;	/* amt of heap required */
	uint32_t loader_flags;	/* reserved, must be 0 */
	uint32_t data_dirs;	/* number of data dir entries */
};

struct data_dirent {
	uint32_t virtual_address;	/* relative to load address */
	uint32_t size;
};

struct data_directory {
	struct data_dirent exports;		/* .edata */
	struct data_dirent imports;		/* .idata */
	struct data_dirent resources;		/* .rsrc */
	struct data_dirent exceptions;		/* .pdata */
	struct data_dirent certs;		/* certs */
	struct data_dirent base_relocations;	/* .reloc */
	struct data_dirent debug;		/* .debug */
	struct data_dirent arch;		/* reservered */
	struct data_dirent global_ptr;		/* global pointer reg. Size=0 */
	struct data_dirent tls;			/* .tls */
	struct data_dirent load_config;		/* load configuration structure */
	struct data_dirent bound_imports;	/* no idea */
	struct data_dirent import_addrs;	/* import address table */
	struct data_dirent delay_imports;	/* delay-load import table */
	struct data_dirent clr_runtime_hdr;	/* .cor (object only) */
	struct data_dirent reserved;
};

struct section_header {
	char name[8];			/* name or "/12\0" string tbl offset */
	uint32_t virtual_size;		/* size of loaded section in ram */
	uint32_t virtual_address;	/* relative virtual address */
	uint32_t raw_data_size;		/* size of the section */
	uint32_t data_addr;		/* file pointer to first page of sec */
	uint32_t relocs;		/* file pointer to relocation entries */
	uint32_t line_numbers;		/* line numbers! */
	uint16_t num_relocs;		/* number of relocations */
	uint16_t num_lin_numbers;	/* srsly. */
	uint32_t flags;
};

struct win_certificate {
	uint32_t length;
	uint16_t revision;
	uint16_t cert_type;
};

/*
 * Return -1 if not PE, else offset of the PE header
 */
static int get_pehdr_offset(const char *buf)
{
	int pe_hdr_offset;

	pe_hdr_offset = *((int *)(buf + 0x3c));
	buf += pe_hdr_offset;
	if (!!memcmp(buf, "PE\0\0", 4)) {
		printf("Not a PE file\n");
		return -1;
	}

	return pe_hdr_offset;
}

#endif
