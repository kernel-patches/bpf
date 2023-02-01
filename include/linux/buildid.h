/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BUILDID_H
#define _LINUX_BUILDID_H

#include <linux/mm_types.h>
#include <linux/slab.h>

#define BUILD_ID_SIZE_MAX 20

struct build_id {
	u32 sz;
	char data[BUILD_ID_SIZE_MAX];
};

int build_id_parse(struct vm_area_struct *vma, unsigned char *build_id,
		   __u32 *size);
int build_id_parse_buf(const void *buf, unsigned char *build_id, u32 buf_size);

#if IS_ENABLED(CONFIG_STACKTRACE_BUILD_ID) || IS_ENABLED(CONFIG_CRASH_CORE)
extern unsigned char vmlinux_build_id[BUILD_ID_SIZE_MAX];
void init_vmlinux_build_id(void);
#else
static inline void init_vmlinux_build_id(void) { }
#endif

#ifdef CONFIG_FILE_BUILD_ID
void __init build_id_init(void);
void build_id_free(struct build_id *bid);
int vma_get_build_id(struct vm_area_struct *vma, struct build_id **bidp);
void file_build_id_free(struct file *f);
#else
static inline void __init build_id_init(void) { }
static inline void build_id_free(struct build_id *bid) { }
static inline void file_build_id_free(struct file *f) { }
#endif /* CONFIG_FILE_BUILD_ID */

#endif
