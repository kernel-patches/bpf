/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FREADER_H
#define _LINUX_FREADER_H

#include <linux/types.h>

struct freader {
	void *buf;
	u32 buf_sz;
	int err;
	union {
		struct {
			struct file *file;
			struct folio *folio;
			void *addr;
			loff_t folio_off;
			bool may_fault;
		};
		struct {
			const char *data;
			u64 data_sz;
		};
	};
};

void freader_init_from_file(struct freader *r, void *buf, u32 buf_sz,
			    struct file *file, bool may_fault);
void freader_init_from_mem(struct freader *r, const char *data, u64 data_sz);
const void *freader_fetch(struct freader *r, loff_t file_off, size_t sz);
void freader_cleanup(struct freader *r);
int freader_err(struct freader *r);
#endif
