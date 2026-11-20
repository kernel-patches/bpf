/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2026 Namjae Jeon <linkinjeon@kernel.org>
 */

#ifndef _LINUX_EXFAT_IOMAP_H
#define _LINUX_EXFAT_IOMAP_H

#include <linux/iomap.h>

/* One synchronous attempt for a direct write extending valid_size. */
struct exfat_dio {
	struct kiocb iocb;
	loff_t start;
	loff_t completed;
};

DECLARE_IOMAP_ITER_NEXT(exfat_iomap_next);
DECLARE_IOMAP_ITER_NEXT(exfat_write_iomap_next);
extern const struct iomap_write_ops exfat_iomap_write_ops;
extern const struct iomap_write_ops exfat_dio_gap_write_ops;
extern const struct iomap_writeback_ops exfat_writeback_ops;
extern const struct iomap_read_ops exfat_iomap_bio_read_ops;

int exfat_iomap_swap_activate(struct swap_info_struct *sis,
			       struct file *file, sector_t *span);

#endif /* _LINUX_EXFAT_IOMAP_H */
