/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2020 Facebook */
#ifndef _BPF_SIDECAR_H
#define _BPF_SIDECAR_H

#include <linux/types.h>

struct bpf_sidecar_test_read_ctx {
	char *buf;
	loff_t off;
	size_t len;
};

#endif /* _BPF_SIDECAR_H */
