/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025 Xiaomi */

#ifndef __BTF_SORT_H
#define __BTF_SORT_H

static __s32 _btf_find_by_name_kind(const struct btf *btf, int start_id, const char *type_name, __u32 kind);
static int btf_compare_type_kinds_names(const void *a, const void *b, void *priv);
static void btf_check_sorted(struct btf *btf, int start_id);

#endif
