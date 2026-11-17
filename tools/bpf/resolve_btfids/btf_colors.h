/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __RESOLVE_BTFIDS_BTF_COLORS_H
#define __RESOLVE_BTFIDS_BTF_COLORS_H

#include <bpf/btf.h>

enum btf_color {
	BTF_COLOR_NONE = 0,
	BTF_COLOR_MAIN = 1,
	BTF_COLOR_LOC = 2,
	BTF_COLOR_SHARED = BTF_COLOR_MAIN | BTF_COLOR_LOC,
};

#define BTF_SHA256_DIGEST_LENGTH	32

void btf_sha256(const void *data, size_t len,
		__u8 out[BTF_SHA256_DIGEST_LENGTH]);
size_t btf_essential_name_len(const char *name);
int btf_types_are_compat(const struct btf *btf1, __u32 id1,
			 const struct btf *btf2, __u32 id2);
void btf_mark_reachable(struct btf *btf, __u32 root, enum btf_color color,
			__u8 *colors, __u32 *worklist);

int btf_split_by_color(struct btf *src, const __u8 *colors,
		       struct btf **main_out, struct btf **inline_out);

#endif
