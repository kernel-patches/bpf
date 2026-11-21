/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __LIBBPF_TOOLS_H
#define __LIBBPF_TOOLS_H

#include <linux/types.h>
#include <stddef.h>

/* Internal interfaces for kernel tools that link libbpf statically. */

struct btf;
struct btf_header;
struct btf_type;

const struct btf_header *btf_header(const struct btf *btf);
int btf_kfunc_proto_match(const struct btf *a, __u32 a_id,
			  const struct btf *b, __u32 b_id);

enum btf_field_iter_kind {
	BTF_FIELD_ITER_IDS,
	BTF_FIELD_ITER_STRS,
};

struct btf_field_desc {
	/* once-per-type offsets */
	int t_off_cnt, t_offs[2];
	/* member struct size, or zero, if no members */
	int m_sz;
	/* repeated per-member offsets */
	int m_off_cnt, m_offs[2];
};

struct btf_field_iter {
	struct btf_field_desc desc;
	void *p;
	int m_idx;
	int off_idx;
	int vlen;
};

int btf_field_iter_init(struct btf_field_iter *it, struct btf_type *t,
			enum btf_field_iter_kind iter_kind);
__u32 *btf_field_iter_next(struct btf_field_iter *it);

#define SHA256_DIGEST_LENGTH 32

void libbpf_sha256(const void *data, size_t len, __u8 out[SHA256_DIGEST_LENGTH]);

#endif /* __LIBBPF_TOOLS_H */
