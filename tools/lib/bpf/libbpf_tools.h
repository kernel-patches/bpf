/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __LIBBPF_TOOLS_H
#define __LIBBPF_TOOLS_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <linux/types.h>

/* Internal interfaces for kernel tools that link libbpf statically. */

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/*
 * Re-implement glibc's reallocarray() for libbpf internal-only use.
 * reallocarray(), unfortunately, is not available in all versions of glibc,
 * so requires extra feature detection and using reallocarray() stub from
 * <tools/libc_compat.h> and COMPAT_NEED_REALLOCARRAY. All this complicates
 * build of libbpf unnecessarily and is just a maintenance burden. Instead,
 * it's trivial to implement libbpf-specific internal version and use it
 * throughout libbpf.
 */
static inline void *libbpf_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	size_t total;

#if __has_builtin(__builtin_mul_overflow)
	if (unlikely(__builtin_mul_overflow(nmemb, size, &total)))
		return NULL;
#else
	if (size == 0 || nmemb > ULONG_MAX / size)
		return NULL;
	total = nmemb * size;
#endif
	return realloc(ptr, total);
}

struct btf;
struct btf_header;
struct btf_type;
struct bpf_core_cand;
struct bpf_core_cand_list;

const struct btf_header *btf_header(const struct btf *btf);
const char *btf_kind_str(const struct btf_type *t);
const struct btf_type *skip_mods_and_typedefs(const struct btf *btf, __u32 id, __u32 *res_id);

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

struct btf_ext_info {
	/*
	 * info points to the individual info section (e.g. func_info and
	 * line_info) from the .BTF.ext. It does not include the __u32 rec_size.
	 */
	void *info;
	__u32 rec_size;
	__u32 len;
	/* optional (maintained internally by libbpf) mapping between .BTF.ext
	 * section and corresponding ELF section. This is used to join
	 * information like CO-RE relocation records with corresponding BPF
	 * programs defined in ELF sections
	 */
	__u32 *sec_idxs;
	int sec_cnt;
};

#define for_each_btf_ext_sec(seg, sec)					\
	for (sec = (seg)->info;						\
	     (void *)sec < (seg)->info + (seg)->len;			\
	     sec = (void *)sec + sizeof(struct btf_ext_info_sec) +	\
		   (seg)->rec_size * sec->num_info)

#define for_each_btf_ext_rec(seg, sec, i, rec)				\
	for (i = 0, rec = (void *)&(sec)->data;				\
	     i < (sec)->num_info;					\
	     i++, rec = (void *)rec + (seg)->rec_size)

/*
 * The .BTF.ext ELF section layout defined as
 *   struct btf_ext_header
 *   func_info subsection
 *
 * The func_info subsection layout:
 *   record size for struct bpf_func_info in the func_info subsection
 *   struct btf_ext_info_sec for section #1
 *   a list of bpf_func_info records for section #1
 *     where struct bpf_func_info mimics one in include/uapi/linux/bpf.h
 *     but may not be identical
 *   struct btf_ext_info_sec for section #2
 *   a list of bpf_func_info records for section #2
 *   ......
 *
 * Note that the bpf_func_info record size in .BTF.ext may not
 * be the same as the one defined in include/uapi/linux/bpf.h.
 * The loader should ensure that record_size meets minimum
 * requirement and pass the record as is to the kernel. The
 * kernel will handle the func_info properly based on its contents.
 */
struct btf_ext_header {
	__u16	magic;
	__u8	version;
	__u8	flags;
	__u32	hdr_len;

	/* All offsets are in bytes relative to the end of this header */
	__u32	func_info_off;
	__u32	func_info_len;
	__u32	line_info_off;
	__u32	line_info_len;

	/* optional part of .BTF.ext header */
	__u32	core_relo_off;
	__u32	core_relo_len;
};

struct btf_ext {
	union {
		struct btf_ext_header *hdr;
		void *data;
	};
	void *data_swapped;
	bool swapped_endian;
	struct btf_ext_info func_info;
	struct btf_ext_info line_info;
	struct btf_ext_info core_relo_info;
	__u32 data_size;
};

struct btf_ext_info_sec {
	__u32	sec_name_off;
	__u32	num_info;
	/* Followed by num_info * record_size number of bytes */
	__u8	data[];
};

int bpf_core_add_cands(struct bpf_core_cand *local_cand,
		       size_t local_essent_len,
		       const struct btf *targ_btf,
		       const char *targ_btf_name,
		       int targ_start_id,
		       struct bpf_core_cand_list *cands);
void bpf_core_free_cands(struct bpf_core_cand_list *cands);

int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz);

#define SHA256_DIGEST_LENGTH 32

void libbpf_sha256(const void *data, size_t len, __u8 out[SHA256_DIGEST_LENGTH]);

#endif /* __LIBBPF_TOOLS_H */
