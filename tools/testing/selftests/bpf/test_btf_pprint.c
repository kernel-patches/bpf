/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 Facebook */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#include "bpf_rlimit.h"
#include "bpf_util.h"
#include "test_btf.h"

#define MAX_INSNS	512
#define MAX_SUBPROGS	16

static uint32_t pass_cnt;
static uint32_t error_cnt;
static uint32_t skip_cnt;

#define CHECK(condition, format...) ({					\
	int __ret = !!(condition);					\
	if (__ret) {							\
		fprintf(stderr, "%s:%d:FAIL ", __func__, __LINE__);	\
		fprintf(stderr, format);				\
	}								\
	__ret;								\
})

static int count_result(int err)
{
	if (err)
		error_cnt++;
	else
		pass_cnt++;

	fprintf(stderr, "\n");
	return err;
}

static int __base_pr(enum libbpf_print_level level __attribute__((unused)),
		     const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

#define BTF_END_RAW 0xdeadbeef
#define NAME_TBD 0xdeadb33f

#define NAME_NTH(N) (0xffff0000 | N)
#define IS_NAME_NTH(X) ((X & 0xffff0000) == 0xffff0000)
#define GET_NAME_NTH_IDX(X) (X & 0x0000ffff)

#define MAX_NR_RAW_U32 1024
#define BTF_LOG_BUF_SIZE 65535

static struct args {
	bool always_log;
} args;

static char btf_log_buf[BTF_LOG_BUF_SIZE];

static struct btf_header hdr_tmpl = {
	.magic = BTF_MAGIC,
	.version = BTF_VERSION,
	.hdr_len = sizeof(struct btf_header),
};

/* several different mapv kinds(types) supported by pprint */
enum pprint_mapv_kind_t {
	PPRINT_MAPV_KIND_BASIC = 0,
	PPRINT_MAPV_KIND_INT128,
};

struct btf_raw_test {
	const char *descr;
	const char *str_sec;
	const char *map_name;
	const char *err_str;
	__u32 raw_types[MAX_NR_RAW_U32];
	__u32 str_sec_size;
	enum bpf_map_type map_type;
	__u32 key_size;
	__u32 value_size;
	__u32 key_type_id;
	__u32 value_type_id;
	__u32 max_entries;
	bool btf_load_err;
	bool map_create_err;
	bool ordered_map;
	bool lossless_map;
	bool percpu_map;
	int hdr_len_delta;
	int type_off_delta;
	int str_off_delta;
	int str_len_delta;
	enum pprint_mapv_kind_t mapv_kind;
};

#define BTF_STR_SEC(str) \
	.str_sec = str, .str_sec_size = sizeof(str)

static const char *get_next_str(const char *start, const char *end)
{
	return start < end - 1 ? start + 1 : NULL;
}

static int get_raw_sec_size(const __u32 *raw_types)
{
	int i;

	for (i = MAX_NR_RAW_U32 - 1;
	     i >= 0 && raw_types[i] != BTF_END_RAW;
	     i--)
		;

	return i < 0 ? i : i * sizeof(raw_types[0]);
}

static void *btf_raw_create(const struct btf_header *hdr,
			    const __u32 *raw_types,
			    const char *str,
			    unsigned int str_sec_size,
			    unsigned int *btf_size,
			    const char **ret_next_str)
{
	const char *next_str = str, *end_str = str + str_sec_size;
	const char **strs_idx = NULL, **tmp_strs_idx;
	int strs_cap = 0, strs_cnt = 0, next_str_idx = 0;
	unsigned int size_needed, offset;
	struct btf_header *ret_hdr;
	int i, type_sec_size, err = 0;
	uint32_t *ret_types;
	void *raw_btf = NULL;

	type_sec_size = get_raw_sec_size(raw_types);
	if (CHECK(type_sec_size < 0, "Cannot get nr_raw_types"))
		return NULL;

	size_needed = sizeof(*hdr) + type_sec_size + str_sec_size;
	raw_btf = malloc(size_needed);
	if (CHECK(!raw_btf, "Cannot allocate memory for raw_btf"))
		return NULL;

	/* Copy header */
	memcpy(raw_btf, hdr, sizeof(*hdr));
	offset = sizeof(*hdr);

	/* Index strings */
	while ((next_str = get_next_str(next_str, end_str))) {
		if (strs_cnt == strs_cap) {
			strs_cap += max(16, strs_cap / 2);
			tmp_strs_idx = realloc(strs_idx,
					       sizeof(*strs_idx) * strs_cap);
			if (CHECK(!tmp_strs_idx,
				  "Cannot allocate memory for strs_idx")) {
				err = -1;
				goto done;
			}
			strs_idx = tmp_strs_idx;
		}
		strs_idx[strs_cnt++] = next_str;
		next_str += strlen(next_str);
	}

	/* Copy type section */
	ret_types = raw_btf + offset;
	for (i = 0; i < type_sec_size / sizeof(raw_types[0]); i++) {
		if (raw_types[i] == NAME_TBD) {
			if (CHECK(next_str_idx == strs_cnt,
				  "Error in getting next_str #%d",
				  next_str_idx)) {
				err = -1;
				goto done;
			}
			ret_types[i] = strs_idx[next_str_idx++] - str;
		} else if (IS_NAME_NTH(raw_types[i])) {
			int idx = GET_NAME_NTH_IDX(raw_types[i]);

			if (CHECK(idx <= 0 || idx > strs_cnt,
				  "Error getting string #%d, strs_cnt:%d",
				  idx, strs_cnt)) {
				err = -1;
				goto done;
			}
			ret_types[i] = strs_idx[idx-1] - str;
		} else {
			ret_types[i] = raw_types[i];
		}
	}
	offset += type_sec_size;

	/* Copy string section */
	memcpy(raw_btf + offset, str, str_sec_size);

	ret_hdr = (struct btf_header *)raw_btf;
	ret_hdr->type_len = type_sec_size;
	ret_hdr->str_off = type_sec_size;
	ret_hdr->str_len = str_sec_size;

	*btf_size = size_needed;
	if (ret_next_str)
		*ret_next_str =
			next_str_idx < strs_cnt ? strs_idx[next_str_idx] : NULL;

done:
	if (err) {
		if (raw_btf)
			free(raw_btf);
		if (strs_idx)
			free(strs_idx);
		return NULL;
	}
	return raw_btf;
}

const char *pprint_enum_str[] = {
	"ENUM_ZERO",
	"ENUM_ONE",
	"ENUM_TWO",
	"ENUM_THREE",
};

struct pprint_mapv {
	uint32_t ui32;
	uint16_t ui16;
	/* 2 bytes hole */
	int32_t si32;
	uint32_t unused_bits2a:2,
		bits28:28,
		unused_bits2b:2;
	union {
		uint64_t ui64;
		uint8_t ui8a[8];
	};
	enum {
		ENUM_ZERO,
		ENUM_ONE,
		ENUM_TWO,
		ENUM_THREE,
	} aenum;
	uint32_t ui32b;
	uint32_t bits2c:2;
	uint8_t si8_4[2][2];
};

#ifdef __SIZEOF_INT128__
struct pprint_mapv_int128 {
	__int128 si128a;
	__int128 si128b;
	unsigned __int128 bits3:3;
	unsigned __int128 bits80:80;
	unsigned __int128 ui128;
};
#endif

static struct btf_raw_test pprint_test_template[] = {
{
	.raw_types = {
		/* unsighed char */			/* [1] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 8, 1),
		/* unsigned short */			/* [2] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 16, 2),
		/* unsigned int */			/* [3] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 32, 4),
		/* int */				/* [4] */
		BTF_TYPE_INT_ENC(NAME_TBD, BTF_INT_SIGNED, 0, 32, 4),
		/* unsigned long long */		/* [5] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 64, 8),
		/* 2 bits */				/* [6] */
		BTF_TYPE_INT_ENC(0, 0, 0, 2, 2),
		/* 28 bits */				/* [7] */
		BTF_TYPE_INT_ENC(0, 0, 0, 28, 4),
		/* uint8_t[8] */			/* [8] */
		BTF_TYPE_ARRAY_ENC(9, 1, 8),
		/* typedef unsigned char uint8_t */	/* [9] */
		BTF_TYPEDEF_ENC(NAME_TBD, 1),
		/* typedef unsigned short uint16_t */	/* [10] */
		BTF_TYPEDEF_ENC(NAME_TBD, 2),
		/* typedef unsigned int uint32_t */	/* [11] */
		BTF_TYPEDEF_ENC(NAME_TBD, 3),
		/* typedef int int32_t */		/* [12] */
		BTF_TYPEDEF_ENC(NAME_TBD, 4),
		/* typedef unsigned long long uint64_t *//* [13] */
		BTF_TYPEDEF_ENC(NAME_TBD, 5),
		/* union (anon) */			/* [14] */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_UNION, 0, 2), 8),
		BTF_MEMBER_ENC(NAME_TBD, 13, 0),/* uint64_t ui64; */
		BTF_MEMBER_ENC(NAME_TBD, 8, 0),	/* uint8_t ui8a[8]; */
		/* enum (anon) */			/* [15] */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_ENUM, 0, 4), 4),
		BTF_ENUM_ENC(NAME_TBD, 0),
		BTF_ENUM_ENC(NAME_TBD, 1),
		BTF_ENUM_ENC(NAME_TBD, 2),
		BTF_ENUM_ENC(NAME_TBD, 3),
		/* struct pprint_mapv */		/* [16] */
		BTF_TYPE_ENC(NAME_TBD, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 11), 40),
		BTF_MEMBER_ENC(NAME_TBD, 11, 0),	/* uint32_t ui32 */
		BTF_MEMBER_ENC(NAME_TBD, 10, 32),	/* uint16_t ui16 */
		BTF_MEMBER_ENC(NAME_TBD, 12, 64),	/* int32_t si32 */
		BTF_MEMBER_ENC(NAME_TBD, 6, 96),	/* unused_bits2a */
		BTF_MEMBER_ENC(NAME_TBD, 7, 98),	/* bits28 */
		BTF_MEMBER_ENC(NAME_TBD, 6, 126),	/* unused_bits2b */
		BTF_MEMBER_ENC(0, 14, 128),		/* union (anon) */
		BTF_MEMBER_ENC(NAME_TBD, 15, 192),	/* aenum */
		BTF_MEMBER_ENC(NAME_TBD, 11, 224),	/* uint32_t ui32b */
		BTF_MEMBER_ENC(NAME_TBD, 6, 256),	/* bits2c */
		BTF_MEMBER_ENC(NAME_TBD, 17, 264),	/* si8_4 */
		BTF_TYPE_ARRAY_ENC(18, 1, 2),		/* [17] */
		BTF_TYPE_ARRAY_ENC(1, 1, 2),		/* [18] */
		BTF_END_RAW,
	},
	BTF_STR_SEC("\0unsigned char\0unsigned short\0unsigned int\0int\0unsigned long long\0uint8_t\0uint16_t\0uint32_t\0int32_t\0uint64_t\0ui64\0ui8a\0ENUM_ZERO\0ENUM_ONE\0ENUM_TWO\0ENUM_THREE\0pprint_mapv\0ui32\0ui16\0si32\0unused_bits2a\0bits28\0unused_bits2b\0aenum\0ui32b\0bits2c\0si8_4"),
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct pprint_mapv),
	.key_type_id = 3,	/* unsigned int */
	.value_type_id = 16,	/* struct pprint_mapv */
	.max_entries = 128 * 1024,
},

{
	/* this type will have the same type as the
	 * first .raw_types definition, but struct type will
	 * be encoded with kind_flag set.
	 */
	.raw_types = {
		/* unsighed char */			/* [1] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 8, 1),
		/* unsigned short */			/* [2] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 16, 2),
		/* unsigned int */			/* [3] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 32, 4),
		/* int */				/* [4] */
		BTF_TYPE_INT_ENC(NAME_TBD, BTF_INT_SIGNED, 0, 32, 4),
		/* unsigned long long */		/* [5] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 64, 8),
		BTF_TYPE_INT_ENC(0, 0, 0, 32, 4),	/* [6] */
		BTF_TYPE_INT_ENC(0, 0, 0, 32, 4),	/* [7] */
		/* uint8_t[8] */			/* [8] */
		BTF_TYPE_ARRAY_ENC(9, 1, 8),
		/* typedef unsigned char uint8_t */	/* [9] */
		BTF_TYPEDEF_ENC(NAME_TBD, 1),
		/* typedef unsigned short uint16_t */	/* [10] */
		BTF_TYPEDEF_ENC(NAME_TBD, 2),
		/* typedef unsigned int uint32_t */	/* [11] */
		BTF_TYPEDEF_ENC(NAME_TBD, 3),
		/* typedef int int32_t */		/* [12] */
		BTF_TYPEDEF_ENC(NAME_TBD, 4),
		/* typedef unsigned long long uint64_t *//* [13] */
		BTF_TYPEDEF_ENC(NAME_TBD, 5),
		/* union (anon) */			/* [14] */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_UNION, 0, 2), 8),
		BTF_MEMBER_ENC(NAME_TBD, 13, 0),/* uint64_t ui64; */
		BTF_MEMBER_ENC(NAME_TBD, 8, 0),	/* uint8_t ui8a[8]; */
		/* enum (anon) */			/* [15] */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_ENUM, 0, 4), 4),
		BTF_ENUM_ENC(NAME_TBD, 0),
		BTF_ENUM_ENC(NAME_TBD, 1),
		BTF_ENUM_ENC(NAME_TBD, 2),
		BTF_ENUM_ENC(NAME_TBD, 3),
		/* struct pprint_mapv */		/* [16] */
		BTF_TYPE_ENC(NAME_TBD, BTF_INFO_ENC(BTF_KIND_STRUCT, 1, 11), 40),
		BTF_MEMBER_ENC(NAME_TBD, 11, BTF_MEMBER_OFFSET(0, 0)),	/* uint32_t ui32 */
		BTF_MEMBER_ENC(NAME_TBD, 10, BTF_MEMBER_OFFSET(0, 32)),	/* uint16_t ui16 */
		BTF_MEMBER_ENC(NAME_TBD, 12, BTF_MEMBER_OFFSET(0, 64)),	/* int32_t si32 */
		BTF_MEMBER_ENC(NAME_TBD, 6, BTF_MEMBER_OFFSET(2, 96)),	/* unused_bits2a */
		BTF_MEMBER_ENC(NAME_TBD, 7, BTF_MEMBER_OFFSET(28, 98)),	/* bits28 */
		BTF_MEMBER_ENC(NAME_TBD, 6, BTF_MEMBER_OFFSET(2, 126)),	/* unused_bits2b */
		BTF_MEMBER_ENC(0, 14, BTF_MEMBER_OFFSET(0, 128)),	/* union (anon) */
		BTF_MEMBER_ENC(NAME_TBD, 15, BTF_MEMBER_OFFSET(0, 192)),	/* aenum */
		BTF_MEMBER_ENC(NAME_TBD, 11, BTF_MEMBER_OFFSET(0, 224)),	/* uint32_t ui32b */
		BTF_MEMBER_ENC(NAME_TBD, 6, BTF_MEMBER_OFFSET(2, 256)),	/* bits2c */
		BTF_MEMBER_ENC(NAME_TBD, 17, 264),	/* si8_4 */
		BTF_TYPE_ARRAY_ENC(18, 1, 2),		/* [17] */
		BTF_TYPE_ARRAY_ENC(1, 1, 2),		/* [18] */
		BTF_END_RAW,
	},
	BTF_STR_SEC("\0unsigned char\0unsigned short\0unsigned int\0int\0unsigned long long\0uint8_t\0uint16_t\0uint32_t\0int32_t\0uint64_t\0ui64\0ui8a\0ENUM_ZERO\0ENUM_ONE\0ENUM_TWO\0ENUM_THREE\0pprint_mapv\0ui32\0ui16\0si32\0unused_bits2a\0bits28\0unused_bits2b\0aenum\0ui32b\0bits2c\0si8_4"),
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct pprint_mapv),
	.key_type_id = 3,	/* unsigned int */
	.value_type_id = 16,	/* struct pprint_mapv */
	.max_entries = 128 * 1024,
},

{
	/* this type will have the same layout as the
	 * first .raw_types definition. The struct type will
	 * be encoded with kind_flag set, bitfield members
	 * are added typedef/const/volatile, and bitfield members
	 * will have both int and enum types.
	 */
	.raw_types = {
		/* unsighed char */			/* [1] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 8, 1),
		/* unsigned short */			/* [2] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 16, 2),
		/* unsigned int */			/* [3] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 32, 4),
		/* int */				/* [4] */
		BTF_TYPE_INT_ENC(NAME_TBD, BTF_INT_SIGNED, 0, 32, 4),
		/* unsigned long long */		/* [5] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 64, 8),
		BTF_TYPE_INT_ENC(0, 0, 0, 32, 4),	/* [6] */
		BTF_TYPE_INT_ENC(0, 0, 0, 32, 4),	/* [7] */
		/* uint8_t[8] */			/* [8] */
		BTF_TYPE_ARRAY_ENC(9, 1, 8),
		/* typedef unsigned char uint8_t */	/* [9] */
		BTF_TYPEDEF_ENC(NAME_TBD, 1),
		/* typedef unsigned short uint16_t */	/* [10] */
		BTF_TYPEDEF_ENC(NAME_TBD, 2),
		/* typedef unsigned int uint32_t */	/* [11] */
		BTF_TYPEDEF_ENC(NAME_TBD, 3),
		/* typedef int int32_t */		/* [12] */
		BTF_TYPEDEF_ENC(NAME_TBD, 4),
		/* typedef unsigned long long uint64_t *//* [13] */
		BTF_TYPEDEF_ENC(NAME_TBD, 5),
		/* union (anon) */			/* [14] */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_UNION, 0, 2), 8),
		BTF_MEMBER_ENC(NAME_TBD, 13, 0),/* uint64_t ui64; */
		BTF_MEMBER_ENC(NAME_TBD, 8, 0),	/* uint8_t ui8a[8]; */
		/* enum (anon) */			/* [15] */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_ENUM, 0, 4), 4),
		BTF_ENUM_ENC(NAME_TBD, 0),
		BTF_ENUM_ENC(NAME_TBD, 1),
		BTF_ENUM_ENC(NAME_TBD, 2),
		BTF_ENUM_ENC(NAME_TBD, 3),
		/* struct pprint_mapv */		/* [16] */
		BTF_TYPE_ENC(NAME_TBD, BTF_INFO_ENC(BTF_KIND_STRUCT, 1, 11), 40),
		BTF_MEMBER_ENC(NAME_TBD, 11, BTF_MEMBER_OFFSET(0, 0)),	/* uint32_t ui32 */
		BTF_MEMBER_ENC(NAME_TBD, 10, BTF_MEMBER_OFFSET(0, 32)),	/* uint16_t ui16 */
		BTF_MEMBER_ENC(NAME_TBD, 12, BTF_MEMBER_OFFSET(0, 64)),	/* int32_t si32 */
		BTF_MEMBER_ENC(NAME_TBD, 17, BTF_MEMBER_OFFSET(2, 96)),	/* unused_bits2a */
		BTF_MEMBER_ENC(NAME_TBD, 7, BTF_MEMBER_OFFSET(28, 98)),	/* bits28 */
		BTF_MEMBER_ENC(NAME_TBD, 19, BTF_MEMBER_OFFSET(2, 126)),/* unused_bits2b */
		BTF_MEMBER_ENC(0, 14, BTF_MEMBER_OFFSET(0, 128)),	/* union (anon) */
		BTF_MEMBER_ENC(NAME_TBD, 15, BTF_MEMBER_OFFSET(0, 192)),	/* aenum */
		BTF_MEMBER_ENC(NAME_TBD, 11, BTF_MEMBER_OFFSET(0, 224)),	/* uint32_t ui32b */
		BTF_MEMBER_ENC(NAME_TBD, 17, BTF_MEMBER_OFFSET(2, 256)),	/* bits2c */
		BTF_MEMBER_ENC(NAME_TBD, 20, BTF_MEMBER_OFFSET(0, 264)),	/* si8_4 */
		/* typedef unsigned int ___int */	/* [17] */
		BTF_TYPEDEF_ENC(NAME_TBD, 18),
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_VOLATILE, 0, 0), 6),	/* [18] */
		BTF_TYPE_ENC(0, BTF_INFO_ENC(BTF_KIND_CONST, 0, 0), 15),	/* [19] */
		BTF_TYPE_ARRAY_ENC(21, 1, 2),					/* [20] */
		BTF_TYPE_ARRAY_ENC(1, 1, 2),					/* [21] */
		BTF_END_RAW,
	},
	BTF_STR_SEC("\0unsigned char\0unsigned short\0unsigned int\0int\0unsigned long long\0uint8_t\0uint16_t\0uint32_t\0int32_t\0uint64_t\0ui64\0ui8a\0ENUM_ZERO\0ENUM_ONE\0ENUM_TWO\0ENUM_THREE\0pprint_mapv\0ui32\0ui16\0si32\0unused_bits2a\0bits28\0unused_bits2b\0aenum\0ui32b\0bits2c\0___int\0si8_4"),
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct pprint_mapv),
	.key_type_id = 3,	/* unsigned int */
	.value_type_id = 16,	/* struct pprint_mapv */
	.max_entries = 128 * 1024,
},

#ifdef __SIZEOF_INT128__
{
	/* test int128 */
	.raw_types = {
		/* unsigned int */				/* [1] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 32, 4),
		/* __int128 */					/* [2] */
		BTF_TYPE_INT_ENC(NAME_TBD, BTF_INT_SIGNED, 0, 128, 16),
		/* unsigned __int128 */				/* [3] */
		BTF_TYPE_INT_ENC(NAME_TBD, 0, 0, 128, 16),
		/* struct pprint_mapv_int128 */			/* [4] */
		BTF_TYPE_ENC(NAME_TBD, BTF_INFO_ENC(BTF_KIND_STRUCT, 1, 5), 64),
		BTF_MEMBER_ENC(NAME_TBD, 2, BTF_MEMBER_OFFSET(0, 0)),		/* si128a */
		BTF_MEMBER_ENC(NAME_TBD, 2, BTF_MEMBER_OFFSET(0, 128)),		/* si128b */
		BTF_MEMBER_ENC(NAME_TBD, 3, BTF_MEMBER_OFFSET(3, 256)),		/* bits3 */
		BTF_MEMBER_ENC(NAME_TBD, 3, BTF_MEMBER_OFFSET(80, 259)),	/* bits80 */
		BTF_MEMBER_ENC(NAME_TBD, 3, BTF_MEMBER_OFFSET(0, 384)),		/* ui128 */
		BTF_END_RAW,
	},
	BTF_STR_SEC("\0unsigned int\0__int128\0unsigned __int128\0pprint_mapv_int128\0si128a\0si128b\0bits3\0bits80\0ui128"),
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(struct pprint_mapv_int128),
	.key_type_id = 1,
	.value_type_id = 4,
	.max_entries = 128 * 1024,
	.mapv_kind = PPRINT_MAPV_KIND_INT128,
},
#endif

};

static struct btf_pprint_test_meta {
	const char *descr;
	enum bpf_map_type map_type;
	const char *map_name;
	bool ordered_map;
	bool lossless_map;
	bool percpu_map;
} pprint_tests_meta[] = {
{
	.descr = "BTF pretty print array",
	.map_type = BPF_MAP_TYPE_ARRAY,
	.map_name = "pprint_test_array",
	.ordered_map = true,
	.lossless_map = true,
	.percpu_map = false,
},

{
	.descr = "BTF pretty print hash",
	.map_type = BPF_MAP_TYPE_HASH,
	.map_name = "pprint_test_hash",
	.ordered_map = false,
	.lossless_map = true,
	.percpu_map = false,
},

{
	.descr = "BTF pretty print lru hash",
	.map_type = BPF_MAP_TYPE_LRU_HASH,
	.map_name = "pprint_test_lru_hash",
	.ordered_map = false,
	.lossless_map = false,
	.percpu_map = false,
},

{
	.descr = "BTF pretty print percpu array",
	.map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.map_name = "pprint_test_percpu_array",
	.ordered_map = true,
	.lossless_map = true,
	.percpu_map = true,
},

{
	.descr = "BTF pretty print percpu hash",
	.map_type = BPF_MAP_TYPE_PERCPU_HASH,
	.map_name = "pprint_test_percpu_hash",
	.ordered_map = false,
	.lossless_map = true,
	.percpu_map = true,
},

{
	.descr = "BTF pretty print lru percpu hash",
	.map_type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
	.map_name = "pprint_test_lru_percpu_hash",
	.ordered_map = false,
	.lossless_map = false,
	.percpu_map = true,
},

};

static size_t get_pprint_mapv_size(enum pprint_mapv_kind_t mapv_kind)
{
	if (mapv_kind == PPRINT_MAPV_KIND_BASIC)
		return sizeof(struct pprint_mapv);

#ifdef __SIZEOF_INT128__
	if (mapv_kind == PPRINT_MAPV_KIND_INT128)
		return sizeof(struct pprint_mapv_int128);
#endif

	assert(0);
}

static void set_pprint_mapv(enum pprint_mapv_kind_t mapv_kind,
			    void *mapv, uint32_t i,
			    int num_cpus, int rounded_value_size)
{
	int cpu;

	if (mapv_kind == PPRINT_MAPV_KIND_BASIC) {
		struct pprint_mapv *v = mapv;

		for (cpu = 0; cpu < num_cpus; cpu++) {
			v->ui32 = i + cpu;
			v->si32 = -i;
			v->unused_bits2a = 3;
			v->bits28 = i;
			v->unused_bits2b = 3;
			v->ui64 = i;
			v->aenum = i & 0x03;
			v->ui32b = 4;
			v->bits2c = 1;
			v->si8_4[0][0] = (cpu + i) & 0xff;
			v->si8_4[0][1] = (cpu + i + 1) & 0xff;
			v->si8_4[1][0] = (cpu + i + 2) & 0xff;
			v->si8_4[1][1] = (cpu + i + 3) & 0xff;
			v = (void *)v + rounded_value_size;
		}
	}

#ifdef __SIZEOF_INT128__
	if (mapv_kind == PPRINT_MAPV_KIND_INT128) {
		struct pprint_mapv_int128 *v = mapv;

		for (cpu = 0; cpu < num_cpus; cpu++) {
			v->si128a = i;
			v->si128b = -i;
			v->bits3 = i & 0x07;
			v->bits80 = (((unsigned __int128)1) << 64) + i;
			v->ui128 = (((unsigned __int128)2) << 64) + i;
			v = (void *)v + rounded_value_size;
		}
	}
#endif
}

ssize_t get_pprint_expected_line(enum pprint_mapv_kind_t mapv_kind,
				 char *expected_line, ssize_t line_size,
				 bool percpu_map, unsigned int next_key,
				 int cpu, void *mapv)
{
	ssize_t nexpected_line = -1;

	if (mapv_kind == PPRINT_MAPV_KIND_BASIC) {
		struct pprint_mapv *v = mapv;

		nexpected_line = snprintf(expected_line, line_size,
					  "%s%u: {%u,0,%d,0x%x,0x%x,0x%x,"
					  "{%llu|[%u,%u,%u,%u,%u,%u,%u,%u]},%s,"
					  "%u,0x%x,[[%d,%d],[%d,%d]]}\n",
					  percpu_map ? "\tcpu" : "",
					  percpu_map ? cpu : next_key,
					  v->ui32, v->si32,
					  v->unused_bits2a,
					  v->bits28,
					  v->unused_bits2b,
					  (__u64)v->ui64,
					  v->ui8a[0], v->ui8a[1],
					  v->ui8a[2], v->ui8a[3],
					  v->ui8a[4], v->ui8a[5],
					  v->ui8a[6], v->ui8a[7],
					  pprint_enum_str[v->aenum],
					  v->ui32b,
					  v->bits2c,
					  v->si8_4[0][0], v->si8_4[0][1],
					  v->si8_4[1][0], v->si8_4[1][1]);
	}

#ifdef __SIZEOF_INT128__
	if (mapv_kind == PPRINT_MAPV_KIND_INT128) {
		struct pprint_mapv_int128 *v = mapv;

		nexpected_line = snprintf(expected_line, line_size,
					  "%s%u: {0x%lx,0x%lx,0x%lx,"
					  "0x%lx%016lx,0x%lx%016lx}\n",
					  percpu_map ? "\tcpu" : "",
					  percpu_map ? cpu : next_key,
					  (uint64_t)v->si128a,
					  (uint64_t)v->si128b,
					  (uint64_t)v->bits3,
					  (uint64_t)(v->bits80 >> 64),
					  (uint64_t)v->bits80,
					  (uint64_t)(v->ui128 >> 64),
					  (uint64_t)v->ui128);
	}
#endif

	return nexpected_line;
}

static int check_line(const char *expected_line, int nexpected_line,
		      int expected_line_len, const char *line)
{
	if (CHECK(nexpected_line == expected_line_len,
		  "expected_line is too long"))
		return -1;

	if (strcmp(expected_line, line)) {
		fprintf(stderr, "unexpected pprint output\n");
		fprintf(stderr, "expected: %s", expected_line);
		fprintf(stderr, "    read: %s", line);
		return -1;
	}

	return 0;
}


static int do_test_pprint(int test_num)
{
	const struct btf_raw_test *test = &pprint_test_template[test_num];
	enum pprint_mapv_kind_t mapv_kind = test->mapv_kind;
	struct bpf_create_map_attr create_attr = {};
	bool ordered_map, lossless_map, percpu_map;
	int err, ret, num_cpus, rounded_value_size;
	unsigned int key, nr_read_elems;
	int map_fd = -1, btf_fd = -1;
	unsigned int raw_btf_size;
	char expected_line[255];
	FILE *pin_file = NULL;
	char pin_path[255];
	size_t line_len = 0;
	char *line = NULL;
	void *mapv = NULL;
	uint8_t *raw_btf;
	ssize_t nread;

	fprintf(stderr, "%s(#%d)......", test->descr, test_num);
	raw_btf = btf_raw_create(&hdr_tmpl, test->raw_types,
				 test->str_sec, test->str_sec_size,
				 &raw_btf_size, NULL);

	if (!raw_btf)
		return -1;

	*btf_log_buf = '\0';
	btf_fd = bpf_load_btf(raw_btf, raw_btf_size,
			      btf_log_buf, BTF_LOG_BUF_SIZE,
			      args.always_log);
	free(raw_btf);

	if (CHECK(btf_fd == -1, "errno:%d", errno)) {
		err = -1;
		goto done;
	}

	create_attr.name = test->map_name;
	create_attr.map_type = test->map_type;
	create_attr.key_size = test->key_size;
	create_attr.value_size = test->value_size;
	create_attr.max_entries = test->max_entries;
	create_attr.btf_fd = btf_fd;
	create_attr.btf_key_type_id = test->key_type_id;
	create_attr.btf_value_type_id = test->value_type_id;

	map_fd = bpf_create_map_xattr(&create_attr);
	if (CHECK(map_fd == -1, "errno:%d", errno)) {
		err = -1;
		goto done;
	}

	ret = snprintf(pin_path, sizeof(pin_path), "%s/%s",
		       "/sys/fs/bpf", test->map_name);

	if (CHECK(ret == sizeof(pin_path), "pin_path %s/%s is too long",
		  "/sys/fs/bpf", test->map_name)) {
		err = -1;
		goto done;
	}

	err = bpf_obj_pin(map_fd, pin_path);
	if (CHECK(err, "bpf_obj_pin(%s): errno:%d.", pin_path, errno))
		goto done;

	percpu_map = test->percpu_map;
	num_cpus = percpu_map ? bpf_num_possible_cpus() : 1;
	rounded_value_size = round_up(get_pprint_mapv_size(mapv_kind), 8);
	mapv = calloc(num_cpus, rounded_value_size);
	if (CHECK(!mapv, "mapv allocation failure")) {
		err = -1;
		goto done;
	}

	for (key = 0; key < test->max_entries; key++) {
		set_pprint_mapv(mapv_kind, mapv, key, num_cpus, rounded_value_size);
		bpf_map_update_elem(map_fd, &key, mapv, 0);
	}

	pin_file = fopen(pin_path, "r");
	if (CHECK(!pin_file, "fopen(%s): errno:%d", pin_path, errno)) {
		err = -1;
		goto done;
	}

	/* Skip lines start with '#' */
	while ((nread = getline(&line, &line_len, pin_file)) > 0 &&
	       *line == '#')
		;

	if (CHECK(nread <= 0, "Unexpected EOF")) {
		err = -1;
		goto done;
	}

	nr_read_elems = 0;
	ordered_map = test->ordered_map;
	lossless_map = test->lossless_map;
	do {
		ssize_t nexpected_line;
		unsigned int next_key;
		void *cmapv;
		int cpu;

		next_key = ordered_map ? nr_read_elems : atoi(line);
		set_pprint_mapv(mapv_kind, mapv, next_key, num_cpus, rounded_value_size);
		cmapv = mapv;

		for (cpu = 0; cpu < num_cpus; cpu++) {
			if (percpu_map) {
				/* for percpu map, the format looks like:
				 * <key>: {
				 *	cpu0: <value_on_cpu0>
				 *	cpu1: <value_on_cpu1>
				 *	...
				 *	cpun: <value_on_cpun>
				 * }
				 *
				 * let us verify the line containing the key here.
				 */
				if (cpu == 0) {
					nexpected_line = snprintf(expected_line,
								  sizeof(expected_line),
								  "%u: {\n",
								  next_key);

					err = check_line(expected_line, nexpected_line,
							 sizeof(expected_line), line);
					if (err == -1)
						goto done;
				}

				/* read value@cpu */
				nread = getline(&line, &line_len, pin_file);
				if (nread < 0)
					break;
			}

			nexpected_line = get_pprint_expected_line(mapv_kind, expected_line,
								  sizeof(expected_line),
								  percpu_map, next_key,
								  cpu, cmapv);
			err = check_line(expected_line, nexpected_line,
					 sizeof(expected_line), line);
			if (err == -1)
				goto done;

			cmapv = cmapv + rounded_value_size;
		}

		if (percpu_map) {
			/* skip the last bracket for the percpu map */
			nread = getline(&line, &line_len, pin_file);
			if (nread < 0)
				break;
		}

		nread = getline(&line, &line_len, pin_file);
	} while (++nr_read_elems < test->max_entries && nread > 0);

	if (lossless_map &&
	    CHECK(nr_read_elems < test->max_entries,
		  "Unexpected EOF. nr_read_elems:%u test->max_entries:%u",
		  nr_read_elems, test->max_entries)) {
		err = -1;
		goto done;
	}

	if (CHECK(nread > 0, "Unexpected extra pprint output: %s", line)) {
		err = -1;
		goto done;
	}

	err = 0;

done:
	if (mapv)
		free(mapv);
	if (!err)
		fprintf(stderr, "OK");
	if (*btf_log_buf && (err || args.always_log))
		fprintf(stderr, "\n%s", btf_log_buf);
	if (btf_fd != -1)
		close(btf_fd);
	if (map_fd != -1)
		close(map_fd);
	if (pin_file)
		fclose(pin_file);
	unlink(pin_path);
	free(line);

	return err;
}

static int test_pprint(void)
{
	unsigned int i;
	int err = 0;

	/* test various maps with the first test template */
	for (i = 0; i < ARRAY_SIZE(pprint_tests_meta); i++) {
		pprint_test_template[0].descr = pprint_tests_meta[i].descr;
		pprint_test_template[0].map_type = pprint_tests_meta[i].map_type;
		pprint_test_template[0].map_name = pprint_tests_meta[i].map_name;
		pprint_test_template[0].ordered_map = pprint_tests_meta[i].ordered_map;
		pprint_test_template[0].lossless_map = pprint_tests_meta[i].lossless_map;
		pprint_test_template[0].percpu_map = pprint_tests_meta[i].percpu_map;

		err |= count_result(do_test_pprint(0));
	}

	/* test rest test templates with the first map */
	for (i = 1; i < ARRAY_SIZE(pprint_test_template); i++) {
		pprint_test_template[i].descr = pprint_tests_meta[0].descr;
		pprint_test_template[i].map_type = pprint_tests_meta[0].map_type;
		pprint_test_template[i].map_name = pprint_tests_meta[0].map_name;
		pprint_test_template[i].ordered_map = pprint_tests_meta[0].ordered_map;
		pprint_test_template[i].lossless_map = pprint_tests_meta[0].lossless_map;
		pprint_test_template[i].percpu_map = pprint_tests_meta[0].percpu_map;
		err |= count_result(do_test_pprint(i));
	}

	return err;
}

static void usage(const char *cmd)
{
	fprintf(stderr, "Usage: %s [-l]\n", cmd);
}

static int parse_args(int argc, char **argv)
{
	const char *optstr = "hlpk:f:r:g:d:";
	int opt;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'l':
			args.always_log = true;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			usage(argv[0]);
			return -1;
		}
	}

	return 0;
}

static void print_summary(void)
{
	fprintf(stderr, "PASS:%u SKIP:%u FAIL:%u\n",
		pass_cnt - skip_cnt, skip_cnt, error_cnt);
}

int main(int argc, char **argv)
{
	int err = 0;

	err = parse_args(argc, argv);
	if (err)
		return err;

	if (args.always_log)
		libbpf_set_print(__base_pr);

	test_pprint();

	print_summary();
	return err;
}
