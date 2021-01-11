// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021, Oracle and/or its affiliates. */
#include <test_progs.h>
#include <linux/bpf.h>
#include <bpf/btf.h>

#include <stdio.h>
#include <string.h>

#define STRSIZE			2048
#define EXPECTED_STRSIZE	256

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))
#endif

/* skip "enum "/"struct " prefixes */
#define SKIP_PREFIX(_typestr, _prefix)					\
	do {								\
		if (strstr(_typestr, _prefix) == _typestr)		\
			_typestr += strlen(_prefix) + 1;		\
	} while (0)

#define TEST_BTF(btf, _str, _type, _flags, _expected, ...)		\
	do {								\
		const char _expectedval[EXPECTED_STRSIZE] = _expected;	\
		const char __ptrtype[64] = #_type;			\
		char *_ptrtype = (char *)__ptrtype;			\
		__u64 _hflags = _flags | BTF_F_COMPACT;			\
		static _type _ptrdata = __VA_ARGS__;			\
		void *_ptr = &_ptrdata;					\
		__s32 _type_id;						\
		int _cmp, _ret;						\
									\
		SKIP_PREFIX(_ptrtype, "enum");				\
		SKIP_PREFIX(_ptrtype, "struct");			\
		SKIP_PREFIX(_ptrtype, "union");				\
		_ptr = &_ptrdata;					\
		_type_id = btf__find_by_name(btf, _ptrtype);		\
		if (CHECK(_type_id <= 0, "find type id",		\
			  "no '%s' in BTF: %d\n", _ptrtype, _type_id))	\
			return;						\
		_ret = btf__snprintf(btf, _str, STRSIZE, _type_id, _ptr,\
				     _hflags);				\
		if (CHECK(_ret < 0, "btf snprintf", "failed: %d\n",	\
			  _ret))					\
			return;						\
		_cmp = strncmp(_str, _expectedval, EXPECTED_STRSIZE);	\
		if (CHECK(_cmp, "ensure expected/actual match",		\
			  "'%s' does not match expected '%s': %d\n",	\
			   _str, _expectedval, _cmp))			\
			return;						\
	} while (0)

/* Use where expected data string matches its stringified declaration */
#define TEST_BTF_C(btf, _str, _type, _flags, ...)			\
	TEST_BTF(btf, _str, _type, _flags, "(" #_type ")" #__VA_ARGS__,	\
		 __VA_ARGS__)

/* Demonstrate that libbpf btf__snprintf succeeds and that various
 * data types are formatted correctly.
 */
void test_snprintf_btf_user(void)
{
	struct btf *btf = libbpf_find_kernel_btf();
	int duration = 0;
	char str[STRSIZE];

	if (CHECK(!btf, "get kernel BTF", "no kernel BTF found"))
		return;

	/* Verify type display for various types. */

	/* simple int */
	TEST_BTF_C(btf, str, int, 0, 1234);
	TEST_BTF(btf, str, int, BTF_F_NONAME, "1234", 1234);

	/* zero value should be printed at toplevel */
	TEST_BTF(btf, str, int, 0, "(int)0", 0);
	TEST_BTF(btf, str, int, BTF_F_NONAME, "0", 0);
	TEST_BTF(btf, str, int, BTF_F_ZERO, "(int)0", 0);
	TEST_BTF(btf, str, int, BTF_F_NONAME | BTF_F_ZERO, "0", 0);
	TEST_BTF_C(btf, str, int, 0, -4567);
	TEST_BTF(btf, str, int, BTF_F_NONAME, "-4567", -4567);

	/* simple char */
	TEST_BTF_C(btf, str, char, 0, 100);
	TEST_BTF(btf, str, char, BTF_F_NONAME, "100", 100);
	/* zero value should be printed at toplevel */
	TEST_BTF(btf, str, char, 0, "(char)0", 0);
	TEST_BTF(btf, str, char, BTF_F_NONAME, "0", 0);
	TEST_BTF(btf, str, char, BTF_F_ZERO, "(char)0", 0);
	TEST_BTF(btf, str, char, BTF_F_NONAME | BTF_F_ZERO, "0", 0);

	/* simple typedef */
	TEST_BTF_C(btf, str, uint64_t, 0, 100);
	TEST_BTF(btf, str, u64, BTF_F_NONAME, "1", 1);
	/* zero value should be printed at toplevel */
	TEST_BTF(btf, str, u64, 0, "(u64)0", 0);
	TEST_BTF(btf, str, u64, BTF_F_NONAME, "0", 0);
	TEST_BTF(btf, str, u64, BTF_F_ZERO, "(u64)0", 0);
	TEST_BTF(btf, str, u64, BTF_F_NONAME|BTF_F_ZERO, "0", 0);

	/* typedef struct */
	TEST_BTF_C(btf, str, atomic_t, 0, {.counter = (int)1,});
	TEST_BTF(btf, str, atomic_t, BTF_F_NONAME, "{1,}", {.counter = 1,});
	/* typedef with 0 value should be printed at toplevel */
	TEST_BTF(btf, str, atomic_t, 0, "(atomic_t){}", {.counter = 0,});
	TEST_BTF(btf, str, atomic_t, BTF_F_NONAME, "{}", {.counter = 0,});
	TEST_BTF(btf,str, atomic_t, BTF_F_ZERO, "(atomic_t){.counter = (int)0,}",
		 {.counter = 0,});
	TEST_BTF(btf, str, atomic_t, BTF_F_NONAME|BTF_F_ZERO,
		 "{0,}", {.counter = 0,});

	/* enum where enum value does (and does not) exist */
	TEST_BTF_C(btf, str, enum bpf_cmd, 0, BPF_MAP_CREATE);
	TEST_BTF(btf, str, enum bpf_cmd, 0, "(enum bpf_cmd)BPF_MAP_CREATE", 0);
	TEST_BTF(btf, str, enum bpf_cmd, BTF_F_NONAME, "BPF_MAP_CREATE",
		 BPF_MAP_CREATE);
	TEST_BTF(btf, str, enum bpf_cmd, BTF_F_NONAME|BTF_F_ZERO,
		 "BPF_MAP_CREATE", 0);

	TEST_BTF(btf, str, enum bpf_cmd, BTF_F_ZERO,
		 "(enum bpf_cmd)BPF_MAP_CREATE",
		 BPF_MAP_CREATE);
	TEST_BTF(btf, str, enum bpf_cmd, BTF_F_NONAME|BTF_F_ZERO,
		 "BPF_MAP_CREATE", BPF_MAP_CREATE);
	TEST_BTF_C(btf, str, enum bpf_cmd, 0, 2000);
	TEST_BTF(btf, str, enum bpf_cmd, BTF_F_NONAME, "2000", 2000);

	/* simple struct */
	TEST_BTF_C(btf, str, struct btf_enum, 0,
		   {.name_off = (__u32)3,.val = (__s32)-1,});
	TEST_BTF(btf, str, struct btf_enum, BTF_F_NONAME, "{3,-1,}",
		 { .name_off = 3, .val = -1,});
	TEST_BTF(btf, str, struct btf_enum, BTF_F_NONAME, "{-1,}",
		 { .name_off = 0, .val = -1,});
	TEST_BTF(btf, str, struct btf_enum, BTF_F_NONAME|BTF_F_ZERO, "{0,-1,}",
		 { .name_off = 0, .val = -1,});
	/* empty struct should be printed */
	TEST_BTF(btf, str, struct btf_enum, 0, "(struct btf_enum){}",
		 { .name_off = 0, .val = 0,});
	TEST_BTF(btf, str, struct btf_enum, BTF_F_NONAME, "{}",
		 { .name_off = 0, .val = 0,});
	TEST_BTF(btf, str, struct btf_enum, BTF_F_ZERO,
		 "(struct btf_enum){.name_off = (__u32)0,.val = (__s32)0,}",
		 { .name_off = 0, .val = 0,});

	/* struct with pointers */
	TEST_BTF(btf, str, struct list_head, BTF_F_PTR_RAW,
		 "(struct list_head){.next = (struct list_head *)0x1,}",
		 { .next = (struct list_head *)1 });
	/* NULL pointer should not be displayed */
	TEST_BTF(btf, str, struct list_head, BTF_F_PTR_RAW,
		 "(struct list_head){}",
		 { .next = (struct list_head *)0 });

	/* struct with char array */
	TEST_BTF(btf, str, struct bpf_prog_info, 0,
		 "(struct bpf_prog_info){.name = (char[])['f','o','o',],}",
		 { .name = "foo",});
	TEST_BTF(btf, str, struct bpf_prog_info, BTF_F_NONAME,
		 "{['f','o','o',],}",
		 {.name = "foo",});
	/* leading null char means do not display string */
	TEST_BTF(btf, str, struct bpf_prog_info, 0,
		 "(struct bpf_prog_info){}",
		 {.name = {'\0', 'f', 'o', 'o'}});
	/* handle non-printable characters */
	TEST_BTF(btf, str, struct bpf_prog_info, 0,
		 "(struct bpf_prog_info){.name = (char[])[1,2,3,],}",
		 { .name = {1, 2, 3, 0}});

	/* struct with non-char array */
	TEST_BTF(btf, str, struct __sk_buff, 0,
		 "(struct __sk_buff){.cb = (__u32[])[1,2,3,4,5,],}",
		 { .cb = {1, 2, 3, 4, 5,},});
	TEST_BTF(btf, str, struct __sk_buff, BTF_F_NONAME,
		 "{[1,2,3,4,5,],}",
		 { .cb = { 1, 2, 3, 4, 5},});
	/* For non-char, arrays, show non-zero values only */
	TEST_BTF(btf, str, struct __sk_buff, 0,
		 "(struct __sk_buff){.cb = (__u32[])[1,],}",
		 { .cb = { 0, 0, 1, 0, 0},});

	/* struct with bitfields */
	TEST_BTF_C(btf, str, struct bpf_insn, 0,
		   {.code = (__u8)1,.dst_reg = (__u8)0x2,.src_reg = (__u8)0x3,.off = (__s16)4,.imm = (__s32)5,});
	TEST_BTF(btf, str, struct bpf_insn, BTF_F_NONAME, "{1,0x2,0x3,4,5,}",
		 {.code = 1, .dst_reg = 0x2, .src_reg = 0x3, .off = 4,
		  .imm = 5,});
}
