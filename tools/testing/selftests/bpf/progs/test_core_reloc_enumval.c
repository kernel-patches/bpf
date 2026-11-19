// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook

#include <linux/bpf.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

struct {
	char in[256];
	char out[256];
	bool skip;
} data = {};

enum named_enum {
	NAMED_ENUM_VAL1 = 1,
	NAMED_ENUM_VAL2 = 2,
	NAMED_ENUM_VAL3 = 3,
};

typedef enum {
	ANON_ENUM_VAL1 = 0x10,
	ANON_ENUM_VAL2 = 0x20,
	ANON_ENUM_VAL3 = 0x30,
} anon_enum;

/* 4-byte enum with values out of the range of int, so it is unsigned */
enum named_uint_enum {
	UINT_ENUM_VAL1 = 0x80000000,
	UINT_ENUM_VAL2 = 0xfffffff0,
};

struct core_reloc_enumval_output {
	bool named_val1_exists;
	bool named_val2_exists;
	bool named_val3_exists;
	bool anon_val1_exists;
	bool anon_val2_exists;
	bool anon_val3_exists;

	int named_val1;
	int named_val2;
	int anon_val1;
	int anon_val2;
	long uint_val1;
	long uint_val2;
};

#ifdef __clang__
#define UINT_ENUM_VALUE(v) bpf_core_enum_value(enum named_uint_enum, v)
#else
/* GCC's __builtin_preserve_enum_value() returns int */
#define UINT_ENUM_VALUE(v) (unsigned int)bpf_core_enum_value(enum named_uint_enum, v)
#endif

SEC("raw_tracepoint/sys_enter")
int test_core_enumval(void *ctx)
{
#if __has_builtin(__builtin_preserve_enum_value)
	struct core_reloc_enumval_output *out = (void *)&data.out;
	enum named_enum named = 0;
	anon_enum anon = 0;

	out->named_val1_exists = bpf_core_enum_value_exists(named, NAMED_ENUM_VAL1);
	out->named_val2_exists = bpf_core_enum_value_exists(enum named_enum, NAMED_ENUM_VAL2);
	out->named_val3_exists = bpf_core_enum_value_exists(enum named_enum, NAMED_ENUM_VAL3);

	out->anon_val1_exists = bpf_core_enum_value_exists(anon, ANON_ENUM_VAL1);
	out->anon_val2_exists = bpf_core_enum_value_exists(anon_enum, ANON_ENUM_VAL2);
	out->anon_val3_exists = bpf_core_enum_value_exists(anon_enum, ANON_ENUM_VAL3);

	out->named_val1 = bpf_core_enum_value(named, NAMED_ENUM_VAL1);
	out->named_val2 = bpf_core_enum_value(named, NAMED_ENUM_VAL2);
	/* NAMED_ENUM_VAL3 value is optional */

	out->anon_val1 = bpf_core_enum_value(anon, ANON_ENUM_VAL1);
	out->anon_val2 = bpf_core_enum_value(anon, ANON_ENUM_VAL2);
	/* ANON_ENUM_VAL3 value is optional */

	/* enum named_uint_enum is optional */
	if (bpf_core_enum_value_exists(enum named_uint_enum, UINT_ENUM_VAL1))
		out->uint_val1 = UINT_ENUM_VALUE(UINT_ENUM_VAL1);
	if (bpf_core_enum_value_exists(enum named_uint_enum, UINT_ENUM_VAL2))
		out->uint_val2 = UINT_ENUM_VALUE(UINT_ENUM_VAL2);
#else
	data.skip = true;
#endif

	return 0;
}
