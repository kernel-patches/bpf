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

enum named_enum64 {
	NAMED_ENUM64_VAL1 = 0x1ffffffffULL,
	NAMED_ENUM64_VAL2 = 0x2ffffffffULL,
	NAMED_ENUM64_VAL3 = 0x3ffffffffULL,
};

struct core_reloc_enum64val_output {
	bool named_val1_exists;
	bool named_val2_exists;
	bool named_val3_exists;

	long named_val1;
	long named_val2;
};

SEC("raw_tracepoint/sys_enter")
int test_core_enum64val(void *ctx)
{
#if __has_builtin(__builtin_preserve_enum_value)
	struct core_reloc_enum64val_output *out = (void *)&data.out;
	enum named_enum64 named = 0;

	out->named_val1_exists = bpf_core_enum_value_exists(named, NAMED_ENUM64_VAL1);
	out->named_val2_exists = bpf_core_enum_value_exists(enum named_enum64, NAMED_ENUM64_VAL2);
	out->named_val3_exists = bpf_core_enum_value_exists(enum named_enum64, NAMED_ENUM64_VAL3);

	out->named_val1 = bpf_core_enum_value(named, NAMED_ENUM64_VAL1);
	out->named_val2 = bpf_core_enum_value(named, NAMED_ENUM64_VAL2);
	/* NAMED_ENUM64_VAL3 value is optional */

#else
	data.skip = true;
#endif

	return 0;
}
