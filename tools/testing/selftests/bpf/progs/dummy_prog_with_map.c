// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#if __has_attribute(btf_decl_tag)
#define __decl_tag_bpf_ctx __attribute__((btf_decl_tag(("preserve_static_offset"))))
#endif

struct test_struct_a {
	int v;
} __decl_tag_bpf_ctx;

struct test_struct_b {
	int v;
} __decl_tag_bpf_ctx;

struct test_struct_c {
	int v;
} __decl_tag_bpf_ctx;

struct test_struct_d {
	int v;
} __decl_tag_bpf_ctx;

struct test_struct_e {
	int v;
} __decl_tag_bpf_ctx;

struct test_struct_f {
	int v;
	struct pt_regs *r;
} __decl_tag_bpf_ctx;

struct test_struct_h {
	struct pt_regs r;
};

typedef struct test_struct_c test_struct_c_td;

struct map_value {
	struct test_struct_a a;
	struct test_struct_b b[2];
	test_struct_c_td c;
	const struct test_struct_d *(*d)(volatile struct test_struct_e *);
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, struct map_value);
} test_map1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, struct test_struct_f);
} test_map2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, int);
	__type(value, struct test_struct_h);
} test_map3 SEC(".maps");

/* A dummy program that references map 'test_map', used by test_bpftool.py */
SEC("tc")
int dummy_prog_with_map(void *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
