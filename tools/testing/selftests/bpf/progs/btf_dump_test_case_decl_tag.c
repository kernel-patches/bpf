// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * BTF-to-C dumper test for __atribute__((btf_decl_tag("..."))).
 */

#define SEC(x) __attribute__((section(x)))

/* ----- START-EXPECTED-OUTPUT ----- */
#if __has_attribute(btf_decl_tag)
#define __btf_decl_tag(x) __attribute__((btf_decl_tag(x)))
#else
#define __btf_decl_tag(x)
#endif

struct empty_with_tag {} __btf_decl_tag("a");

struct one_tag {
	int x;
} __btf_decl_tag("b");

struct same_tag {
	int x;
} __btf_decl_tag("b");

struct two_tags {
	int x;
} __btf_decl_tag("a") __btf_decl_tag("b");

struct packed {
	int x;
	short y;
} __attribute__((packed)) __btf_decl_tag("another_name");

typedef int td_with_tag __btf_decl_tag("td");

struct tags_on_fields {
	int x __btf_decl_tag("t1");
	int y;
	int z __btf_decl_tag("t2") __btf_decl_tag("t3");
};

struct tag_on_field_and_struct {
	int x __btf_decl_tag("t1");
} __btf_decl_tag("t2");

struct root_struct {
	struct empty_with_tag a;
	struct one_tag b;
	struct same_tag c;
	struct two_tags d;
	struct packed e;
	td_with_tag f;
	struct tags_on_fields g;
	struct tag_on_field_and_struct h;
};

SEC(".data") int global_var __btf_decl_tag("var_tag") = (int)777;

/* ------ END-EXPECTED-OUTPUT ------ */

int f(struct root_struct *s)
{
	return 0;
}
