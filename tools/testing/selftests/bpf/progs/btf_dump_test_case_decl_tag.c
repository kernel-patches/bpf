// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * BTF-to-C dumper test for __atribute__((btf_decl_tag("..."))).
 */
/* ----- START-EXPECTED-OUTPUT ----- */
struct empty_with_tag {} __attribute__((btf_decl_tag("a")));

struct one_tag {
	int x;
} __attribute__((btf_decl_tag("b")));

struct same_tag {
	int x;
} __attribute__((btf_decl_tag("b")));

struct two_tags {
	int x;
} __attribute__((btf_decl_tag("a"))) __attribute__((btf_decl_tag("b")));

struct packed {
	int x;
	short y;
} __attribute__((packed)) __attribute__((btf_decl_tag("another_name")));

struct root_struct {
	struct empty_with_tag a;
	struct one_tag b;
	struct same_tag c;
	struct two_tags d;
	struct packed e;
};

/* ------ END-EXPECTED-OUTPUT ------ */

int f(struct root_struct *s)
{
	return 0;
}
