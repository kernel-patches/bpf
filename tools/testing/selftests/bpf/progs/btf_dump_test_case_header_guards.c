// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * BTF-to-C dumper test for header guards.
 */
struct hg_struct {
	int x;
} __attribute__((btf_decl_tag("header_guard:S")));

union hg_union {
	int x;
} __attribute__((btf_decl_tag("header_guard:U")));

typedef int hg_typedef __attribute__((btf_decl_tag("header_guard:T")));

struct hg_fwd_a;

struct hg_fwd_b {
	struct hg_fwd_a *loop;
} __attribute__((btf_decl_tag("header_guard:FWD")));

struct hg_fwd_a {
	struct hg_fwd_b *loop;
} __attribute__((btf_decl_tag("header_guard:FWD")));

struct root_struct {
	struct hg_struct a;
	union hg_union b;
	hg_typedef c;
	struct hg_fwd_a d;
	struct hg_fwd_b e;
};

/* ----- START-EXPECTED-OUTPUT ----- */
/*
 *#ifndef S
 *
 *struct hg_struct {
 *	int x;
 *};
 *
 *#endif
 *
 *#ifndef U
 *
 *union hg_union {
 *	int x;
 *};
 *
 *#endif
 *
 *#ifndef T
 *
 *typedef int hg_typedef;
 *
 *#endif
 *
 *#ifndef FWD
 *
 *struct hg_fwd_b;
 *
 *#endif
 *
 *#ifndef FWD
 *
 *struct hg_fwd_a {
 *	struct hg_fwd_b *loop;
 *};
 *
 *#endif
 *
 *#ifndef FWD
 *
 *struct hg_fwd_b {
 *	struct hg_fwd_a *loop;
 *};
 *
 *#endif
 *
 *struct root_struct {
 *	struct hg_struct a;
 *	union hg_union b;
 *	hg_typedef c;
 *	struct hg_fwd_a d;
 *	struct hg_fwd_b e;
 *};
 *
 */
/* ------ END-EXPECTED-OUTPUT ------ */

int f(struct root_struct *s)
{
	return 0;
}
