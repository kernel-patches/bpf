// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <string.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
#include <linux/kernel.h>
#define CONFIG_DEBUG_INFO_BTF
#include <linux/btf_ids.h>
#include "test_progs.h"

#ifndef KF_FASTCALL
#define KF_FASTCALL (1 << 12)
#endif

struct symbol {
	const char	*name;
	int		 type;
	int		 id;
};

struct symbol test_symbols[] = {
	{ "unused",  BTF_KIND_UNKN,     0 },
	{ "S",       BTF_KIND_TYPEDEF, -1 },
	{ "T",       BTF_KIND_TYPEDEF, -1 },
	{ "U",       BTF_KIND_TYPEDEF, -1 },
	{ "S",       BTF_KIND_STRUCT,  -1 },
	{ "U",       BTF_KIND_UNION,   -1 },
	{ "func",    BTF_KIND_FUNC,    -1 },
};

struct kfunc_symbol {
	const char	*name;
	s32		 id;
	u32		 flags;
};

static struct kfunc_symbol kfunc_symbols[] = {
	{ "kfunc_a", -1, 0 },
	{ "kfunc_b", -1, KF_FASTCALL },
};

/* Align the .BTF_ids section to 4 bytes */
asm (
".pushsection " BTF_IDS_SECTION " ,\"a\"; \n"
".balign 4, 0;                            \n"
".popsection;                             \n");

/*
 * The BTF ID arrays below are .local symbols placed in .BTF_ids by
 * inline asm, and are read here directly by C name. To the compiler
 * they are plain, default-visibility extern objects.
 *
 * When test_progs is linked as a position-independent executable (PIE),
 * taking the address of such an extern is routed through the GOT. The
 * GNU assembler on aarch64 unconditionally converts references to
 * .local symbols into section + addend form (".BTF_ids + <offset>"),
 * but a GOT slot cannot carry an addend (the AArch64 ELF spec mandates
 * zero), so the linker resolves it to the .BTF_ids base.
 *
 * Mark these symbols hidden so the compiler treats them as
 * non-interposable and emits a direct, addend-preserving PC-relative
 * access instead of a GOT load, in both PIE and non-PIE builds.
 */
#pragma GCC visibility push(hidden)
BTF_ID_LIST(test_list_local)
BTF_ID_UNUSED
BTF_ID(typedef, S)
BTF_ID(typedef, T)
BTF_ID(typedef, U)
BTF_ID(struct,  S)
BTF_ID(union,   U)
BTF_ID(func,    func)

extern __u32 test_list_global[];
BTF_ID_LIST_GLOBAL(test_list_global, 1)
BTF_ID_UNUSED
BTF_ID(typedef, S)
BTF_ID(typedef, T)
BTF_ID(typedef, U)
BTF_ID(struct,  S)
BTF_ID(union,   U)
BTF_ID(func,    func)

BTF_SET_START(test_set)
BTF_ID(typedef, S)
BTF_ID(typedef, T)
BTF_ID(typedef, U)
BTF_ID(struct,  S)
BTF_ID(union,   U)
BTF_ID(func,    func)
BTF_SET_END(test_set)

BTF_KFUNCS_START(test_kfunc_set)
BTF_ID_FLAGS(func, kfunc_a)
BTF_ID_FLAGS(func, kfunc_b, KF_FASTCALL)
BTF_KFUNCS_END(test_kfunc_set)

#pragma GCC visibility pop

static int
__resolve_symbol(struct btf *btf, int type_id)
{
	const struct btf_type *type;
	const char *str;
	unsigned int i;

	type = btf__type_by_id(btf, type_id);
	if (!type) {
		PRINT_FAIL("Failed to get type for ID %d\n", type_id);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(test_symbols); i++) {
		if (test_symbols[i].id >= 0)
			continue;

		if (BTF_INFO_KIND(type->info) != test_symbols[i].type)
			continue;

		str = btf__name_by_offset(btf, type->name_off);
		if (!str) {
			PRINT_FAIL("Failed to get name for BTF ID %d\n", type_id);
			return -1;
		}

		if (!strcmp(str, test_symbols[i].name))
			test_symbols[i].id = type_id;
	}

	if (BTF_INFO_KIND(type->info) == BTF_KIND_FUNC) {
		str = btf__name_by_offset(btf, type->name_off);
		if (str) {
			for (i = 0; i < ARRAY_SIZE(kfunc_symbols); i++) {
				if (kfunc_symbols[i].id >= 0)
					continue;
				if (!strcmp(str, kfunc_symbols[i].name))
					kfunc_symbols[i].id = type_id;
			}
		}
	}

	return 0;
}

static int resolve_symbols(struct btf *btf)
{
	__u32 nr = btf__type_cnt(btf);
	int type_id;

	for (type_id = 1; type_id < nr; type_id++) {
		if (__resolve_symbol(btf, type_id))
			return -1;
	}
	return 0;
}

static bool btf_has_decl_tag(struct btf *btf, const char *tag_name, s32 target_id)
{
	const struct btf_type *t;
	const char *name;
	int nr, id;

	nr = btf__type_cnt(btf);
	for (id = 1; id < nr; id++) {
		t = btf__type_by_id(btf, id);
		if (!btf_is_decl_tag(t))
			continue;
		if (t->type != (__u32)target_id)
			continue;
		if (btf_decl_tag(t)->component_idx != -1)
			continue;
		name = btf__name_by_offset(btf, t->name_off);
		if (name && strcmp(name, tag_name) == 0)
			return true;
	}
	return false;
}

void test_resolve_btfids(void)
{
	__u32 *test_list, *test_lists[] = { test_list_local, test_list_global };
	unsigned int i, j;
	struct btf *btf;

	btf = btf__parse_raw("resolve_btfids.test.o.BTF");
	if (!ASSERT_OK_PTR(btf, "btf_parse"))
		goto out;

	if (resolve_symbols(btf))
		goto out;

	/* Check BTF_ID_LIST(test_list_local) and
	 * BTF_ID_LIST_GLOBAL(test_list_global) IDs
	 */
	for (j = 0; j < ARRAY_SIZE(test_lists); j++) {
		test_list = test_lists[j];
		for (i = 0; i < ARRAY_SIZE(test_symbols); i++)
			ASSERT_EQ(test_list[i], test_symbols[i].id, test_symbols[i].name);
	}

	/* Check BTF_SET_START(test_set) IDs */
	for (i = 0; i < test_set.cnt; i++) {
		bool found = false;

		for (j = 0; j < ARRAY_SIZE(test_symbols); j++) {
			if (test_symbols[j].id != test_set.ids[i])
				continue;
			found = true;
			break;
		}

		ASSERT_TRUE(found, "id_in_test_symbols");

		if (i > 0)
			ASSERT_LE(test_set.ids[i - 1], test_set.ids[i], "sort_check");
	}

	/* Check BTF_KFUNCS_START(test_kfunc_set) */
	ASSERT_EQ(test_kfunc_set.flags, BTF_SET8_KFUNCS, "kfunc_set_flags");
	ASSERT_EQ(test_kfunc_set.cnt, ARRAY_SIZE(kfunc_symbols), "kfunc_set_cnt");

	for (i = 0; i < test_kfunc_set.cnt; i++) {
		bool found = false;

		for (j = 0; j < ARRAY_SIZE(kfunc_symbols); j++) {
			if (kfunc_symbols[j].id != (s32)test_kfunc_set.pairs[i].id)
				continue;
			found = true;
			ASSERT_EQ(test_kfunc_set.pairs[i].flags,
				  kfunc_symbols[j].flags, "kfunc_flags_check");
			break;
		}

		ASSERT_TRUE(found, "kfunc_id_found");

		if (i > 0)
			ASSERT_LE(test_kfunc_set.pairs[i - 1].id,
				  test_kfunc_set.pairs[i].id, "kfunc_sort_check");
	}

	/* Check resolve_btfids emitted bpf_kfunc decl_tag for each kfunc */
	for (i = 0; i < ARRAY_SIZE(kfunc_symbols); i++)
		ASSERT_TRUE(btf_has_decl_tag(btf, "bpf_kfunc",
					     kfunc_symbols[i].id),
			    kfunc_symbols[i].name);

out:
	btf__free(btf);
}
