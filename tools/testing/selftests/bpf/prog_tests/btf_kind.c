// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <test_progs.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

/* verify kind encoding exists for each kind */
static void test_btf_kind_encoding(void)
{
	LIBBPF_OPTS(btf_new_opts, opts);
	const struct btf_header *hdr;
	const void *raw_btf;
	struct btf *btf;
	__u32 raw_size;

	opts.add_kind_layout = true;
	btf = btf__new_empty_opts(&opts);
	if (!ASSERT_OK_PTR(btf, "btf_new"))
		return;

	raw_btf = btf__raw_data(btf, &raw_size);
	if (!ASSERT_OK_PTR(raw_btf, "btf__raw_data"))
		return;

	hdr = raw_btf;

	ASSERT_EQ(hdr->kind_layout_off % 4, 0, "kind_layout aligned");
	ASSERT_EQ(hdr->kind_layout_len, sizeof(struct btf_kind_layout) * NR_BTF_KINDS,
		  "kind_layout_len");
	btf__free(btf);
}

static void write_raw_btf(const char *btf_path, void *raw_btf, size_t raw_size)
{
	int fd = open(btf_path, O_WRONLY | O_CREAT);

	write(fd, raw_btf, raw_size);
	close(fd);
}

/* fabricate an unrecognized kind at BTF_KIND_MAX + 1, and after adding
 * the appropriate struct/typedefs to the BTF such that it recognizes
 * this kind, ensure that parsing of BTF containing the unrecognized kind
 * can succeed.
 */
void test_btf_kind_decoding(void)
{
	__s32 int_id, unrec_id, id, id2;
	LIBBPF_OPTS(btf_new_opts, opts);
	struct btf *btf, *new_btf;
	struct btf_kind_layout *k;
	struct btf_header *hdr;
	const void *raw_btf;
	struct btf_type *t;
	char btf_path[64];
	void *new_raw_btf;
	__u32 raw_size;

	opts.add_kind_layout = true;
	btf = btf__new_empty_opts(&opts);
	if (!ASSERT_OK_PTR(btf, "btf_new"))
		return;

	int_id = btf__add_int(btf, "test_char", 1, BTF_INT_CHAR);
	if (!ASSERT_GT(int_id, 0, "add_int_id"))
		return;

	/* now create our type with unrecognized kind by adding a typedef kind
	 * we will overwrite it with our unrecognized kind value.
	 */
	unrec_id = btf__add_typedef(btf, "unrec_kind", int_id);
	if (!ASSERT_GT(unrec_id, 0, "add_unrec_id"))
		return;

	/* add an id after it that we will look up to verify we can parse
	 * beyond unrecognized kinds.
	 */
	id = btf__add_typedef(btf, "test_lookup", int_id);
	if (!ASSERT_GT(id, 0, "add_test_lookup_id"))
		return;
	id2 = btf__add_typedef(btf, "test_lookup2", int_id);
	if (!ASSERT_GT(id2, 0, "add_test_lookup_id2"))
		return;

	raw_btf = (void *)btf__raw_data(btf, &raw_size);
	if (!ASSERT_OK_PTR(raw_btf, "btf__raw_data"))
		return;

	new_raw_btf = calloc(1, raw_size + sizeof(*k));
	memcpy(new_raw_btf, raw_btf, raw_size);

	/* add new layout description */
	hdr = new_raw_btf;
	hdr->kind_layout_len += sizeof(*k);
	k = new_raw_btf + hdr->hdr_len + hdr->kind_layout_off;
	k[NR_BTF_KINDS].info_sz = 0;
	k[NR_BTF_KINDS].elem_sz = 0;

	/* now modify our typedef added above to be an unrecognized kind. */
	t = (void *)hdr + hdr->hdr_len + hdr->type_off + sizeof(struct btf_type) +
		sizeof(__u32);
	t->info = (NR_BTF_KINDS << 24);

	/* now write our BTF to a raw file, ready for parsing. */
	snprintf(btf_path, sizeof(btf_path), "/tmp/btf_kind.%d", getpid());

	write_raw_btf(btf_path, new_raw_btf, raw_size + sizeof(*k));

	/* verify parsing succeeds, and that we can read type info past
	 * the unrecognized kind.
	 */
	new_btf = btf__parse_raw(btf_path);
	if (ASSERT_OK_PTR(new_btf, "btf__parse_raw")) {
		ASSERT_EQ(btf__find_by_name_kind(new_btf, "test_lookup",
						 BTF_KIND_TYPEDEF), id,
			  "verify_id_lookup");
		ASSERT_EQ(btf__find_by_name_kind(new_btf, "test_lookup2",
						 BTF_KIND_TYPEDEF), id2,
			  "verify_id2_lookup");
	}
	btf__free(new_btf);

	/* next, change info_sz to equal sizeof(struct btf_type); this means the
	 * "test_lookup" kind will be reinterpreted as a singular info element
	 * following the unrecognized kind.
	 */
	k[NR_BTF_KINDS].info_sz = sizeof(struct btf_type);
	write_raw_btf(btf_path, new_raw_btf, raw_size + sizeof(*k));

	new_btf = btf__parse_raw(btf_path);
	if (ASSERT_OK_PTR(new_btf, "btf__parse_raw")) {
		ASSERT_EQ(btf__find_by_name_kind(new_btf, "test_lookup",
						 BTF_KIND_TYPEDEF), -ENOENT,
			  "verify_id_not_found");
		/* id of "test_lookup2" will be id2 -1 as we have removed one type */
		ASSERT_EQ(btf__find_by_name_kind(new_btf, "test_lookup2",
						 BTF_KIND_TYPEDEF), id2 - 1,
			  "verify_id_lookup2");

	}
	btf__free(new_btf);

	/* next, change elem_sz to equal sizeof(struct btf_type)/2 and set
	 * vlen associated with unrecognized type to 2; this allows us to verify
	 * vlen-specified BTF can still be parsed.
	 */
	k[NR_BTF_KINDS].info_sz = 0;
	k[NR_BTF_KINDS].elem_sz = sizeof(struct btf_type)/2;
	t->info |= 2;
	write_raw_btf(btf_path, new_raw_btf, raw_size + sizeof(*k));

	new_btf = btf__parse_raw(btf_path);
	if (ASSERT_OK_PTR(new_btf, "btf__parse_raw")) {
		ASSERT_EQ(btf__find_by_name_kind(new_btf, "test_lookup",
						 BTF_KIND_TYPEDEF), -ENOENT,
			  "verify_id_not_found");
		/* id of "test_lookup2" will be id2 -1 as we have removed one type */
		ASSERT_EQ(btf__find_by_name_kind(new_btf, "test_lookup2",
						 BTF_KIND_TYPEDEF), id2 - 1,
			  "verify_id_lookup2");

	}
	btf__free(new_btf);
	free(new_raw_btf);
	unlink(btf_path);
	btf__free(btf);
}

void test_btf_kind(void)
{
	if (test__start_subtest("btf_kind_encoding"))
		test_btf_kind_encoding();
	if (test__start_subtest("btf_kind_decoding"))
		test_btf_kind_decoding();
}
