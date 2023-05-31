// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <test_progs.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

/* verify kind encoding exists for each kind */
void test_btf_kind_encoding(struct btf *btf, char *description)
{
	const struct btf_header *hdr;
	const struct btf_metadata *meta;
	const void *raw_btf;
	__u32 raw_size;
	__u16 i;

	raw_btf = btf__raw_data(btf, &raw_size);
	if (!ASSERT_OK_PTR(raw_btf, "btf__raw_data"))
		return;

	hdr = raw_btf;
	meta = raw_btf + hdr->hdr_len + hdr->meta_header.meta_off;

	if (!ASSERT_EQ(meta->kind_meta_cnt, NR_BTF_KINDS, "unexpected kind_meta_cnt"))
		return;

	if (!ASSERT_EQ(strcmp(description, btf__name_by_offset(btf, meta->description_off)),
		       0, "check meta description"))
		return;

	for (i = 0; i <= BTF_KIND_MAX; i++) {
		const struct btf_kind_meta *k = &meta->kind_meta[i];

		if (ASSERT_OK_PTR(btf__name_by_offset(btf, k->name_off), "kind_name_valid"))
			return;
	}
}

/* fabricate an unrecognized kind at BTF_KIND_MAX + 1, and after adding
 * the appropriate struct/typedefs to the BTF such that it recognizes
 * this kind, ensure that parsing of BTF containing the unrecognized kind
 * can succeed.
 */
void test_btf_kind_decoding(struct btf *btf)
{
	__s32 int_id, unrec_id, id;
	struct btf_type *t;
	char btf_path[64];
	const void *raw_btf;
	void *new_raw_btf;
	struct btf *new_btf;
	struct btf_header *hdr;
	struct btf_metadata *meta;
	struct btf_kind_meta *k;
	__u32 raw_size;
	int fd;

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

	raw_btf = (void *)btf__raw_data(btf, &raw_size);
	if (!ASSERT_OK_PTR(raw_btf, "btf__raw_data"))
		return;

	new_raw_btf = calloc(1, raw_size + sizeof(*k));
	memcpy(new_raw_btf, raw_btf, raw_size);

	/* add new metadata description */
	hdr = new_raw_btf;
	hdr->meta_header.meta_len += sizeof(*k);
	meta = new_raw_btf + hdr->hdr_len + hdr->meta_header.meta_off;
	meta->kind_meta_cnt += 1;
	/* we will call our kinds UNKN, re-using the string offsets from BTF_KIND_UNKN */
	k = &meta->kind_meta[NR_BTF_KINDS];
	k->name_off = meta->kind_meta[0].name_off + strlen("BTF_KIND_");
	k->flags = BTF_KIND_META_OPTIONAL;
	k->info_sz = 0;
	k->elem_sz = 0;

	/* now modify our typedef added above to be an unrecognized kind. */
	t = (void *)hdr + hdr->hdr_len + hdr->type_off + sizeof(struct btf_type) +
		sizeof(__u32);
	t->info = (NR_BTF_KINDS << 24);

	/* now write our BTF to a raw file, ready for parsing. */
	snprintf(btf_path, sizeof(btf_path), "/tmp/btf_kind.%d", getpid());
	fd = open(btf_path, O_WRONLY | O_CREAT);
	write(fd, new_raw_btf, raw_size + sizeof(*k));
	close(fd);

	/* verify parsing succeeds, and that we can read type info past
	 * the unrecognized kind.
	 */
	new_btf = btf__parse_raw(btf_path);
	if (ASSERT_OK_PTR(new_btf, "btf__parse_raw")) {
		ASSERT_EQ(btf__find_by_name_kind(new_btf, "test_lookup",
						 BTF_KIND_TYPEDEF), id,
			  "verify_id_lookup");
		/* verify the kernel can handle unrecognized kinds. */
		ASSERT_EQ(btf__load_into_kernel(new_btf), 0, "btf_load_into_kernel");
	}
	unlink(btf_path);
}

void test_btf_kind(void)
{
	LIBBPF_OPTS(btf_new_opts, opts);
	char *description = "testing metadata!";

	opts.add_meta = true;
	opts.description = description;

	struct btf *btf = btf__new_empty_opts(&opts);

	if (!ASSERT_OK_PTR(btf, "btf_new"))
		return;

	if (test__start_subtest("btf_kind_encoding"))
		test_btf_kind_encoding(btf, description);
	if (test__start_subtest("btf_kind_decoding"))
		test_btf_kind_decoding(btf);
	btf__free(btf);
}
