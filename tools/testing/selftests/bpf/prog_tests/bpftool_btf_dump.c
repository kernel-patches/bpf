// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpftool_helpers.h>
#include <bpf/btf.h>
#include <unistd.h>

#define DUMP_BUF_SZ	(16 * 1024)

static int btf_to_tmpfile(struct btf *btf, char *path, size_t path_sz)
{
	const void *raw;
	ssize_t written;
	__u32 sz;
	int fd;

	raw = btf__raw_data(btf, &sz);
	if (!ASSERT_OK_PTR(raw, "raw_data"))
		return -1;

	snprintf(path, path_sz, "/tmp/bpftool_btf_dump.XXXXXX");
	fd = mkstemp(path);
	if (!ASSERT_OK_FD(fd, "mkstemp"))
		return -1;

	written = write(fd, raw, sz);
	close(fd);
	if (!ASSERT_EQ(written, sz, "write_btf")) {
		unlink(path);
		return -1;
	}
	return 0;
}

static char *dump_c(const char *path, bool sorted)
{
	char args[MAX_BPFTOOL_CMD_LEN];
	char *buf;
	int err;

	buf = malloc(DUMP_BUF_SZ);
	if (!ASSERT_OK_PTR(buf, "alloc"))
		return NULL;

	snprintf(args, sizeof(args), "btf dump file %s format c%s",
		 path, sorted ? "" : " unsorted");
	err = get_bpftool_command_output(args, buf, DUMP_BUF_SZ);
	if (!ASSERT_OK(err, "dump")) {
		free(buf);
		return NULL;
	}
	return buf;
}

/*
 * struct holey { int c; <32 bit hole> int tail; };
 * enum { E0 = 1 }; enum { E1 = 2 }; enum { E2 = 3 };
 * struct s { int f; };
 * union u { int f; };
 *
 * One record with a hole, and a 4-byte long to pad it with. How records
 * themselves are rendered is already covered by the build.
 * The anonymous enums matter to the sorting subtest.
 */
static struct btf *mk_btf(void)
{
	struct btf *btf;
	int id, err, i;

	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "new_empty"))
		return NULL;

	id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (!ASSERT_EQ(id, 1, "int"))
		goto err_out;

	id = btf__add_int(btf, "long int", 4, BTF_INT_SIGNED);
	if (!ASSERT_GT(id, 0, "long"))
		goto err_out;

	id = btf__add_struct(btf, "holey", 16);
	if (!ASSERT_GT(id, 0, "struct_holey"))
		goto err_out;

	err = btf__add_field(btf, "c", 1, 0, 0);
	if (!ASSERT_OK(err, "holey_c"))
		goto err_out;

	err = btf__add_field(btf, "tail", 1, 96, 0);
	if (!ASSERT_OK(err, "holey_tail"))
		goto err_out;

	for (i = 0; i < 3; i++) {
		char name[16];

		snprintf(name, sizeof(name), "E%d", i);

		id = btf__add_enum(btf, NULL, 4);
		if (!ASSERT_GT(id, 0, "anon_enum"))
			goto err_out;

		err = btf__add_enum_value(btf, name, i + 1);
		if (!ASSERT_OK(err, "enum_val"))
			goto err_out;
	}

	id = btf__add_struct(btf, "s", 4);
	if (!ASSERT_GT(id, 0, "struct_s"))
		goto err_out;

	err = btf__add_field(btf, "f", 1, 0, 0);
	if (!ASSERT_OK(err, "s_field"))
		goto err_out;

	id = btf__add_union(btf, "u", 4);
	if (!ASSERT_GT(id, 0, "union_u"))
		goto err_out;

	err = btf__add_field(btf, "f", 1, 0, 0);
	if (!ASSERT_OK(err, "u_field"))
		goto err_out;

	btf__set_pointer_size(btf, 4);

	return btf;
err_out:
	btf__free(btf);
	return NULL;
}

static int count_substr(const char *haystack, const char *needle)
{
	const char *p = haystack;
	int n = 0;

	for (; (p = strstr(p, needle)); p++)
		n++;

	return n;
}

static void test_sort_preserves_types(const char *path)
{
	char *sorted = NULL, *unsorted = NULL;
	int n_sorted, n_unsorted;

	sorted = dump_c(path, true);
	unsorted = dump_c(path, false);
	if (!sorted || !unsorted)
		goto out;

	/*
	 * Count definitions by the closing brace in their first column. Counting
	 * "struct"/"union"/"enum" openers instead would also count forward
	 * declarations, and which types need one depends on emission order.
	 */
	n_unsorted = count_substr(unsorted, "\n}");
	n_sorted = count_substr(sorted, "\n}");
	ASSERT_GT(n_unsorted, 0, "types_emitted");
	ASSERT_EQ(n_sorted, n_unsorted, "same_type_count");

out:
	free(sorted);
	free(unsorted);
}

/*
 * Check only what the selftests build cannot:
 *   - bpf_helpers.h defines __ksym and __weak as well, and no program uses
 *     __bpf_fastcall, so losing the macro block changes nothing;
 *   - building without the preserve_access_index pragma is a supported mode
 *     (BPF_NO_PRESERVE_ACCESS_INDEX), so losing it only costs CO-RE;
 *   - the padding width comes from the BTF's pointer size, and a native build
 *     never runs the host bpftool over a differently sized target's BTF.
 */
static void test_dump(const char *path, bool sorted)
{
	char *buf;

	buf = dump_c(path, sorted);
	if (!buf)
		return;

	ASSERT_HAS_SUBSTR(buf, "#define __ksym __attribute__((section(\".ksyms\")))",
			  "ksym");
	ASSERT_HAS_SUBSTR(buf, "#define __weak __attribute__((weak))", "weak");
	ASSERT_HAS_SUBSTR(buf, "#define __bpf_fastcall __attribute__((bpf_fastcall))",
			  "bpf_fastcall");

	ASSERT_HAS_SUBSTR(buf, "#ifndef BPF_NO_PRESERVE_ACCESS_INDEX", "pai_guard");
	ASSERT_HAS_SUBSTR(buf,
			  "#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)",
			  "pai_push");
	ASSERT_HAS_SUBSTR(buf, "#pragma clang attribute pop", "pai_pop");

	ASSERT_HAS_SUBSTR(buf, "long: 32;", "target_ptr_size");

	free(buf);
}

void test_bpftool_btf_dump(void)
{
	char path[PATH_MAX];
	struct btf *btf;

	btf = mk_btf();
	if (!btf)
		return;
	if (btf_to_tmpfile(btf, path, sizeof(path)))
		goto out;

	if (test__start_subtest("c_sorted"))
		test_dump(path, true);
	if (test__start_subtest("c_unsorted"))
		test_dump(path, false);

	if (test__start_subtest("c_sort_preserves_types"))
		test_sort_preserves_types(path);

	unlink(path);
out:
	btf__free(btf);
}
