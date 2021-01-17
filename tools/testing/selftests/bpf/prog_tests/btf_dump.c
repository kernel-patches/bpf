// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>

static int duration = 0;

void btf_dump_printf(void *ctx, const char *fmt, va_list args)
{
	vfprintf(ctx, fmt, args);
}

static struct btf_dump_test_case {
	const char *name;
	const char *file;
	bool known_ptr_sz;
	struct btf_dump_opts opts;
} btf_dump_test_cases[] = {
	{"btf_dump: syntax", "btf_dump_test_case_syntax", true, {}},
	{"btf_dump: ordering", "btf_dump_test_case_ordering", false, {}},
	{"btf_dump: padding", "btf_dump_test_case_padding", true, {}},
	{"btf_dump: packing", "btf_dump_test_case_packing", true, {}},
	{"btf_dump: bitfields", "btf_dump_test_case_bitfields", true, {}},
	{"btf_dump: multidim", "btf_dump_test_case_multidim", false, {}},
	{"btf_dump: namespacing", "btf_dump_test_case_namespacing", false, {}},
};

static int btf_dump_all_types(const struct btf *btf,
			      const struct btf_dump_opts *opts)
{
	size_t type_cnt = btf__get_nr_types(btf);
	struct btf_dump *d;
	int err = 0, id;

	d = btf_dump__new(btf, NULL, opts, btf_dump_printf);
	if (IS_ERR(d))
		return PTR_ERR(d);

	for (id = 1; id <= type_cnt; id++) {
		err = btf_dump__dump_type(d, id);
		if (err)
			goto done;
	}

done:
	btf_dump__free(d);
	return err;
}

static int test_btf_dump_case(int n, struct btf_dump_test_case *t)
{
	char test_file[256], out_file[256], diff_cmd[1024];
	struct btf *btf = NULL;
	int err = 0, fd = -1;
	FILE *f = NULL;

	snprintf(test_file, sizeof(test_file), "%s.o", t->file);

	btf = btf__parse_elf(test_file, NULL);
	if (CHECK(IS_ERR(btf), "btf_parse_elf",
	    "failed to load test BTF: %ld\n", PTR_ERR(btf))) {
		err = -PTR_ERR(btf);
		btf = NULL;
		goto done;
	}

	/* tests with t->known_ptr_sz have no "long" or "unsigned long" type,
	 * so it's impossible to determine correct pointer size; but if they
	 * do, it should be 8 regardless of host architecture, becaues BPF
	 * target is always 64-bit
	 */
	if (!t->known_ptr_sz) {
		btf__set_pointer_size(btf, 8);
	} else {
		CHECK(btf__pointer_size(btf) != 8, "ptr_sz", "exp %d, got %zu\n",
		      8, btf__pointer_size(btf));
	}

	snprintf(out_file, sizeof(out_file), "/tmp/%s.output.XXXXXX", t->file);
	fd = mkstemp(out_file);
	if (CHECK(fd < 0, "create_tmp", "failed to create file: %d\n", fd)) {
		err = fd;
		goto done;
	}
	f = fdopen(fd, "w");
	if (CHECK(f == NULL, "open_tmp",  "failed to open file: %s(%d)\n",
		  strerror(errno), errno)) {
		close(fd);
		goto done;
	}

	t->opts.ctx = f;
	err = btf_dump_all_types(btf, &t->opts);
	fclose(f);
	close(fd);
	if (CHECK(err, "btf_dump", "failure during C dumping: %d\n", err)) {
		goto done;
	}

	snprintf(test_file, sizeof(test_file), "progs/%s.c", t->file);
	if (access(test_file, R_OK) == -1)
		/*
		 * When the test is run with O=, kselftest copies TEST_FILES
		 * without preserving the directory structure.
		 */
		snprintf(test_file, sizeof(test_file), "%s.c", t->file);
	/*
	 * Diff test output and expected test output, contained between
	 * START-EXPECTED-OUTPUT and END-EXPECTED-OUTPUT lines in test case.
	 * For expected output lines, everything before '*' is stripped out.
	 * Also lines containing comment start and comment end markers are
	 * ignored. 
	 */
	snprintf(diff_cmd, sizeof(diff_cmd),
		 "awk '/START-EXPECTED-OUTPUT/{out=1;next} "
		 "/END-EXPECTED-OUTPUT/{out=0} "
		 "/\\/\\*|\\*\\//{next} " /* ignore comment start/end lines */
		 "out {sub(/^[ \\t]*\\*/, \"\"); print}' '%s' | diff -u - '%s'",
		 test_file, out_file);
	err = system(diff_cmd);
	if (CHECK(err, "diff",
		  "differing test output, output=%s, err=%d, diff cmd:\n%s\n",
		  out_file, err, diff_cmd))
		goto done;

	remove(out_file);

done:
	btf__free(btf);
	return err;
}

static char *dump_buf;
static size_t dump_buf_sz;
static FILE *dump_buf_file;

void test_btf_dump_incremental(void)
{
	struct btf *btf = NULL;
	struct btf_dump *d = NULL;
	struct btf_dump_opts opts;
	int id, err, i;

	dump_buf_file = open_memstream(&dump_buf, &dump_buf_sz);
	if (!ASSERT_OK_PTR(dump_buf_file, "dump_memstream"))
		return;
	btf = btf__new_empty();
	if (!ASSERT_OK_PTR(btf, "new_empty"))
		goto err_out;
	opts.ctx = dump_buf_file;
	d = btf_dump__new(btf, NULL, &opts, btf_dump_printf);
	if (!ASSERT_OK(libbpf_get_error(d), "btf_dump__new"))
		goto err_out;

	/* First, generate BTF corresponding to the following C code:
	 *
	 * enum { VAL = 1 };
	 *
	 * struct s { int x; };
	 *
	 */
	id = btf__add_enum(btf, NULL, 4);
	ASSERT_EQ(id, 1, "enum_id");
	err = btf__add_enum_value(btf, "VAL", 1);
	ASSERT_OK(err, "enum_val_ok");

	id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	ASSERT_EQ(id, 2, "int_id");

	id = btf__add_struct(btf, "s", 4);
	ASSERT_EQ(id, 3, "struct_id");
	err = btf__add_field(btf, "x", 2, 0, 0);
	ASSERT_OK(err, "field_ok");

	for (i = 1; i <= btf__get_nr_types(btf); i++) {
		err = btf_dump__dump_type(d, i);
		ASSERT_OK(err, "dump_type_ok");
	}

	fflush(dump_buf_file);
	dump_buf[dump_buf_sz] = 0; /* some libc implementations don't do this */
	ASSERT_STREQ(dump_buf,
"enum {\n"
"	VAL = 1,\n"
"};\n"
"\n"
"struct s {\n"
"	int x;\n"
"};\n\n", "c_dump1");

	/* Now, after dumping original BTF, append another struct that embeds
	 * anonymous enum. It also has a name conflict with the first struct:
	 *
	 * struct s___2 {
	 *     enum { VAL___2 = 1 } x;
	 *     struct s s;
	 * };
	 *
	 * This will test that btf_dump'er maintains internal state properly.
	 * Note that VAL___2 enum value. It's because we've already emitted
	 * that enum as a global anonymous enum, so btf_dump will ensure that
	 * enum values don't conflict;
	 *
	 */
	fseek(dump_buf_file, 0, SEEK_SET);

	id = btf__add_struct(btf, "s", 4);
	ASSERT_EQ(id, 4, "struct_id");
	err = btf__add_field(btf, "x", 1, 0, 0);
	ASSERT_OK(err, "field_ok");
	err = btf__add_field(btf, "s", 3, 32, 0);
	ASSERT_OK(err, "field_ok");

	for (i = 1; i <= btf__get_nr_types(btf); i++) {
		err = btf_dump__dump_type(d, i);
		ASSERT_OK(err, "dump_type_ok");
	}

	fflush(dump_buf_file);
	dump_buf[dump_buf_sz] = 0; /* some libc implementations don't do this */
	ASSERT_STREQ(dump_buf,
"struct s___2 {\n"
"	enum {\n"
"		VAL___2 = 1,\n"
"	} x;\n"
"	struct s s;\n"
"};\n\n" , "c_dump1");

err_out:
	fclose(dump_buf_file);
	free(dump_buf);
	btf_dump__free(d);
	btf__free(btf);
}

#define STRSIZE				2048
#define	EXPECTED_STRSIZE		256

void btf_dump_snprintf(void *ctx, const char *fmt, va_list args)
{
	char *s = ctx, new[STRSIZE];

	vsnprintf(new, STRSIZE, fmt, args);
	strncat(s, new, STRSIZE);
	vfprintf(ctx, fmt, args);
}

/* skip "enum "/"struct " prefixes */
#define SKIP_PREFIX(_typestr, _prefix)					\
	do {								\
		if (strstr(_typestr, _prefix) == _typestr)		\
			_typestr += strlen(_prefix) + 1;		\
	} while (0)

int btf_dump_data(struct btf *btf, struct btf_dump *d,
		  char *ptrtype, __u64 flags, void *ptr,
		  char *str, char *expectedval)
{
	struct btf_dump_emit_type_data_opts opts = { 0 };
	int ret = 0, cmp;
	__s32 type_id;

	opts.sz = sizeof(opts);
	opts.compact = true;
	if (flags & BTF_F_NONAME)
		opts.noname = true;
	if (flags & BTF_F_ZERO)
		opts.zero = true;
	SKIP_PREFIX(ptrtype, "enum");
	SKIP_PREFIX(ptrtype, "struct");
	SKIP_PREFIX(ptrtype, "union");
	type_id = btf__find_by_name(btf, ptrtype);
	if (CHECK(type_id <= 0, "find type id",
		  "no '%s' in BTF: %d\n", ptrtype, type_id)) {
		ret = -ENOENT;
		goto err;
	}
	str[0] = '\0';
	ret = btf_dump__emit_type_data(d, type_id, &opts, ptr);
	if (CHECK(ret < 0, "btf_dump__emit_type_data",
		  "failed: %d\n", ret))
		goto err;

	cmp = strncmp(str, expectedval, EXPECTED_STRSIZE);
	if (CHECK(cmp, "ensure expected/actual match",
		  "'%s' does not match expected '%s': %d\n",
		  str, expectedval, cmp))
		ret = -EFAULT;

err:
	if (ret)
		btf_dump__free(d);
	return ret;
}

#define TEST_BTF_DUMP_DATA(_b, _d, _str, _type, _flags, _expected, ...)	\
	do {								\
		char _expectedval[EXPECTED_STRSIZE] = _expected;	\
		char __ptrtype[64] = #_type;				\
		char *_ptrtype = (char *)__ptrtype;			\
		static _type _ptrdata = __VA_ARGS__;			\
		void *_ptr = &_ptrdata;					\
									\
		if (btf_dump_data(_b, _d, _ptrtype, _flags, _ptr,	\
				  _str, _expectedval))			\
			return;						\
	} while (0)

/* Use where expected data string matches its stringified declaration */
#define TEST_BTF_DUMP_DATA_C(_b, _d, _str, _type, _opts, ...)		\
	TEST_BTF_DUMP_DATA(_b, _d, _str, _type, _opts,			\
			   "(" #_type ")" #__VA_ARGS__,	__VA_ARGS__)

void test_btf_dump_data(void)
{
	struct btf *btf = libbpf_find_kernel_btf();
	char str[STRSIZE];
	struct btf_dump_opts opts = { .ctx = str };
	struct btf_dump *d;

	if (CHECK(!btf, "get kernel BTF", "no kernel BTF found"))
		return;

	d = btf_dump__new(btf, NULL, &opts, btf_dump_snprintf);

	if (CHECK(!d, "new dump", "could not create BTF dump"))
		return;

	/* Verify type display for various types. */

	/* simple int */
	TEST_BTF_DUMP_DATA_C(btf, d, str, int, 0, 1234);
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_NONAME, "1234", 1234);

	/* zero value should be printed at toplevel */
	TEST_BTF_DUMP_DATA(btf, d, str, int, 0, "(int)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_NONAME, "0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_ZERO, "(int)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_NONAME | BTF_F_ZERO,
			   "0", 0);
	TEST_BTF_DUMP_DATA_C(btf, d, str, int, 0, -4567);
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_NONAME, "-4567", -4567);

	/* simple char */
	TEST_BTF_DUMP_DATA_C(btf, d, str, char, 0, 100);
	TEST_BTF_DUMP_DATA(btf, d, str, char, BTF_F_NONAME, "100", 100);
	/* zero value should be printed at toplevel */
	TEST_BTF_DUMP_DATA(btf, d, str, char, 0, "(char)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, char, BTF_F_NONAME, "0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, char, BTF_F_ZERO, "(char)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, char, BTF_F_NONAME | BTF_F_ZERO,
			   "0", 0);

	/* simple typedef */
	TEST_BTF_DUMP_DATA_C(btf, d, str, uint64_t, 0, 100);
	TEST_BTF_DUMP_DATA(btf, d, str, u64, BTF_F_NONAME, "1", 1);
	/* zero value should be printed at toplevel */
	TEST_BTF_DUMP_DATA(btf, d, str, u64, 0, "(u64)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, u64, BTF_F_NONAME, "0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, u64, BTF_F_ZERO, "(u64)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, u64, BTF_F_NONAME | BTF_F_ZERO,
			   "0", 0);

	/* typedef struct */
	TEST_BTF_DUMP_DATA_C(btf, d, str, atomic_t, 0, {.counter = (int)1,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, BTF_F_NONAME, "{1,}",
			   {.counter = 1,});
	/* typedef with 0 value should be printed at toplevel */
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, 0, "(atomic_t){}",
			   {.counter = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, BTF_F_NONAME, "{}",
			   {.counter = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, BTF_F_ZERO,
			   "(atomic_t){.counter = (int)0,}",
			   {.counter = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, BTF_F_NONAME | BTF_F_ZERO,
			   "{0,}", {.counter = 0,});
	/* enum where enum value does (and does not) exist */
	TEST_BTF_DUMP_DATA_C(btf, d, str, enum bpf_cmd, 0, BPF_MAP_CREATE);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd, 0,
			   "(enum bpf_cmd)BPF_MAP_CREATE", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd, BTF_F_NONAME,
			   "BPF_MAP_CREATE",
			   BPF_MAP_CREATE);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd,
			   BTF_F_NONAME | BTF_F_ZERO,
			   "BPF_MAP_CREATE", 0);

	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd, BTF_F_ZERO,
			   "(enum bpf_cmd)BPF_MAP_CREATE",
			   BPF_MAP_CREATE);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd,
			   BTF_F_NONAME | BTF_F_ZERO,
			   "BPF_MAP_CREATE", BPF_MAP_CREATE);
	TEST_BTF_DUMP_DATA_C(btf, d, str, enum bpf_cmd, 0, 2000);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd, BTF_F_NONAME,
			   "2000", 2000);

	/* simple struct */
	TEST_BTF_DUMP_DATA_C(btf, d, str, struct btf_enum, 0,
			     {.name_off = (__u32)3,.val = (__s32)-1,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum, BTF_F_NONAME,
			   "{3,-1,}",
			   { .name_off = 3, .val = -1,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum, BTF_F_NONAME, "{-1,}",
			   { .name_off = 0, .val = -1,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum,
			   BTF_F_NONAME | BTF_F_ZERO,
			   "{0,-1,}",
			   { .name_off = 0, .val = -1,});
	/* empty struct should be printed */
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum, 0,
			   "(struct btf_enum){}",
			   { .name_off = 0, .val = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum, BTF_F_NONAME, "{}",
			   { .name_off = 0, .val = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum, BTF_F_ZERO,
			   "(struct btf_enum){.name_off = (__u32)0,.val = (__s32)0,}",
			   { .name_off = 0, .val = 0,});

	/* struct with pointers */
	TEST_BTF_DUMP_DATA(btf, d, str, struct list_head, 0,
			   "(struct list_head){.next = (struct list_head *)0x1,}",
			   { .next = (struct list_head *)1 });
	/* NULL pointer should not be displayed */
	TEST_BTF_DUMP_DATA(btf, d, str, struct list_head, 0,
			   "(struct list_head){}",
			   { .next = (struct list_head *)0 });
	/* struct with char array */
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_prog_info, 0,
			   "(struct bpf_prog_info){.name = (char[])['f','o','o',],}",
			   { .name = "foo",});
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_prog_info, BTF_F_NONAME,
			   "{['f','o','o',],}",
			   {.name = "foo",});
	/* leading null char means do not display string */
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_prog_info, 0,
			   "(struct bpf_prog_info){}",
			   {.name = {'\0', 'f', 'o', 'o'}});
	/* handle non-printable characters */
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_prog_info, 0,
			   "(struct bpf_prog_info){.name = (char[])[1,2,3,],}",
			   { .name = {1, 2, 3, 0}});

	/* struct with non-char array */
	TEST_BTF_DUMP_DATA(btf, d, str, struct __sk_buff, 0,
			   "(struct __sk_buff){.cb = (__u32[])[1,2,3,4,5,],}",
			   { .cb = {1, 2, 3, 4, 5,},});
	TEST_BTF_DUMP_DATA(btf, d, str, struct __sk_buff, BTF_F_NONAME,
			   "{[1,2,3,4,5,],}",
			   { .cb = { 1, 2, 3, 4, 5},});
	/* For non-char, arrays, show non-zero values only */
	TEST_BTF_DUMP_DATA(btf, d, str, struct __sk_buff, 0,
			   "(struct __sk_buff){.cb = (__u32[])[1,],}",
			   { .cb = { 0, 0, 1, 0, 0},});

	/* struct with bitfields */
	TEST_BTF_DUMP_DATA_C(btf, d, str, struct bpf_insn, 0,
		{.code = (__u8)1,.dst_reg = (__u8)0x2,.src_reg = (__u8)0x3,.off = (__s16)4,.imm = (__s32)5,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_insn, BTF_F_NONAME,
			   "{1,0x2,0x3,4,5,}",
			   { .code = 1, .dst_reg = 0x2, .src_reg = 0x3, .off = 4,
			     .imm = 5,});
}


void test_btf_dump() {
	int i;

	for (i = 0; i < ARRAY_SIZE(btf_dump_test_cases); i++) {
		struct btf_dump_test_case *t = &btf_dump_test_cases[i];

		if (!test__start_subtest(t->name))
			continue;

		test_btf_dump_case(i, &btf_dump_test_cases[i]);
	}
	if (test__start_subtest("btf_dump: incremental"))
		test_btf_dump_incremental();
	if (test__start_subtest("btf_dump: data"))
		test_btf_dump_data();
}
