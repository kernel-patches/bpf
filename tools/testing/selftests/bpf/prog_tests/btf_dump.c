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
	err = libbpf_get_error(d);
	if (err)
		return err;

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
	if (!ASSERT_OK_PTR(btf, "btf_parse_elf")) {
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
	if (!ASSERT_GE(fd, 0, "create_tmp")) {
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

#define STRSIZE				4096

void btf_dump_snprintf(void *ctx, const char *fmt, va_list args)
{
	char *s = ctx, new[STRSIZE];

	vsnprintf(new, STRSIZE, fmt, args);
	strncat(s, new, STRSIZE);
}

/* skip "enum "/"struct " prefixes */
#define SKIP_PREFIX(_typestr, _prefix)					\
	do {								\
		if (strncmp(_typestr, _prefix, strlen(_prefix)) == 0)	\
			_typestr += strlen(_prefix) + 1;		\
	} while (0)

int btf_dump_data(struct btf *btf, struct btf_dump *d,
		  char *name, __u64 flags, void *ptr,
		  size_t ptrsize, char *str, const char *expectedval)
{
	DECLARE_LIBBPF_OPTS(btf_dump_type_data_opts, opts);
	int ret = 0, cmp;
	size_t typesize;
	__s32 type_id;

	if (flags & BTF_F_COMPACT)
		opts.compact = true;
	if (flags & BTF_F_NONAME)
		opts.skip_names = true;
	if (flags & BTF_F_ZERO)
		opts.emit_zeroes = true;
	SKIP_PREFIX(name, "enum");
	SKIP_PREFIX(name, "struct");
	SKIP_PREFIX(name, "union");
	type_id = btf__find_by_name(btf, name);
	if (CHECK(type_id <= 0, "find type id",
		  "no '%s' in BTF: %d\n", name, type_id)) {
		ret = -ENOENT;
		goto err;
	}
	typesize = btf__resolve_size(btf, type_id);
	str[0] = '\0';
	ret = btf_dump__dump_type_data(d, type_id, ptr, ptrsize, &opts);
	if (typesize <= ptrsize) {
		if (CHECK(ret != typesize, "btf_dump__dump_type_data",
			  "failed/unexpected typesize: %d\n", ret))
			goto err;
	} else {
		if (CHECK(ret != -E2BIG, "btf_dump__dump_type_data -E2BIG",
			  "failed to return -E2BIG: %d\n", ret))
			goto err;
		ret = 0;
	}

	cmp = strcmp(str, expectedval);
	if (CHECK(cmp, "ensure expected/actual match",
		  "'%s' does not match expected '%s': %d\n",
		  str, expectedval, cmp))
		ret = -EFAULT;
err:
	if (ret < 0)
		btf_dump__free(d);
	return ret;
}

#define TEST_BTF_DUMP_DATA(_b, _d, _str, _type, _flags, _expected, ...)	\
	do {								\
		char __ptrtype[64] = #_type;				\
		char *_ptrtype = (char *)__ptrtype;			\
		_type _ptrdata = __VA_ARGS__;				\
		void *_ptr = &_ptrdata;					\
		int _err;						\
									\
		_err = btf_dump_data(_b, _d, _ptrtype, _flags, _ptr,	\
				     sizeof(_type), _str, _expected);	\
		if (_err < 0)						\
			return _err;					\
	} while (0)

/* Use where expected data string matches its stringified declaration */
#define TEST_BTF_DUMP_DATA_C(_b, _d, _str, _type, _flags, ...)		\
	TEST_BTF_DUMP_DATA(_b, _d, _str, _type, _flags,			\
			   "(" #_type ")" #__VA_ARGS__,	__VA_ARGS__)

/* overflow test; pass typesize < expected type size, ensure E2BIG returned */
#define TEST_BTF_DUMP_DATA_OVER(_b, _d, _str, _type, _typesize, _expected, ...)\
	do {								\
		char __ptrtype[64] = #_type;				\
		char *_ptrtype = (char *)__ptrtype;			\
		_type _ptrdata = __VA_ARGS__;				\
		void *_ptr = &_ptrdata;					\
		int _err;						\
									\
		_err = btf_dump_data(_b, _d, _ptrtype, 0, _ptr,		\
				     _typesize, _str, _expected);	\
		if (_err < 0)						\
			return _err;					\
	} while (0)

#define TEST_BTF_DUMP_VAR(_b, _d, _str, _var, _type, _flags, _expected, ...) \
	do {								\
		_type _ptrdata = __VA_ARGS__;				\
		void *_ptr = &_ptrdata;					\
		int _err;						\
									\
		_err = btf_dump_data(_b, _d, _var, _flags, _ptr,	\
				     sizeof(_type), _str, _expected);	\
		if (_err < 0)						\
			return _err;					\
	} while (0)

int test_btf_dump_int_data(struct btf *btf, struct btf_dump *d, char *str)
{
	/* simple int */
	TEST_BTF_DUMP_DATA_C(btf, d, str, int, BTF_F_COMPACT, 1234);
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_COMPACT | BTF_F_NONAME,
			   "1234", 1234);
	TEST_BTF_DUMP_DATA(btf, d, str, int, 0, "(int)1234\n", 1234);

	/* zero value should be printed at toplevel */
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_COMPACT, "(int)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_COMPACT | BTF_F_NONAME,
			   "0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_COMPACT | BTF_F_ZERO,
			   "(int)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, int,
			   BTF_F_COMPACT | BTF_F_NONAME | BTF_F_ZERO,
			   "0", 0);
	TEST_BTF_DUMP_DATA_C(btf, d, str, int, BTF_F_COMPACT, -4567);
	TEST_BTF_DUMP_DATA(btf, d, str, int, BTF_F_COMPACT | BTF_F_NONAME,
			   "-4567", -4567);
	TEST_BTF_DUMP_DATA(btf, d, str, int, 0, "(int)-4567\n", -4567);

	TEST_BTF_DUMP_DATA_OVER(btf, d, str, int, sizeof(int)-1, "", 1);

	return 0;
}

/* since the kernel does not likely have any float types in its BTF, we
 * will need to add some of various sizes.
 */
#define TEST_ADD_FLOAT(_btf, _name, _sz)				\
	do {								\
		int _err;						\
									\
		_err = btf__add_float(_btf, _name, _sz);		\
		if (CHECK(_err < 0, "btf__add_float",			\
			  "could not add float of size %d: %d",		\
			  _sz, _err))					\
			return _err;					\
	} while (0)

#define TEST_DUMP_FLOAT(_b, _d, _str, _type, _flags, _data, _sz,	\
			_expectedval)					\
	do {								\
		int _err;						\
									\
		_err = btf_dump_data(_b, _d, _type, _flags,		\
				     _data, _sz, _str, _expectedval);	\
		if (CHECK(_err < 0, "btf_dump float",			\
			  "could not dump float data: %d\n", _err))	\
			return _err;					\
	} while (0)

int test_btf_dump_float_data(struct btf *btf, struct btf_dump *d, char *str)
{
	float t1 = 1.234567;
	float t2 = -1.234567;
	float t3 = 0.0;
	double t4 = 5.678912;
	double t5 = -5.678912;
	double t6 = 0.0;
	long double t7 = 9.876543;
	long double t8 = -9.876543;
	long double t9 = 0.0;

	TEST_ADD_FLOAT(btf, "test_float", 4);
	TEST_DUMP_FLOAT(btf, d, str, "test_float", 0, &t1, 4,
			"(test_float)1.234567\n");
	TEST_DUMP_FLOAT(btf, d, str, "test_float", 0, &t2, 4,
			"(test_float)-1.234567\n");
	TEST_DUMP_FLOAT(btf, d, str, "test_float", 0, &t3, 4,
			"(test_float)0.000000\n");

	TEST_ADD_FLOAT(btf, "test_double", 8);
	TEST_DUMP_FLOAT(btf, d, str, "test_double", 0, &t4, 8,
			"(test_double)5.678912\n");
	TEST_DUMP_FLOAT(btf, d, str, "test_double", 0, &t5, 8,
			"(test_double)-5.678912\n");
	TEST_DUMP_FLOAT(btf, d, str, "test_double", 0, &t6, 8,
			"(test_double)0.000000\n");

	TEST_ADD_FLOAT(btf, "test_long_double", 16);
	TEST_DUMP_FLOAT(btf, d, str, "test_long_double", 0, &t7, 16,
			"(test_long_double)9.876543\n");
	TEST_DUMP_FLOAT(btf, d, str, "test_long_double", 0, &t8, 16,
			"(test_long_double)-9.876543\n");
	TEST_DUMP_FLOAT(btf, d, str, "test_long_double", 0, &t9, 16,
			"(test_long_double)0.000000\n");

	return 0;
}

int test_btf_dump_char_data(struct btf *btf, struct btf_dump *d, char *str)
{
	/* simple char */
	TEST_BTF_DUMP_DATA_C(btf, d, str, char, BTF_F_COMPACT, 100);
	TEST_BTF_DUMP_DATA(btf, d, str, char, BTF_F_COMPACT | BTF_F_NONAME,
			   "100", 100);
	TEST_BTF_DUMP_DATA(btf, d, str, char, 0, "(char)100\n", 100);
	/* zero value should be printed at toplevel */
	TEST_BTF_DUMP_DATA(btf, d, str, char, BTF_F_COMPACT, "(char)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, char, BTF_F_COMPACT | BTF_F_NONAME,
			   "0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, char, BTF_F_COMPACT | BTF_F_ZERO,
			   "(char)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, char,
			   BTF_F_COMPACT | BTF_F_NONAME | BTF_F_ZERO,
			   "0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, char, 0, "(char)0\n", 0);

	TEST_BTF_DUMP_DATA_OVER(btf, d, str, char, sizeof(char)-1, "", 100);

	return 0;
}

int test_btf_dump_typedef_data(struct btf *btf, struct btf_dump *d, char *str)
{
	/* simple typedef */
	TEST_BTF_DUMP_DATA_C(btf, d, str, uint64_t, BTF_F_COMPACT, 100);
	TEST_BTF_DUMP_DATA(btf, d, str, u64, BTF_F_COMPACT | BTF_F_NONAME,
			   "1", 1);
	TEST_BTF_DUMP_DATA(btf, d, str, u64, 0, "(u64)1\n", 1);
	/* zero value should be printed at toplevel */
	TEST_BTF_DUMP_DATA(btf, d, str, u64, BTF_F_COMPACT, "(u64)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, u64, BTF_F_COMPACT | BTF_F_NONAME,
			   "0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, u64, BTF_F_COMPACT | BTF_F_ZERO,
			   "(u64)0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, u64,
			   BTF_F_COMPACT | BTF_F_NONAME | BTF_F_ZERO,
			   "0", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, u64, 0, "(u64)0\n", 0);

	/* typedef struct */
	TEST_BTF_DUMP_DATA_C(btf, d, str, atomic_t, BTF_F_COMPACT,
			     {.counter = (int)1,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, BTF_F_COMPACT | BTF_F_NONAME,
			   "{1,}", { .counter = 1 });
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, 0,
			   "(atomic_t){\n\t.counter = (int)1,\n}\n",
			   {.counter = 1,});
	/* typedef with 0 value should be printed at toplevel */
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, BTF_F_COMPACT, "(atomic_t){}",
			   {.counter = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, BTF_F_COMPACT | BTF_F_NONAME,
			   "{}", {.counter = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, 0,
			   "(atomic_t){\n}\n", {.counter = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, BTF_F_COMPACT | BTF_F_ZERO,
			   "(atomic_t){.counter = (int)0,}",
			   {.counter = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t,
			   BTF_F_COMPACT | BTF_F_NONAME | BTF_F_ZERO,
			   "{0,}", {.counter = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, atomic_t, BTF_F_ZERO,
			   "(atomic_t){\n\t.counter = (int)0,\n}\n",
			   { .counter = 0,});

	/* overflow should show type but not value since it overflows */
	TEST_BTF_DUMP_DATA_OVER(btf, d, str, atomic_t, sizeof(atomic_t)-1,
				"(atomic_t){\n", { .counter = 1});

	return 0;
}

int test_btf_dump_enum_data(struct btf *btf, struct btf_dump *d, char *str)
{
	/* enum where enum value does (and does not) exist */
	TEST_BTF_DUMP_DATA_C(btf, d, str, enum bpf_cmd, BTF_F_COMPACT,
			     BPF_MAP_CREATE);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd, BTF_F_COMPACT,
			   "(enum bpf_cmd)BPF_MAP_CREATE", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd,
			   BTF_F_COMPACT | BTF_F_NONAME,
			   "BPF_MAP_CREATE",
			   BPF_MAP_CREATE);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd, 0,
			   "(enum bpf_cmd)BPF_MAP_CREATE\n",
			   BPF_MAP_CREATE);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd,
			   BTF_F_COMPACT | BTF_F_NONAME | BTF_F_ZERO,
			   "BPF_MAP_CREATE", 0);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd,
			   BTF_F_COMPACT | BTF_F_ZERO,
			   "(enum bpf_cmd)BPF_MAP_CREATE",
			   BPF_MAP_CREATE);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd,
			   BTF_F_COMPACT | BTF_F_NONAME | BTF_F_ZERO,
			   "BPF_MAP_CREATE", BPF_MAP_CREATE);
	TEST_BTF_DUMP_DATA_C(btf, d, str, enum bpf_cmd, BTF_F_COMPACT, 2000);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd,
			   BTF_F_COMPACT | BTF_F_NONAME,
			   "2000", 2000);
	TEST_BTF_DUMP_DATA(btf, d, str, enum bpf_cmd, 0,
			   "(enum bpf_cmd)2000\n", 2000);

	TEST_BTF_DUMP_DATA_OVER(btf, d, str, enum bpf_cmd,
				sizeof(enum bpf_cmd) - 1, "", BPF_MAP_CREATE);

	return 0;
}

int test_btf_dump_struct_data(struct btf *btf, struct btf_dump *d, char *str)
{
	DECLARE_LIBBPF_OPTS(btf_dump_type_data_opts, opts);
	char zerodata[512] = { 0 };
	char typedata[512];
	void *fops = typedata;
	void *skb = typedata;
	size_t typesize;
	__s32 type_id;
	int ret, cmp;
	char *cmpstr;

	memset(typedata, 255, sizeof(typedata));

	/* simple struct */
	TEST_BTF_DUMP_DATA_C(btf, d, str, struct btf_enum, BTF_F_COMPACT,
			     {.name_off = (__u32)3,.val = (__s32)-1,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum,
			   BTF_F_COMPACT | BTF_F_NONAME,
			   "{3,-1,}",
			   { .name_off = 3, .val = -1,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum, 0,
			   "(struct btf_enum){\n\t.name_off = (__u32)3,\n\t.val = (__s32)-1,\n}\n",
			   { .name_off = 3, .val = -1,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum,
			   BTF_F_COMPACT | BTF_F_NONAME,
			   "{-1,}",
			   { .name_off = 0, .val = -1,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum,
			   BTF_F_COMPACT | BTF_F_NONAME | BTF_F_ZERO,
			   "{0,-1,}",
			   { .name_off = 0, .val = -1,});
	/* empty struct should be printed */
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum, BTF_F_COMPACT,
			   "(struct btf_enum){}",
			   { .name_off = 0, .val = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum,
			   BTF_F_COMPACT | BTF_F_NONAME,
			   "{}",
			   { .name_off = 0, .val = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum, 0,
			   "(struct btf_enum){\n}\n",
			   { .name_off = 0, .val = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum,
			   BTF_F_COMPACT | BTF_F_ZERO,
			   "(struct btf_enum){.name_off = (__u32)0,.val = (__s32)0,}",
			   { .name_off = 0, .val = 0,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct btf_enum,
			   BTF_F_ZERO,
			   "(struct btf_enum){\n\t.name_off = (__u32)0,\n\t.val = (__s32)0,\n}\n",
			   { .name_off = 0, .val = 0,});

	/* struct with pointers */
	TEST_BTF_DUMP_DATA(btf, d, str, struct list_head, BTF_F_COMPACT,
			   "(struct list_head){.next = (struct list_head *)0x1,}",
			   { .next = (struct list_head *)1 });
	TEST_BTF_DUMP_DATA(btf, d, str, struct list_head, 0,
			   "(struct list_head){\n\t.next = (struct list_head *)0x1,\n}\n",
			   { .next = (struct list_head *)1 });
	/* NULL pointer should not be displayed */
	TEST_BTF_DUMP_DATA(btf, d, str, struct list_head, BTF_F_COMPACT,
			   "(struct list_head){}",
			   { .next = (struct list_head *)0 });
	TEST_BTF_DUMP_DATA(btf, d, str, struct list_head, 0,
			   "(struct list_head){\n}\n",
			   { .next = (struct list_head *)0 });

	/* struct with function pointers */
	type_id = btf__find_by_name(btf, "file_operations");
	if (CHECK(type_id <= 0, "find type id",
		  "no 'struct file_operations' in BTF: %d\n", type_id))
		return -ENOENT;
	typesize = btf__resolve_size(btf, type_id);
	str[0] = '\0';

	ret = btf_dump__dump_type_data(d, type_id, fops, typesize, &opts);
	if (CHECK(ret != typesize,
		  "dump file_operations is successful",
		  "unexpected return value dumping file_operations '%s': %d\n",
		  str, ret))
		return -EINVAL;

	cmpstr = "(struct file_operations){\n\t.owner = (struct module *)0xffffffffffffffff,\n\t.llseek = (loff_t(*)(struct file *, loff_t, int))0xffffffffffffffff,";
	cmp = strncmp(str, cmpstr, strlen(cmpstr));
	if (CHECK(cmp != 0, "check file_operations dump",
		  "file_operations '%s' did not match expected\n",
		  str))
		return -EINVAL;

	/* struct with char array */
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_prog_info, BTF_F_COMPACT,
			   "(struct bpf_prog_info){.name = (char[])['f','o','o',],}",
			   { .name = "foo",});
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_prog_info,
			   BTF_F_COMPACT | BTF_F_NONAME,
			   "{['f','o','o',],}",
			   {.name = "foo",});
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_prog_info, 0,
			   "(struct bpf_prog_info){\n\t.name = (char[])[\n\t\t'f',\n\t\t\'o',\n\t\t'o',\n\t],\n}\n",
			   {.name = "foo",});
	/* leading null char means do not display string */
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_prog_info, BTF_F_COMPACT,
			   "(struct bpf_prog_info){}",
			   {.name = {'\0', 'f', 'o', 'o'}});
	/* handle non-printable characters */
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_prog_info, BTF_F_COMPACT,
			   "(struct bpf_prog_info){.name = (char[])[1,2,3,],}",
			   { .name = {1, 2, 3, 0}});

	/* struct with non-char array */
	TEST_BTF_DUMP_DATA(btf, d, str, struct __sk_buff, BTF_F_COMPACT,
			   "(struct __sk_buff){.cb = (__u32[])[1,2,3,4,5,],}",
			   { .cb = {1, 2, 3, 4, 5,},});
	TEST_BTF_DUMP_DATA(btf, d, str, struct __sk_buff,
			   BTF_F_COMPACT | BTF_F_NONAME,
			   "{[1,2,3,4,5,],}",
			   { .cb = { 1, 2, 3, 4, 5},});
	TEST_BTF_DUMP_DATA(btf, d, str, struct __sk_buff, 0,
			   "(struct __sk_buff){\n\t.cb = (__u32[])[\n\t\t1,\n\t\t2,\n\t\t3,\n\t\t4,\n\t\t5,\n\t],\n}\n",
			   { .cb = { 1, 2, 3, 4, 5},});
	/* For non-char, arrays, show non-zero values only */
	TEST_BTF_DUMP_DATA(btf, d, str, struct __sk_buff, BTF_F_COMPACT,
			   "(struct __sk_buff){.cb = (__u32[])[0,0,1,0,0,],}",
			   { .cb = { 0, 0, 1, 0, 0},});
	TEST_BTF_DUMP_DATA(btf, d, str, struct __sk_buff, 0,
			   "(struct __sk_buff){\n\t.cb = (__u32[])[\n\t\t0,\n\t\t0,\n\t\t1,\n\t\t0,\n\t\t0,\n\t],\n}\n",
			   { .cb = { 0, 0, 1, 0, 0},});

	/* struct with bitfields */
	TEST_BTF_DUMP_DATA_C(btf, d, str, struct bpf_insn, BTF_F_COMPACT,
		{.code = (__u8)1,.dst_reg = (__u8)0x2,.src_reg = (__u8)0x3,.off = (__s16)4,.imm = (__s32)5,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_insn,
			   BTF_F_COMPACT | BTF_F_NONAME,
			   "{1,0x2,0x3,4,5,}",
			   { .code = 1, .dst_reg = 0x2, .src_reg = 0x3, .off = 4,
			     .imm = 5,});
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_insn, 0,
			   "(struct bpf_insn){\n\t.code = (__u8)1,\n\t.dst_reg = (__u8)0x2,\n\t.src_reg = (__u8)0x3,\n\t.off = (__s16)4,\n\t.imm = (__s32)5,\n}\n",
			   {.code = 1, .dst_reg = 2, .src_reg = 3, .off = 4, .imm = 5});

	/* zeroed bitfields should not be displayed */
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_insn, BTF_F_COMPACT,
			   "(struct bpf_insn){.dst_reg = (__u8)0x1,}",
			   { .code = 0, .dst_reg = 1});

	/* struct with enum bitfield */
	type_id = btf__find_by_name(btf, "nft_cmp_expr");
	if (CHECK(type_id <= 0, "find nft_cmp_expr",
		  "no 'struct nft_cmp_expr' in BTF: %d\n", type_id))
		return -ENOENT;
	typesize = btf__resolve_size(btf, type_id);
	str[0] = '\0';

	opts.emit_zeroes = true;
	ret = btf_dump__dump_type_data(d, type_id, zerodata, typesize, &opts);
	if (CHECK(ret != typesize,
		  "dump nft_cmp_expr is successful",
		  "unexpected return value dumping nft_cmp_expr '%s': %d\n",
		  str, ret))
		return -EINVAL;

	if (CHECK(strstr(str, "NFT_CMP_EQ") == NULL,
		  "verify enum value shown for bitfield",
		  "bitfield value not present in '%s'\n", str))
		return -EINVAL;

	/* struct with nested anon union */
	TEST_BTF_DUMP_DATA(btf, d, str, struct bpf_sock_ops, BTF_F_COMPACT,
			   "(struct bpf_sock_ops){.op = (__u32)1,(union){.args = (__u32[])[1,2,3,4,],.reply = (__u32)1,.replylong = (__u32[])[1,2,3,4,],},}",
			   { .op = 1, .args = { 1, 2, 3, 4}});

	/* union with nested struct */
	TEST_BTF_DUMP_DATA(btf, d, str, union bpf_iter_link_info, BTF_F_COMPACT,
			   "(union bpf_iter_link_info){.map = (struct){.map_fd = (__u32)1,},}",
			   { .map = { .map_fd = 1 }});

	/* struct skb with nested structs/unions; because type output is so
	 * complex, we don't do a string comparison, just verify we return
	 * the type size as the amount of data displayed.
	 */
	type_id = btf__find_by_name(btf, "sk_buff");
	if (CHECK(type_id <= 0, "find type id",
		  "no 'struct sk_buff' in BTF: %d\n", type_id))
		return -ENOENT;
	typesize = btf__resolve_size(btf, type_id);
	str[0] = '\0';

	ret = btf_dump__dump_type_data(d, type_id, skb, typesize, &opts);
	if (CHECK(ret != typesize,
		  "dump sk_buff is successful",
		  "unexpected return value dumping sk_buff '%s': %d\n",
		  str, ret))
		return -EINVAL;

	/* overflow bpf_sock_ops struct with final element nonzero/zero.
	 * Regardless of the value of the final field, we don't have all the
	 * data we need to display it, so we should trigger an overflow.
	 * In other words oveflow checking should trump "is field zero?"
	 * checks because if we've overflowed, it shouldn't matter what the
	 * field is - we can't trust its value so shouldn't display it.
	 */
	TEST_BTF_DUMP_DATA_OVER(btf, d, str, struct bpf_sock_ops,
				sizeof(struct bpf_sock_ops) - 1,
				"(struct bpf_sock_ops){\n\t.op = (__u32)1,\n",
				{ .op = 1, .skb_tcp_flags = 2});
	TEST_BTF_DUMP_DATA_OVER(btf, d, str, struct bpf_sock_ops,
				sizeof(struct bpf_sock_ops) - 1,
				"(struct bpf_sock_ops){\n\t.op = (__u32)1,\n",
				{ .op = 1, .skb_tcp_flags = 0});

	return 0;
}

int test_btf_dump_var_data(struct btf *btf, struct btf_dump *d, char *str)
{

	TEST_BTF_DUMP_VAR(btf, d, str, "cpu_number", int, BTF_F_COMPACT,
			  "int cpu_number = (int)100", 100);
	TEST_BTF_DUMP_VAR(btf, d, str, "cpu_profile_flip", int, BTF_F_COMPACT,
			  "static int cpu_profile_flip = (int)2", 2);

	return 0;
}

int test_btf_datasec(struct btf *btf, struct btf_dump *d, char *str,
		     const char *name, const char *expectedval,
		     void *data, size_t data_sz)
{
	DECLARE_LIBBPF_OPTS(btf_dump_type_data_opts, opts);
	int ret = 0, cmp;
	size_t secsize;
	__s32 type_id;

	opts.compact = true;

	type_id = btf__find_by_name(btf, name);
	if (CHECK(type_id <= 0, "find type id",
		  "no '%s' in BTF: %d\n", name, type_id))
		return -ENOENT;

	secsize = btf__resolve_size(btf, type_id);
	if (CHECK(secsize != 0, "verify section size",
		  "unexpected section size %ld for %s\n", secsize, name))
		return -EINVAL;

	str[0] = '\0';
	ret = btf_dump__dump_type_data(d, type_id, data, data_sz, &opts);
	if (CHECK(ret != 0, "btf_dump__dump_type_data",
		  "failed/unexpected return value: %d\n", ret))
		return ret;

	cmp = strcmp(str, expectedval);
	if (CHECK(cmp, "ensure expected/actual match",
		  "'%s' does not match expected '%s': %d\n",
		  str, expectedval, cmp))
		ret = -EFAULT;

	return ret;
}

int test_btf_dump_datasec_data(char *str)
{
	struct btf *btf = btf__parse("xdping_kern.o", NULL);
	struct btf_dump_opts opts = { .ctx = str };
	char license[4] = "GPL";
	struct btf_dump *d;

	if (CHECK(!btf, "get prog BTF", "xdping_kern.o BTF not found"))
		return -ENOENT;

	d = btf_dump__new(btf, NULL, &opts, btf_dump_snprintf);

	if (CHECK(!d, "new dump", "could not create BTF dump"))
		return -ENOENT;

	if (test_btf_datasec(btf, d, str, "license",
			     "SEC(\"license\") char[] _license = (char[])['G','P','L',];",
			     license, sizeof(license)))
		return -EINVAL;

	return 0;
}

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
	if (test_btf_dump_int_data(btf, d, str))
		return;
	if (test_btf_dump_float_data(btf, d, str))
		return;
	if (test_btf_dump_char_data(btf, d, str))
		return;
	if (test_btf_dump_typedef_data(btf, d, str))
		return;
	if (test_btf_dump_enum_data(btf, d, str))
		return;
	if (test_btf_dump_struct_data(btf, d, str))
		return;
	if (test_btf_dump_var_data(btf, d, str))
		return;
	btf_dump__free(d);
	btf__free(btf);

	/* verify datasec display */
	if (test_btf_dump_datasec_data(str))
		return;

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
