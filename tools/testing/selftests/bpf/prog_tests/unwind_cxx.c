// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <bpf/btf.h>

/*
 * llvm tags the functions that say in r3 whether they return or unwind.
 * Without that _Unwind_RaiseException() is an unknown extern and libbpf doesn't
 * open the object, so look before that.
 */
static bool llvm_lowers_unwinding(const char *file)
{
	struct btf *btf = btf__parse(file, NULL);
	int i, n = btf ? btf__type_cnt(btf) : 0;
	bool ret = false;

	for (i = 1; i < n && !ret; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);

		ret = btf_is_decl_tag(t) &&
		      !strcmp(btf__name_by_offset(btf, t->name_off), "unwind");
	}
	btf__free(btf);
	return ret;
}

static void run(struct bpf_object *obj, const char *name, int len, int retval, int dtors)
{
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, name);
	struct bpf_map *map = bpf_object__find_map_by_name(obj, ".data.dtors");
	char data[256] = {};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = data,
		.data_size_in = len,
		.repeat = 1,
	);
	int key = 0, val = 0;

	if (!ASSERT_OK_PTR(prog, name) || !ASSERT_OK_PTR(map, "dtors"))
		return;
	ASSERT_OK(bpf_map__update_elem(map, &key, sizeof(key), &val, sizeof(val), 0), "clear");
	ASSERT_OK(bpf_prog_test_run_opts(bpf_program__fd(prog), &opts), "test_run");
	ASSERT_EQ(opts.retval, retval, "retval");
	ASSERT_OK(bpf_map__lookup_elem(map, &key, sizeof(key), &val, sizeof(val), 0), "lookup");
	ASSERT_EQ(val, dtors, "dtors");
}

void test_unwind_cxx(void)
{
#if defined(__x86_64__) || defined(__aarch64__)
	const char *file = "./unwind_cxx.bpf.o";
	struct bpf_object *obj;

	/* gcc flavor doesn't build it */
	if (access(file, R_OK) || !llvm_lowers_unwinding(file) || !is_jit_enabled()) {
		test__skip();
		return;
	}
	obj = bpf_object__open_file(file, NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return;
	if (!ASSERT_OK(bpf_object__load(obj), "load"))
		goto out;
	/* libbpf goes on without BTF when the kernel doesn't take it */
	ASSERT_GE(bpf_object__btf_fd(obj), 0, "btf_fd");

	/* inner's destructor, then middle's */
	run(obj, "catches", 64, 65, 12);
	run(obj, "catches", 200, 42, 12);
	run(obj, "does_not_catch", 64, 65, 12);
	run(obj, "does_not_catch", 200, 0, 12);
out:
	bpf_object__close(obj);
#else
	test__skip();
#endif
}
