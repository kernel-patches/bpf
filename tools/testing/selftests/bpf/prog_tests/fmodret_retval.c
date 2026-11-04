// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include <bpf/btf.h>
#include "fmodret_retval.skel.h"
#include "fmodret_retval_ext.skel.h"

#define TAG_FMODRET		"bpf_fmodret"
#define TAG_RETVAL		"bpf_fmodret_retval:"
#define TAG_TEST_RETVAL		"test_retval:"

#define RETVAL_MODULE		"bpf_test_retval"

/* The decl tags of a function */
struct func_tags {
	const char *test_retval;
	const char *retval;
	bool target;
};

static bool tag_value(const char *name, const char *key, const char **value)
{
	size_t len = strlen(key);

	if (strncmp(name, key, len))
		return false;
	*value = name + len;
	return true;
}

/*
 * Return the decl tags of the functions of module BTF, indexed by BTF ID. Only
 * the types of the module itself are read, not those of its vmlinux base.
 */
static struct func_tags *collect_tags(const struct btf *btf, int start_id)
{
	int id, nr_types = btf__type_cnt(btf);
	struct func_tags *tags;

	tags = calloc(nr_types, sizeof(*tags));
	if (!tags)
		return NULL;
	for (id = start_id; id < nr_types; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);
		struct func_tags *f;
		const char *name;

		if (!btf_is_decl_tag(t) || btf_decl_tag(t)->component_idx != -1 ||
		    t->type >= nr_types)
			continue;
		f = &tags[t->type];
		name = btf__name_by_offset(btf, t->name_off);
		if (!tag_value(name, TAG_TEST_RETVAL, &f->test_retval) &&
		    !tag_value(name, TAG_RETVAL, &f->retval) && !strcmp(name, TAG_FMODRET))
			f->target = true;
	}

	return tags;
}

/* Compare the tags of every fixture with the values it expects */
static void test_tags(const struct btf *btf, const struct func_tags *tags, int start_id)
{
	int id, nr_types = btf__type_cnt(btf), nr_fixtures = 0;

	for (id = start_id; id < nr_types; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);
		const char *name;

		if (!btf_is_func(t) || !tags[id].test_retval)
			continue;
		name = btf__name_by_offset(btf, t->name_off);
		ASSERT_STREQ(tags[id].retval ?: "", tags[id].test_retval, name);
		if (*tags[id].test_retval)
			ASSERT_TRUE(tags[id].target, name);
		else if (strcmp(name, "bpf_testmod_retval_declared"))
			ASSERT_FALSE(tags[id].target, name);
		nr_fixtures++;
	}
	ASSERT_GT(nr_fixtures, 0, "fixtures");

	id = btf__find_by_name_kind(btf, "bpf_testmod_retval_declared", BTF_KIND_FUNC);
	if (ASSERT_GE(id, start_id, "declared"))
		ASSERT_TRUE(tags[id].target, "declared_target");
}

/* Open the programs again with only the extension, to replace FUNC of TARGET */
static struct fmodret_retval_ext *open_extension(struct bpf_program *target,
						 const char *func, char *log, size_t log_size)
{
	struct fmodret_retval_ext *skel;

	skel = fmodret_retval_ext__open();
	if (!ASSERT_OK_PTR(skel, "fmodret_retval_ext__open"))
		return NULL;
	bpf_program__set_autoload(skel->progs.restricted, false);
	bpf_program__set_autoload(skel->progs.unrestricted, false);
	if (!ASSERT_OK(bpf_program__set_attach_target(skel->progs.extension,
						      bpf_program__fd(target), func),
		       "set_attach_target")) {
		fmodret_retval_ext__destroy(skel);
		return NULL;
	}
	bpf_program__set_log_buf(skel->progs.extension, log, log_size);
	return skel;
}

/*
 * An extension could return any value for an fmod_ret program, so it must not
 * replace one whose return values are restricted, neither at load nor when it
 * is attached later to another program.
 */
static void test_extension(void)
{
	struct fmodret_retval_ext *targets, *skel = NULL;
	struct bpf_link *link;
	char log[4096] = {};

	if (!is_jit_enabled()) {
		printf("%s:SKIP:extensions need the JIT\n", __func__);
		test__skip();
		return;
	}

	targets = fmodret_retval_ext__open();
	if (!ASSERT_OK_PTR(targets, "fmodret_retval_ext__open"))
		return;
	bpf_program__set_autoload(targets->progs.extension, false);
	if (!ASSERT_OK(fmodret_retval_ext__load(targets), "load_targets"))
		goto out;

	skel = open_extension(targets->progs.restricted, "restricted_value", log, sizeof(log));
	if (!skel)
		goto out;
	ASSERT_ERR(fmodret_retval_ext__load(skel), "load_restricted");
	ASSERT_HAS_SUBSTR(log, "Cannot extend an fmod_ret program with restricted return values",
			  "log_restricted");
	fmodret_retval_ext__destroy(skel);

	skel = open_extension(targets->progs.unrestricted, "unrestricted_value", log, sizeof(log));
	if (!skel)
		goto out;
	if (!ASSERT_OK(fmodret_retval_ext__load(skel), "load_unrestricted"))
		goto out;
	link = bpf_program__attach_freplace(skel->progs.extension,
					    bpf_program__fd(targets->progs.restricted),
					    "restricted_value");
	if (!ASSERT_ERR_PTR(link, "attach_restricted"))
		bpf_link__destroy(link);
	link = bpf_program__attach_freplace(skel->progs.extension,
					    bpf_program__fd(targets->progs.unrestricted),
					    "unrestricted_value");
	if (ASSERT_OK_PTR(link, "attach_unrestricted"))
		bpf_link__destroy(link);
out:
	fmodret_retval_ext__destroy(skel);
	fmodret_retval_ext__destroy(targets);
}

void test_fmodret_retval(void)
{
	struct btf *vmlinux_btf, *btf = NULL;
	struct func_tags *tags = NULL;
	int id, start_id, nr_types;
	bool has_fixtures = false;

	if (!env.has_testmod) {
		test__skip();
		return;
	}

	if (!ASSERT_OK(load_module(RETVAL_MODULE ".ko", env_verbosity > VERBOSE_NONE),
		       "load_module"))
		return;
	vmlinux_btf = btf__load_vmlinux_btf();
	if (!ASSERT_OK_PTR(vmlinux_btf, "btf__load_vmlinux_btf"))
		goto out;
	btf = btf__load_module_btf(RETVAL_MODULE, vmlinux_btf);
	if (!btf && errno == ENOENT) {
		printf("%s:SKIP:%s has no BTF\n", __func__, RETVAL_MODULE);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK_PTR(btf, "btf__load_module_btf"))
		goto out;
	start_id = btf__type_cnt(vmlinux_btf);
	nr_types = btf__type_cnt(btf);
	tags = collect_tags(btf, start_id);
	if (!ASSERT_OK_PTR(tags, "collect_tags"))
		goto out;

	/* The fixtures are built only with the compiler plugin */
	for (id = start_id; id < nr_types && !has_fixtures; id++)
		has_fixtures = tags[id].test_retval;
	if (!has_fixtures) {
		printf("%s:SKIP:%s has no %s tags\n", __func__, RETVAL_MODULE, TAG_TEST_RETVAL);
		test__skip();
		goto out;
	}

	if (test__start_subtest("tags"))
		test_tags(btf, tags, start_id);
	if (test__start_subtest("extension"))
		test_extension();
	RUN_TESTS(fmodret_retval);
out:
	free(tags);
	btf__free(btf);
	btf__free(vmlinux_btf);
	unload_module(RETVAL_MODULE, env_verbosity > VERBOSE_NONE);
}
