// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */
#include <test_progs.h>
#include <dirent.h>
#include <bpf/skel_internal.h>

#define NR_PROGS 7

enum execution_case {
	ATTACH,
	NO_AUTOLOAD,
	NO_AUTOATTACH,
	ROLLBACK,
};

static int link_create_attr_offset(const struct gen_loader_opts *opts, int index)
{
	const struct bpf_insn *insns = (const void *)opts->insns;
	int i, count = opts->insns_sz / sizeof(*insns);

	for (i = 4; i < count; i++) {
		if (insns[i].code != (BPF_JMP | BPF_CALL) ||
		    insns[i].imm != BPF_FUNC_sys_bpf ||
		    insns[i - 4].code != (BPF_ALU64 | BPF_MOV | BPF_K) ||
		    insns[i - 4].dst_reg != BPF_REG_1 ||
		    insns[i - 4].imm != BPF_LINK_CREATE)
			continue;
		if (!index--)
			return insns[i - 2].imm;
	}
	return -1;
}

static struct bpf_object *generate(struct gen_loader_opts *opts, enum execution_case test)
{
	struct bpf_program *prog;
	struct bpf_object *obj;

	obj = bpf_object__open_file("gen_loader_attach.bpf.o", NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return NULL;
	prog = bpf_object__find_program_by_name(obj, "lsm_open");
	bpf_program__set_autoload(prog, test != NO_AUTOLOAD);
	bpf_program__set_autoattach(prog, test != NO_AUTOATTACH);
	if (!ASSERT_OK(bpf_object__gen_loader(obj, opts), "gen_loader") ||
	    !ASSERT_OK(bpf_object__load(obj), "generate"))
		goto err_out;
	return obj;

err_out:
	bpf_object__close(obj);
	return NULL;
}

static void check_load_only(void)
{
	LIBBPF_OPTS(gen_loader_opts, opts);
	struct bpf_object *obj;

	obj = generate(&opts, ATTACH);
	if (!obj)
		return;
	ASSERT_EQ(link_create_attr_offset(&opts, 0), -1, "no_link_create");
	bpf_object__close(obj);
}

static void check_unsupported(void)
{
	LIBBPF_OPTS(gen_loader_opts, opts, .gen_attach = true);
	struct bpf_program *prog;
	struct bpf_object *obj;

	obj = bpf_object__open_file("gen_loader_attach.bpf.o", NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return;
	prog = bpf_object__find_program_by_name(obj, "socket");
	bpf_program__set_autoload(prog, true);
	if (ASSERT_OK(bpf_object__gen_loader(obj, &opts), "gen_loader"))
		ASSERT_EQ(bpf_object__load(obj), -EOPNOTSUPP, "unsupported_attach");
	bpf_object__close(obj);
}

static void check_tracing_generation(void)
{
	LIBBPF_OPTS(gen_loader_opts, opts, .gen_attach = true);
	struct bpf_program *prog;
	struct bpf_object *obj;
	int index = 0;

	obj = bpf_object__open_file("gen_loader_attach.bpf.o", NULL);
	if (!ASSERT_OK_PTR(obj, "open"))
		return;
	bpf_object__for_each_program(prog, obj)
		bpf_program__set_autoload(prog, bpf_program__type(prog) == BPF_PROG_TYPE_TRACING);
	if (!ASSERT_OK(bpf_object__gen_loader(obj, &opts), "gen_loader") ||
	    !ASSERT_OK(bpf_object__load(obj), "generate"))
		goto out;
	bpf_object__for_each_program(prog, obj) {
		const union bpf_attr *attr;
		int off;

		if (!bpf_program__autoload(prog))
			continue;
		off = link_create_attr_offset(&opts, index++);
		if (!ASSERT_GE(off, 0, bpf_program__name(prog)))
			goto out;
		attr = (const void *)(opts.data + off);
		ASSERT_EQ(attr->link_create.attach_type,
			  bpf_program__expected_attach_type(prog), bpf_program__name(prog));
	}
	ASSERT_EQ(link_create_attr_offset(&opts, index), -1, "link_count");
out:
	bpf_object__close(obj);
}

static int count_fds(void)
{
	struct dirent *entry;
	int count = 0;
	DIR *dir;

	dir = opendir("/proc/self/fd");
	if (!dir)
		return -errno;
	while ((entry = readdir(dir)))
		if (entry->d_name[0] != '.')
			count++;
	closedir(dir);
	return count;
}

static void check_execution(enum execution_case test)
{
	LIBBPF_OPTS(gen_loader_opts, gen, .gen_attach = true);
	struct {
		struct bpf_loader_ctx ctx;
		struct bpf_prog_desc progs[NR_PROGS];
		struct bpf_link_desc links[NR_PROGS];
	} ctx = { .ctx.sz = sizeof(ctx) };
	struct bpf_load_and_run_opts run = { .ctx = &ctx.ctx };
	struct bpf_object *obj;
	int i, off, err, before;

	obj = generate(&gen, test);
	if (!obj)
		return;
	run.insns = gen.insns;
	run.insns_sz = gen.insns_sz;
	run.data = gen.data;
	run.data_sz = gen.data_sz;

	if (test == ROLLBACK) {
		off = link_create_attr_offset(&gen, 1);
		if (!ASSERT_GE(off, 0, "second_link_attr"))
			goto out;
		/* Force the second attachment to fail after the first succeeded. */
		((union bpf_attr *)(gen.data + off))->link_create.attach_type = BPF_TRACE_FENTRY;

		before = count_fds();
		if (!ASSERT_GE(before, 0, "count_fds"))
			goto out;
		ASSERT_EQ(bpf_load_and_run(&run), -EINVAL, "second_attach_failed");
		ASSERT_EQ(count_fds(), before, "rollback_fds");
		goto out;
	}

	err = bpf_load_and_run(&run);
	if (!ASSERT_OK(err, "run_loader"))
		goto out;

	for (i = 0; i < NR_PROGS; i++) {
		struct bpf_link_info link = {};
		struct bpf_prog_info prog = {};
		__u32 size;

		/*
		 * Only the first two programs load by default; NO_AUTOLOAD also
		 * skips the first. NO_AUTOATTACH must still return its program FD.
		 */
		if (i >= 2 || (!i && test == NO_AUTOLOAD)) {
			ASSERT_EQ(ctx.progs[i].prog_fd, 0, "skipped_program");
		} else {
			size = sizeof(prog);
			if (!ASSERT_GT(ctx.progs[i].prog_fd, 0, "program_fd") ||
			    !ASSERT_OK(bpf_prog_get_info_by_fd(ctx.progs[i].prog_fd, &prog, &size),
				       "prog_info"))
				continue;
		}

		/*
		 * Unloaded programs have no link. NO_AUTOATTACH also leaves the
		 * first program's link slot zero, even though its program is loaded.
		 */
		if (i >= 2 || (!i && (test == NO_AUTOLOAD || test == NO_AUTOATTACH))) {
			ASSERT_EQ(ctx.links[i].link_fd, 0, "skipped_link");
			continue;
		}
		/* Verify the link references the corresponding loaded program. */
		size = sizeof(link);
		if (!ASSERT_OK(bpf_link_get_info_by_fd(ctx.links[i].link_fd, &link, &size),
			       "link_info"))
			continue;
		ASSERT_EQ(link.prog_id, prog.id, "attached_program");
	}
out:
	for (i = 0; i < NR_PROGS; i++) {
		skel_closenz(ctx.links[i].link_fd);
		skel_closenz(ctx.progs[i].prog_fd);
	}
	bpf_object__close(obj);
}

void test_gen_loader_attach(void)
{
	if (test__start_subtest("load_only"))
		check_load_only();
	if (test__start_subtest("unsupported"))
		check_unsupported();
	if (test__start_subtest("tracing"))
		check_tracing_generation();
	if (test__start_subtest("execute"))
		check_execution(ATTACH);
	if (test__start_subtest("execute_no_autoload"))
		check_execution(NO_AUTOLOAD);
	if (test__start_subtest("execute_no_autoattach"))
		check_execution(NO_AUTOATTACH);
	if (test__start_subtest("rollback"))
		check_execution(ROLLBACK);
}
