// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright (C) 2022 Huawei Technologies Co., Ltd.

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>

#include "json_writer.h"
#include "main.h"

static bool is_trace_program_type(struct bpf_program *prog)
{
	enum bpf_prog_type trace_types[] = {
		BPF_PROG_TYPE_RAW_TRACEPOINT,
		BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	};
	enum bpf_prog_type prog_type;
	size_t i;

	prog_type = bpf_program__type(prog);
	for (i = 0; i < ARRAY_SIZE(trace_types); i++) {
		if (prog_type == trace_types[i])
			return true;
	}

	return false;
}

static int do_pin(int argc, char **argv)
{
	const char *objfile, *path;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_link *link;
	int err;

	if (!REQ_ARGS(2))
		usage();

	objfile = GET_ARG();
	path = GET_ARG();

	obj = bpf_object__open(objfile);
	err = libbpf_get_error(obj);
	if (err) {
		p_err("can't open objfile %s", objfile);
		return err;
	}

	err = bpf_object__load(obj);
	if (err) {
		p_err("can't load objfile %s", objfile);
		goto close_obj;
	}

	prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		p_err("can't find bpf program in objfile %s", objfile);
		goto close_obj;
	}

	if (!is_trace_program_type(prog)) {
		p_err("invalid bpf program type");
		err = -EINVAL;
		goto close_obj;
	}

	link = bpf_program__attach(prog);
	err = libbpf_get_error(link);
	if (err) {
		p_err("can't attach program %s", bpf_program__name(prog));
		goto close_obj;
	}

	err = mount_bpffs_for_pin(path);
	if (err)
		goto close_link;

	err = bpf_link__pin(link, path);
	if (err) {
		p_err("pin failed for program %s to path %s",
		      bpf_program__name(prog), path);
		goto close_link;
	}

close_link:
	bpf_link__destroy(link);
close_obj:
	bpf_object__close(obj);
	return err;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s pin OBJ PATH\n"
		"       %1$s %2$s help\n"
		"\n"
		"",
		bin_name, "trace");

	return 0;
}

static const struct cmd cmds[] = {
	{ "help",	do_help },
	{ "pin",	do_pin },
	{ 0 }
};

int do_trace(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
