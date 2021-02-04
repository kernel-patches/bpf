// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;

	obj = bpf_object__open_file("hello_kern.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	prog = bpf_object__find_program_by_name(obj, "trace_enter_execve");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	read_trace_pipe();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
