// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "simple.skel.h"

int main(int argc, char **argv)
{
	struct simple_bpf *skel;
	int err, prog_fd;

	skel = simple_bpf__open_and_load();
	prog_fd = bpf_program__fd(skel->progs.test_simple);
	err = bpf_prog_test_run_opts(prog_fd, NULL);

	simple_bpf__destroy(skel);
	return err;
}
