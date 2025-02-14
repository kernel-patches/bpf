// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "loop.skel.h"

int main(int argc, char **argv)
{
	struct loop_bpf *skel;
	int err, prog_fd;

	skel = loop_bpf__open_and_load();
	prog_fd = bpf_program__fd(skel->progs.test_loop);
	err = bpf_prog_test_run_opts(prog_fd, NULL);

	loop_bpf__destroy(skel);
	return err;
}
