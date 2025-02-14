// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "branch.skel.h"

int main(int argc, char **argv)
{
	struct branch_bpf *skel;
	int err, prog_fd;

	skel = branch_bpf__open_and_load();
	prog_fd = bpf_program__fd(skel->progs.test_branch);
	err = bpf_prog_test_run_opts(prog_fd, NULL);

	branch_bpf__destroy(skel);
	return err;
}
