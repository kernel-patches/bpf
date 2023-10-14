/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cgroup_helpers.h"
#include "sock_addr_helpers.h"

int load_path(const char *path, enum bpf_attach_type attach_type,
	      bool expect_reject)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int err;

	obj = bpf_object__open_file(path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		log_err(">>> Opening BPF object (%s) error.\n", path);
		return -1;
	}

	prog = bpf_object__next_program(obj, NULL);
	if (!prog)
		goto err_out;

	bpf_program__set_type(prog, BPF_PROG_TYPE_CGROUP_SOCK_ADDR);
	bpf_program__set_expected_attach_type(prog, attach_type);
	bpf_program__set_flags(prog, BPF_F_TEST_RND_HI32);

	err = bpf_object__load(obj);
	if (err) {
		if (!expect_reject)
			log_err(">>> Loading program (%s) error.\n", path);
		goto err_out;
	}

	return bpf_program__fd(prog);
err_out:
	bpf_object__close(obj);
	return -1;
}
