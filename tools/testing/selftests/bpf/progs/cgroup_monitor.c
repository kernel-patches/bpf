// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Google */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* root is the directory path. */
char root[64];

SEC("tp_btf.s/cgroup_mkdir_s")
int BPF_PROG(mkdir_prog, struct cgroup *cgrp)
{
	static char dirname[64];
	static char prog_path[64];
	static char iter_path[64];
	static union bpf_iter_link_info info;
	static union bpf_attr get_attr;
	static union bpf_attr link_attr;
	static union bpf_attr pin_attr;
	int link_fd, prog_fd, ret;
	__u64 id;

	/* create directory in bpffs named by cgroup's id. */
	id = cgrp->kn->id;
	BPF_SNPRINTF(dirname, sizeof(dirname), "%s/%lu", root, id);
	ret = bpf_mkdir(dirname, sizeof(dirname), 0755);
	if (ret)
		return ret;

	/* get cgroup iter prog pinned by test progs. */
	BPF_SNPRINTF(prog_path, sizeof(prog_path), "%s/prog", root);
	get_attr.bpf_fd = 0;
	get_attr.pathname = (__u64)prog_path;
	get_attr.file_flags = BPF_F_RDONLY;
	prog_fd = bpf_sys_bpf(BPF_OBJ_GET, &get_attr, sizeof(get_attr));
	if (prog_fd < 0)
		return prog_fd;

	/* create a link, parameterized by cgroup id. */
	info.cgroup.cgroup_id = id;
	link_attr.link_create.prog_fd = prog_fd;
	link_attr.link_create.attach_type = BPF_TRACE_ITER;
	link_attr.link_create.target_fd = 0;
	link_attr.link_create.flags = 0;
	link_attr.link_create.iter_info = (__u64)&info;
	link_attr.link_create.iter_info_len = sizeof(info);
	ret = bpf_sys_bpf(BPF_LINK_CREATE, &link_attr, sizeof(link_attr));
	if (ret < 0) {
		bpf_sys_close(prog_fd);
		return ret;
	}
	link_fd = ret;

	/* pin the link in the created directory */
	BPF_SNPRINTF(iter_path, sizeof(iter_path), "%s/stats", dirname);
	pin_attr.pathname = (__u64)iter_path;
	pin_attr.bpf_fd = link_fd;
	pin_attr.file_flags = 0;
	ret = bpf_sys_bpf(BPF_OBJ_PIN, &pin_attr, sizeof(pin_attr));

	bpf_sys_close(prog_fd);
	bpf_sys_close(link_fd);
	return ret;
}

SEC("tp_btf.s/cgroup_rmdir_s")
int BPF_PROG(rmdir_prog, struct cgroup *cgrp)
{
	static char dirname[64];
	static char path[64];

	BPF_SNPRINTF(dirname, sizeof(dirname), "%s/%lu", root, cgrp->kn->id);
	BPF_SNPRINTF(path, sizeof(path), "%s/stats", dirname);
	bpf_unlink(path, sizeof(path));
	return bpf_rmdir(dirname, sizeof(dirname));
}
