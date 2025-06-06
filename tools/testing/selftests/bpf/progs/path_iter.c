// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

char path_name[256];
char xattr_val[64];

static __always_inline void access_path_dentry(struct path *p)
{
	struct bpf_dynptr ptr;
	struct dentry *dentry;

	if (!p)
		return;

	bpf_dynptr_from_mem(xattr_val, sizeof(xattr_val), 0, &ptr);
	bpf_path_d_path(p, path_name, sizeof(path_name));

	dentry = p->dentry;
	if (dentry)
		bpf_get_dentry_xattr(dentry, "user.xattr", &ptr);
}

SEC("lsm.s/file_open")
__success
int BPF_PROG(open_code, struct file *f)
{
	struct bpf_iter_path path_it;
	struct path *p;
	int ret;

	ret = bpf_iter_path_new(&path_it, &f->f_path, 0);
	if (ret) {
		bpf_iter_path_destroy(&path_it);
		return 0;
	}

	p = bpf_iter_path_next(&path_it);
	access_path_dentry(p);
	bpf_iter_path_destroy(&path_it);

	return 0;
}

SEC("lsm.s/file_open")
__success
int BPF_PROG(for_each, struct file *f)
{
	struct path *p;

	bpf_for_each(path, p, &f->f_path, 0)
		access_path_dentry(p);

	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("Unreleased reference")
int BPF_PROG(missing_destroy, struct file *f)
{
	struct bpf_iter_path path_it;

	bpf_iter_path_new(&path_it, &f->f_path, 0);

	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("expected an initialized iter_path")
int BPF_PROG(missing_new, struct file *f)
{
	struct bpf_iter_path path_it;

	bpf_iter_path_destroy(&path_it);
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("expected uninitialized iter_path")
int BPF_PROG(new_twice, struct file *f)
{
	struct bpf_iter_path path_it;

	bpf_iter_path_new(&path_it, &f->f_path, 0);
	bpf_iter_path_new(&path_it, &f->f_path, 0);
	bpf_iter_path_destroy(&path_it);
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("expected an initialized iter_path")
int BPF_PROG(destroy_twice, struct file *f)
{
	struct bpf_iter_path path_it;

	bpf_iter_path_new(&path_it, &f->f_path, 0);
	bpf_iter_path_destroy(&path_it);
	bpf_iter_path_destroy(&path_it);
	return 0;
}

SEC("lsm.s/file_open")
__success
int BPF_PROG(reuse_path_iter, struct file *f)
{
	struct bpf_iter_path path_it;

	bpf_iter_path_new(&path_it, &f->f_path, 0);
	bpf_iter_path_destroy(&path_it);
	bpf_iter_path_new(&path_it, &f->f_path, 0);
	bpf_iter_path_destroy(&path_it);
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("invalid read from stack off")
int BPF_PROG(invalid_read_path_iter, struct file *f)
{
	struct bpf_iter_path path_it;
	struct bpf_iter_path path_it_2;


	bpf_iter_path_new(&path_it, &f->f_path, 0);
	path_it_2 = path_it;
	bpf_iter_path_destroy(&path_it_2);
	return 0;
}

SEC("lsm.s/sb_alloc_security")
__failure __msg("must be referenced or trusted")
int BPF_PROG(untrusted_path, struct super_block *sb)
{
	struct bpf_iter_path path_it;

	bpf_iter_path_new(&path_it, &sb->s_bdev_file->f_path, 0);
	bpf_iter_path_destroy(&path_it);
	return 0;
}
