// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Google */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <../../../tools/include/linux/filter.h>

char _license[] SEC("license") = "GPL";

struct args {
	__u64 log_buf;
	__u32 log_size;
	int max_entries;
	int map_fd;
	int prog_fd;
	int btf_fd;
};

char dirname[64];
char pathname[64];

SEC("syscall")
int mkdir_prog(struct args *ctx)
{
	static char license[] = "GPL";
	static struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	static union bpf_attr load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.insn_cnt = sizeof(insns) / sizeof(insns[0]),
	};
	static union bpf_attr pin_attr = {
		.file_flags = 0,
	};
	int ret;

	ret = bpf_mkdir(dirname, sizeof(dirname), 0644);
	if (ret)
		return ret;

	load_attr.license = (long) license;
	load_attr.insns = (long) insns;
	load_attr.log_buf = ctx->log_buf;
	load_attr.log_size = ctx->log_size;
	load_attr.log_level = 1;
	ret = bpf_sys_bpf(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
	if (ret < 0)
		return ret;
	else if (ret == 0)
		return -1;
	ctx->prog_fd = ret;

	pin_attr.pathname = (__u64)pathname;
	pin_attr.bpf_fd = ret;
	return bpf_sys_bpf(BPF_OBJ_PIN, &pin_attr, sizeof(pin_attr));
}

SEC("syscall")
int rmdir_prog(struct args *ctx)
{
	int ret;

	ret = bpf_unlink(pathname, sizeof(pathname));
	if (ret)
		return ret;

	return bpf_rmdir(dirname, sizeof(dirname));
}
