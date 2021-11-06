// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TARGET_FILE_NAME "1234123412341234123412341234123412341234"

char _license[] SEC("license") = "GPL";

__u32 pid = 0;
__u32 equal = 0;

struct qstr {
	const char *name;
} __attribute__((preserve_access_index));

struct dentry {
	struct qstr d_name;
} __attribute__((preserve_access_index));

struct path {
	struct dentry *dentry;
} __attribute__((preserve_access_index));

static __always_inline int read_file_name(const struct path *path, char *buf,
					  unsigned int len)
{
	const char *name;
	int err;

	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return -1;

	name = BPF_CORE_READ(path, dentry, d_name.name);
	err = bpf_probe_read_kernel_str(buf, len, name);
	if (err <= 0)
		return -1;

	return err;
}

static __always_inline int local_strncmp(const char *s1, const char *s2,
					 unsigned int sz)
{
	int ret = 0;
	unsigned int i;

	for (i = 0; i < sz; i++) {
		ret = s1[i] - s2[i];
		if (ret || !s1[i])
			break;
	}

	return ret;
}

SEC("kprobe/vfs_getattr")
int BPF_KPROBE(vfs_getattr_nocmp, const struct path *path)
{
	char buf[64] = {0};
	int err;

	err = read_file_name(path, buf, sizeof(buf));
	if (err < 0)
		return 0;

	if (buf[0] == '1')
		equal++;

	return 0;
}

SEC("kprobe/vfs_getattr")
int BPF_KPROBE(vfs_getattr_cmp, const struct path *path)
{
	char buf[64] = {0};
	int err;

	err = read_file_name(path, buf, sizeof(buf));
	if (err < 0)
		return 0;

	err = local_strncmp(TARGET_FILE_NAME, buf, sizeof(buf));
	if (!err)
		equal++;

	return 0;
}

SEC("kprobe/vfs_getattr")
int BPF_KPROBE(vfs_getattr_cmp_v2, const struct path *path)
{
	char buf[64] = {0};
	int err;

	err = read_file_name(path, buf, sizeof(buf));
	if (err < 0)
		return 0;

	err = bpf_strncmp(TARGET_FILE_NAME, buf, sizeof(buf));
	if (!err)
		equal++;

	return 0;
}
