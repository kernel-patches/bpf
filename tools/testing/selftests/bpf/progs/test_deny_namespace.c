// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <linux/capability.h>

struct kernel_cap_struct {
	__u32 cap[_LINUX_CAPABILITY_U32S_3];
} __attribute__((preserve_access_index));

struct cred {
	struct kernel_cap_struct cap_effective;
} __attribute__((preserve_access_index));

char _license[] SEC("license") = "GPL";

SEC("lsm/create_user_ns")
int BPF_PROG(test_create_user_ns, const struct cred *cred, int ret)
{
	struct kernel_cap_struct caps = cred->cap_effective;
	int cap_index = CAP_TO_INDEX(CAP_SYS_ADMIN);
	__u32 cap_mask = CAP_TO_MASK(CAP_SYS_ADMIN);

	if (ret)
		return 0;

	ret = -EPERM;
	if (caps.cap[cap_index] & cap_mask)
		return 0;

	return -EPERM;
}

SEC("lsm.s/create_user_ns")
int BPF_PROG(test_sleepable_create_user_ns, const struct cred *cred, int ret)
{
	return 0;
}
