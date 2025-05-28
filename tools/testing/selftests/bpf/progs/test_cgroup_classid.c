// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

int classid;

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
	/* expecte real classid */
	classid = bpf_get_cgroup_classid(skb);
	return TCX_PASS;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb)
{
	/* expecte 0 */
	classid = bpf_get_cgroup_classid(skb);
	return TCX_PASS;
}

SEC("cgroup/dev")
int cg_dev(struct bpf_cgroup_dev_ctx *ctx)
{
	/* expecte real classid */
	classid = bpf_get_cgroup_classid((struct __sk_buff *)ctx);
	/* Allow all */
	return 1;
}

SEC("cgroup/sysctl")
int sysctl_tcp_mem(struct bpf_sysctl *ctx)
{
	/* expecte real classid */
	classid = bpf_get_cgroup_classid((struct __sk_buff *)ctx);
	return 1;
}

SEC("cgroup/getsockopt")
int cg_getsockopt(struct bpf_sockopt *ctx)
{
	/* expecte real classid */
	classid = bpf_get_cgroup_classid((struct __sk_buff *)ctx);
	return 1;
}

char _license[] SEC("license") = "GPL";
