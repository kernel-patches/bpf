// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf_sockopt_helpers.h>
#include "bpf_misc.h"

/*
 * Cgroup programs set return values via bpf_set_retval() helper.
 * The helper argument must be 0 (success) or negative errno.
 * Positive values bypass IS_ERR() check and can cause kernel issues.
 */

SEC("lsm_cgroup/socket_create")
__description("lsm_cgroup bpf_set_retval success")
__success
int BPF_PROG(lsm_cgroup_set_retval_zero_valid, int family, int type, int protocol, int kern)
{
	bpf_set_retval(0);
	return 0;
}

SEC("lsm_cgroup/socket_create")
__description("lsm_cgroup bpf_set_retval valid errno")
__success
int BPF_PROG(lsm_cgroup_set_retval_negative_valid, int family, int type, int protocol, int kern)
{
	bpf_set_retval(-12);
	return 0;
}

SEC("lsm_cgroup/socket_create")
__description("lsm_cgroup bpf_set_retval invalid negative value")
__failure __msg("should have been in [-4095, 0]")
int BPF_PROG(lsm_cgroup_set_retval_negative_invalid, int family, int type, int protocol, int kern)
{
	bpf_set_retval(-4096);
	return 0;
}

SEC("lsm_cgroup/socket_create")
__description("lsm_cgroup bpf_set_retval invalid positive value")
__failure __msg("should have been in [-4095, 0]")
int BPF_PROG(lsm_cgroup_set_retval_positive_invalid, int family, int type, int protocol, int kern)
{
	bpf_set_retval(1);
	return 0;
}

SEC("cgroup/dev")
__description("cgroup_device bpf_set_retval success")
__success
int cgroup_dev_set_retval_0(struct bpf_cgroup_dev_ctx *ctx)
{
	bpf_set_retval(0);
	return 1;
}

SEC("cgroup/dev")
__description("cgroup_device bpf_set_retval valid errno")
__success
int cgroup_dev_set_retval_neg_maxerrno(struct bpf_cgroup_dev_ctx *ctx)
{
	bpf_set_retval(-4095);
	return 1;
}

SEC("cgroup/dev")
__description("cgroup_device bpf_set_retval invalid positive value")
__failure __msg("should have been in [-4095, 0]")
int cgroup_dev_set_retval_1(struct bpf_cgroup_dev_ctx *ctx)
{
	bpf_set_retval(1);
	return 1;
}

SEC("cgroup/dev")
__description("cgroup_device bpf_set_retval invalid negative value")
__failure __msg("should have been in [-4095, 0]")
int cgroup_dev_set_retval_neg_4096(struct bpf_cgroup_dev_ctx *ctx)
{
	bpf_set_retval(-4096);
	return 1;
}

char _license[] SEC("license") = "GPL";
