// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

/* int socket_create(int family, int type, int protocol, int kern) */
struct socket_create_args {
	__bpf_func_args_marker;
	/* out of order */
	int kern;
	int protocol;
	int ret __bpf_func_ret;
	int family;
	/* added: no such parameter */
	long added;
	/* missing: type isn't described */
} __bpf_func_args;

int lc_calls, lc_family = -1, lc_protocol = -1, lc_kern = -1;
int lc_ret_exists = -1, lc_added_exists = -1;

SEC("lsm_cgroup/socket_create")
int socket_create_struct(struct socket_create_args *args)
{
	if (args->family != 1 /* AF_UNIX */)
		return 1;

	lc_calls++;
	lc_family = args->family;
	lc_protocol = args->protocol;
	lc_kern = args->kern;
	lc_ret_exists = bpf_core_field_exists(args->ret);
	lc_added_exists = bpf_core_field_exists(args->added);
	/* allow */
	return 1;
}
