// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

SEC("fmod_ret/security_task_alloc")
__success
int BPF_PROG(fmod_task_alloc_1)
{
	return -1;
}

SEC("fmod_ret/security_task_alloc")
__failure __log_level(2)
__msg("At program exit the register R0 has smin=1 smax=1 should have been in [-4095, 0]")
int BPF_PROG(fmod_task_alloc_2)
{
	return 1;
}

SEC("fmod_ret/" SYS_PREFIX "sys_open")
__failure __log_level(2)
__msg("At program exit the register R0 has smin=0 smax=0 should have been in [-4095, -1]")
int BPF_PROG(fmod_ret_sys_open_1)
{
	return 0;
}

SEC("fmod_ret/" SYS_PREFIX "sys_open")
__failure __log_level(2)
__msg("At program exit the register R0 has smin=1 smax=1 should have been in [-4095, -1]")
int BPF_PROG(fmod_ret_sys_open_2)
{
	return 1;
}

SEC("fmod_ret/" SYS_PREFIX "sys_open")
__success
int BPF_PROG(fmod_ret_sys_open_3)
{
	return -1;
}

SEC("fmod_ret/page_pool_alloc_netmems")
__failure __log_level(2)
__msg("At program exit the register R0 has smin=1 smax=1 should have been in [0, 0]")
int BPF_PROG(fmod_page_pool_alloc_netmems_1)
{
	return 1;
}

SEC("fmod_ret/page_pool_alloc_netmems")
__success
int BPF_PROG(fmod_page_pool_alloc_netmems_2)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
