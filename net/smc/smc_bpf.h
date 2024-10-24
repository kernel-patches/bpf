/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  support for eBPF programs in SMC subsystem.
 *
 *  Copyright IBM Corp. 2016
 *  Copyright (c) 2024, Alibaba Inc.
 *
 *  Author: D. Wythe <alibuda@linux.alibaba.com>
 */
#ifndef __SMC_BPF
#define __SMC_BPF

#include <linux/types.h>
#include <net/sock.h>
#include <net/tcp.h>

#if IS_ENABLED(CONFIG_SMC_BPF)

/* Initialize struct_ops registration. It will automatically unload
 * when module is unloaded.
 * @return 0 on success
 */
int smc_bpf_struct_ops_init(void);

void bpf_smc_set_tcp_option(struct tcp_sock *sk);
void bpf_smc_set_tcp_option_cond(const struct tcp_sock *tp, struct inet_request_sock *ireq);

#else
static inline int smc_bpf_struct_ops_init(void) { return 0; }
#endif /* CONFIG_SMC_BPF */

#endif /* __SMC_BPF */
