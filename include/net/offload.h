/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_NET_OFFLOAD_H__
#define __LINUX_NET_OFFLOAD_H__

#include <linux/types.h>

#define XDP_METADATA_KFUNC_xxx	\
	NETDEV_METADATA_KFUNC(XDP_METADATA_KFUNC_RX_TIMESTAMP, \
			      bpf_xdp_metadata_rx_timestamp) \
	NETDEV_METADATA_KFUNC(XDP_METADATA_KFUNC_RX_HASH, \
			      bpf_xdp_metadata_rx_hash)

#define DEVTX_SB_KFUNC_xxx	\
	NETDEV_METADATA_KFUNC(DEVTX_SB_KFUNC_REQUEST_TIMESTAMP, \
			      bpf_devtx_sb_request_timestamp)

#define DEVTX_CP_KFUNC_xxx	\
	NETDEV_METADATA_KFUNC(DEVTX_CP_KFUNC_TIMESTAMP, \
			      bpf_devtx_cp_timestamp)

enum {
#define NETDEV_METADATA_KFUNC(name, _) name,
XDP_METADATA_KFUNC_xxx
DEVTX_SB_KFUNC_xxx
DEVTX_CP_KFUNC_xxx
#undef NETDEV_METADATA_KFUNC
MAX_NETDEV_METADATA_KFUNC,
};

#ifdef CONFIG_NET
u32 bpf_dev_bound_kfunc_id(int id);
bool bpf_is_dev_bound_kfunc(u32 btf_id);
#else
static inline u32 bpf_dev_bound_kfunc_id(int id) { return 0; }
static inline bool bpf_is_dev_bound_kfunc(u32 btf_id) { return false; }
#endif

#endif /* __LINUX_NET_OFFLOAD_H__ */
