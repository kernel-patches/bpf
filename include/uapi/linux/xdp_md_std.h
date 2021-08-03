#ifndef _UAPI_LINUX_XDP_MD_STD_H
#define _UAPI_LINUX_XDP_MD_STD_H

#include <linux/types.h>

#define XDP_METADATA_USER_TX_TIMESTAMP 0x1

struct xdp_user_tx_metadata {
	__u64 timestamp;
	__u32 md_valid;
	__u32 btf_id;
};

#endif /* _UAPI_LINUX_XDP_MD_STD_H */
