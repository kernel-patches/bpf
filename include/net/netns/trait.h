/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Traits registered to a network namespace.
 */

#ifndef __NETNS_TRAIT_H__
#define __NETNS_TRAIT_H__

#include <linux/types.h>
#include <linux/bpf.h>

struct registered_trait {
	bool used;
	char name[BPF_OBJ_NAME_LEN];
	u32 flags;
};

struct netns_traits {
	struct registered_trait traits[64];
};

#endif /* __NETNS_TRAIT_H__ */
