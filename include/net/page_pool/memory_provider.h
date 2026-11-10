/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_PAGE_POOL_MEMORY_PROVIDER_H
#define _NET_PAGE_POOL_MEMORY_PROVIDER_H

#include <net/netmem.h>
#include <net/page_pool/types.h>

struct netdev_rx_queue;
struct netlink_ext_ack;
struct sk_buff;

/* Memory providers allocate underlying memory (struct net_iov or struct page),
 * cast it to netmem_ref, and supply it to page_pool. While current memory
 * providers only return struct net_iov, they are not architecturally limited to
 * net_iov; a provider returning page-backed netmems is allowed. New code must
 * not assume a memory provider implies net_iov and should, as much as possible,
 * generalize existing limitations to match the design principles.
 *
 * Per-provider custom logic must be delegated to memory_provider_ops rather
 * than handled directly in page_pool core code.
 */

/**
 * enum mp_caps - memory provider capabilities
 * @MP_CAP_READABLE: The CPU can access provider memory. It may back header
 *	page pools, and XDP programs may run on it.
 * @MP_CAP_FRAG: Page pool fragments may split provider buffers.
 * @MP_CAP_RETAIN: The stack may keep page pool references to provider
 *	buffers after the RX poll, for example in an skb or an xdp_frame.
 */
enum mp_caps {
	MP_CAP_READABLE		= BIT(0),
	MP_CAP_FRAG		= BIT(1),
	MP_CAP_RETAIN		= BIT(2),
};

struct memory_provider_ops {
	netmem_ref (*alloc_netmems)(struct page_pool *pool, gfp_t gfp);
	bool (*release_netmem)(struct page_pool *pool, netmem_ref netmem);
	int (*init)(struct page_pool *pool);
	void (*destroy)(struct page_pool *pool);
	int (*nl_fill)(void *mp_priv, struct sk_buff *rsp,
		       struct netdev_rx_queue *rxq);
	void (*uninstall)(void *mp_priv, struct netdev_rx_queue *rxq);
	u32 caps;
};

bool net_mp_niov_set_dma_addr(struct net_iov *niov, dma_addr_t addr);
void net_mp_niov_set_page_pool(struct page_pool *pool, struct net_iov *niov);
void net_mp_niov_clear_page_pool(struct net_iov *niov);

int netif_mp_open_rxq(struct net_device *dev, unsigned int rxq_idx,
		      const struct pp_memory_provider_params *p,
		      struct netlink_ext_ack *extack);
int netif_mp_close_rxq(struct net_device *dev, unsigned int rxq_idx,
		       const struct pp_memory_provider_params *old_p);
bool netif_all_mps_have_cap(struct net_device *dev, u32 cap);

/**
  * net_mp_netmem_place_in_cache() - give a netmem to a page pool
  * @pool:      the page pool to place the netmem into
  * @netmem:    netmem to give
  *
  * Push an accounted netmem into the page pool's allocation cache. The caller
  * must ensure that there is space in the cache. It should only be called off
  * the mp_ops->alloc_netmems() path.
  */
static inline void net_mp_netmem_place_in_cache(struct page_pool *pool,
						netmem_ref netmem)
{
	pool->alloc.cache[pool->alloc.count++] = netmem;
}

#endif
