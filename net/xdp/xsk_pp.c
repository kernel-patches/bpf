// SPDX-License-Identifier: GPL-2.0
/* AF_XDP UMEM as a page pool memory provider
 *
 * Each aligned UMEM chunk is a readable net_iov with one owner at a time:
 *
 *   userspace --FILL--> page pool --release--> reuse --alloc--> page pool
 *       ^                   |
 *       +-----RX ring-------+
 */

#include <net/page_pool/helpers.h>
#include <net/page_pool/memory_provider.h>
#include <net/xdp_sock_drv.h>

#include "xsk.h"
#include "xsk_queue.h"

enum xsk_pp_chunk {
	XSK_PP_USER,	/* owned by userspace */
	XSK_PP_POOL,	/* owned by a page pool */
	XSK_PP_REUSE,	/* on the reuse stack */
};

struct xsk_pp {
	struct net_iov_area area;
	struct xsk_buff_pool *pool;
	/* Protects fq, state and reuse */
	spinlock_t lock;
	struct xsk_queue *fq;
	refcount_t refs;
	u32 nr_pools;
	bool dma_need_sync;
	u8 *state;
	u32 reuse_cnt;
	u32 reuse[];
};

static void xsk_pp_free(struct xsk_pp *pp)
{
	kvfree(pp->state);
	kvfree(pp->area.niovs);
	kvfree(pp);
}

void xsk_pp_put(struct xsk_pp *pp)
{
	if (refcount_dec_and_test(&pp->refs))
		xsk_pp_free(pp);
}

/* @pool must be DMA mapped and have aligned chunks. The provider must be
 * the only consumer of its FILL ring.
 */
struct xsk_pp *xsk_pp_create(struct xsk_buff_pool *pool)
{
	struct net_iov *niov;
	struct xsk_pp *pp;
	dma_addr_t dma;
	u32 i;

	pp = kvzalloc_flex(*pp, reuse, pool->heads_cnt, GFP_KERNEL_ACCOUNT);
	if (!pp)
		return ERR_PTR(-ENOMEM);

	pp->area.niovs = kvzalloc_objs(*pp->area.niovs, pool->heads_cnt,
				       GFP_KERNEL_ACCOUNT);
	pp->state = kvzalloc(pool->heads_cnt, GFP_KERNEL_ACCOUNT);
	if (!pp->area.niovs || !pp->state) {
		xsk_pp_free(pp);
		return ERR_PTR(-ENOMEM);
	}

	pp->area.num_niovs = pool->heads_cnt;
	pp->area.niov_shift = pool->chunk_shift;
	pp->area.vaddr = pool->addrs;
	pp->pool = pool;
	pp->fq = pool->fq;
	pp->dma_need_sync = dma_dev_need_sync(pool->dev);
	spin_lock_init(&pp->lock);
	refcount_set(&pp->refs, 1);

	for (i = 0; i < pp->area.num_niovs; i++) {
		niov = &pp->area.niovs[i];
		dma = xp_raw_get_dma(pool, (u64)i << pool->chunk_shift);
		net_iov_init(niov, &pp->area, NET_IOV_XSK);
		if (net_mp_niov_set_dma_addr(niov, dma)) {
			xsk_pp_free(pp);
			return ERR_PTR(-ERANGE);
		}
	}

	return pp;
}

static int xsk_pp_init(struct page_pool *pool)
{
	struct xsk_pp *pp = pool->mp_priv;

	if (pool->p.order || pool->p.dma_dir != DMA_BIDIRECTIONAL ||
	    pool->p.dev != pp->pool->dev)
		return -EINVAL;
	if (pool->p.max_len > pp->pool->chunk_size ||
	    pool->p.offset > pp->pool->chunk_size - pool->p.max_len)
		return -EINVAL;

	refcount_inc(&pp->refs);
	spin_lock_bh(&pp->lock);
	pp->nr_pools++;
	spin_unlock_bh(&pp->lock);
	return 0;
}

static void xsk_pp_destroy(struct page_pool *pool)
{
	struct xsk_pp *pp = pool->mp_priv;

	spin_lock_bh(&pp->lock);
	pp->nr_pools--;
	spin_unlock_bh(&pp->lock);
	xsk_pp_put(pp);
}

static bool xsk_pp_claim(struct xsk_pp *pp, u32 idx, enum xsk_pp_chunk from)
{
	lockdep_assert_held(&pp->lock);

	if (pp->state[idx] != from)
		return false;

	pp->state[idx] = XSK_PP_POOL;
	return true;
}

static u32 xsk_pp_alloc_reuse(struct xsk_pp *pp, netmem_ref *netmems, u32 max)
{
	u32 idx, n = 0;

	while (n < max && pp->reuse_cnt) {
		idx = pp->reuse[--pp->reuse_cnt];
		if (WARN_ON_ONCE(!xsk_pp_claim(pp, idx, XSK_PP_REUSE)))
			continue;
		netmems[n++] = net_iov_to_netmem(&pp->area.niovs[idx]);
	}

	return n;
}

static u32 xsk_pp_alloc_fill(struct xsk_pp *pp, netmem_ref *netmems, u32 max)
{
	struct xsk_buff_pool *pool = pp->pool;
	struct xsk_queue *fq = pp->fq;
	u32 i, entries, cons, idx, n = 0;
	u64 addr;

	if (!fq || !max)
		return 0;

	entries = xskq_cons_nb_entries(fq, max);
	if (!entries) {
		fq->queue_empty_descs++;
		return 0;
	}

	cons = fq->cached_cons;
	for (i = 0; i < entries; i++) {
		__xskq_cons_read_addr_unchecked(fq, cons++, &addr);
		addr &= pool->chunk_mask;
		idx = addr >> pp->area.niov_shift;
		if (unlikely(addr >= pool->addrs_cnt ||
			     !xsk_pp_claim(pp, idx, XSK_PP_USER))) {
			fq->invalid_descs++;
			continue;
		}
		netmems[n++] = net_iov_to_netmem(&pp->area.niovs[idx]);
	}

	xskq_cons_release_n(fq, entries);
	__xskq_cons_release(fq);
	return n;
}

static netmem_ref xsk_pp_alloc_netmems(struct page_pool *pool, gfp_t gfp)
{
	netmem_ref *netmems = pool->alloc.cache;
	struct xsk_pp *pp = pool->mp_priv;
	struct net_iov *niov;
	dma_addr_t dma;
	u32 i, n;

	if (WARN_ON_ONCE(pool->alloc.count))
		return 0;

	spin_lock_bh(&pp->lock);
	n = xsk_pp_alloc_reuse(pp, netmems, PP_ALLOC_CACHE_REFILL);
	n += xsk_pp_alloc_fill(pp, netmems + n, PP_ALLOC_CACHE_REFILL - n);
	spin_unlock_bh(&pp->lock);
	if (!n)
		return 0;

	for (i = 0; i < n; i++) {
		niov = netmem_to_net_iov(netmems[i]);
		dma = page_pool_get_dma_addr_netmem(netmems[i]);
		if (pp->dma_need_sync)
			dma_sync_single_range_for_device(pool->p.dev, dma,
							 pool->p.offset,
							 pool->p.max_len,
							 pool->p.dma_dir);
		net_mp_niov_set_page_pool(pool, niov);
	}

	pool->alloc.count = n - 1;
	return netmems[n - 1];
}

static bool xsk_pp_release_netmem(struct page_pool *pool, netmem_ref netmem)
{
	struct net_iov *niov = netmem_to_net_iov(netmem);
	struct xsk_pp *pp = pool->mp_priv;
	u32 idx = net_iov_idx(niov);

	spin_lock_bh(&pp->lock);
	net_mp_niov_clear_page_pool(niov);
	if (!WARN_ON_ONCE(pp->state[idx] != XSK_PP_POOL ||
			  pp->reuse_cnt == pp->area.num_niovs)) {
		pp->state[idx] = XSK_PP_REUSE;
		pp->reuse[pp->reuse_cnt++] = idx;
	}
	spin_unlock_bh(&pp->lock);

	return false;
}

static int xsk_pp_nl_fill(void *mp_priv, struct sk_buff *rsp,
			  struct netdev_rx_queue *rxq)
{
	return 0;
}

const struct memory_provider_ops xsk_pp_ops = {
	.init		= xsk_pp_init,
	.destroy	= xsk_pp_destroy,
	.alloc_netmems	= xsk_pp_alloc_netmems,
	.release_netmem	= xsk_pp_release_netmem,
	.nl_fill	= xsk_pp_nl_fill,
	.caps		= MP_CAP_READABLE,
};
