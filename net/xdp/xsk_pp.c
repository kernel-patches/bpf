// SPDX-License-Identifier: GPL-2.0
/* AF_XDP UMEM as a page pool memory provider
 *
 * Each aligned UMEM chunk is a readable net_iov with one owner at a time:
 *
 *   userspace --FILL--> page pool --release--> reuse --alloc--> page pool
 *       ^                   |
 *       +-----RX ring-------+
 */

#include <net/netdev_lock.h>
#include <net/netdev_queues.h>
#include <net/netdev_rx_queue.h>
#include <net/page_pool/helpers.h>
#include <net/page_pool/memory_provider.h>
#include <net/xdp_sock_drv.h>

#include "xsk.h"
#include "xsk_queue.h"

#define XSK_PP_DMA_ATTR	(DMA_ATTR_WEAK_ORDERING | DMA_ATTR_SKIP_CPU_SYNC)

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
	/* RX queue of the provider, NULL once it is removed */
	struct netdev_rx_queue __rcu *rxq;
	bool starved;
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

static bool xsk_pp_wake(struct xsk_pp *pp)
{
	struct netdev_rx_queue *rxq;
	bool running = false;

	rcu_read_lock();
	rxq = rcu_dereference(pp->rxq);
	if (rxq)
		running = netif_mp_wake(rxq);
	rcu_read_unlock();

	return running;
}

int xsk_pp_wakeup(struct xsk_pp *pp)
{
	return xsk_pp_wake(pp) ? 0 : -ENETDOWN;
}

static bool xsk_pp_release_netmem(struct page_pool *pool, netmem_ref netmem)
{
	struct net_iov *niov = netmem_to_net_iov(netmem);
	struct xsk_pp *pp = pool->mp_priv;
	u32 idx = net_iov_idx(niov);
	bool starved;

	spin_lock_bh(&pp->lock);
	net_mp_niov_clear_page_pool(niov);
	if (!WARN_ON_ONCE(pp->state[idx] != XSK_PP_POOL ||
			  pp->reuse_cnt == pp->area.num_niovs)) {
		pp->state[idx] = XSK_PP_REUSE;
		pp->reuse[pp->reuse_cnt++] = idx;
	}
	starved = pp->starved;
	WRITE_ONCE(pp->starved, false);
	spin_unlock_bh(&pp->lock);

	/* A starved queue may wait for this release */
	if (starved)
		xsk_pp_wake(pp);

	return false;
}

static bool xsk_pp_refill_done(struct page_pool *pool, enum pp_refill state)
{
	struct xsk_pp *pp = pool->mp_priv;
	struct xsk_buff_pool *xp = pp->pool;
	bool wait = xp->uses_need_wakeup;
	bool more;

	if (state == PP_REFILL_FULL && !READ_ONCE(pp->starved))
		return true;

	spin_lock_bh(&pp->lock);
	if (!pp->fq) {
		spin_unlock_bh(&pp->lock);
		return true;
	}

	if (state == PP_REFILL_FULL) {
		WRITE_ONCE(pp->starved, false);
		spin_unlock_bh(&pp->lock);
		return true;
	}

	/* With need_wakeup, userspace wakes the queue after it posts FILL */
	more = pp->reuse_cnt || xskq_cons_nb_entries(pp->fq, 1);
	WRITE_ONCE(pp->starved, !more);
	spin_unlock_bh(&pp->lock);

	return !more && wait;
}

static int xsk_pp_nl_fill(void *mp_priv, struct sk_buff *rsp,
			  struct netdev_rx_queue *rxq)
{
	return 0;
}

/* The queue no longer uses the provider, and its DMA stopped */
static void xsk_pp_detach(struct xsk_pp *pp)
{
	RCU_INIT_POINTER(pp->rxq, NULL);
	spin_lock_bh(&pp->lock);
	pp->fq = NULL;
	spin_unlock_bh(&pp->lock);
	/* Wait for wakeups that found the queue */
	synchronize_net();
	xp_dma_unmap(pp->pool, XSK_PP_DMA_ATTR);
}

/* The device unregisters, and is closed */
static void xsk_pp_uninstall(void *mp_priv, struct netdev_rx_queue *rxq)
{
	xsk_pp_detach(mp_priv);
}

const struct memory_provider_ops xsk_pp_ops = {
	.init		= xsk_pp_init,
	.destroy	= xsk_pp_destroy,
	.alloc_netmems	= xsk_pp_alloc_netmems,
	.release_netmem	= xsk_pp_release_netmem,
	.nl_fill	= xsk_pp_nl_fill,
	.uninstall	= xsk_pp_uninstall,
	.refill_done	= xsk_pp_refill_done,
	.caps		= MP_CAP_READABLE,
};

static bool xsk_pp_abandon(struct xsk_pp *pp)
{
	struct xsk_buff_pool *pool = pp->pool;
	bool busy;
	u32 idx;

	spin_lock_bh(&pp->lock);
	busy = pp->nr_pools;
	while (!busy && pp->reuse_cnt) {
		idx = pp->reuse[--pp->reuse_cnt];
		pp->state[idx] = XSK_PP_USER;
		xp_free(&pool->heads[idx]);
	}
	spin_unlock_bh(&pp->lock);

	return !busy;
}

static int xsk_pp_validate(struct net_device *dev, struct xsk_buff_pool *pool,
			   unsigned int mtu, struct bpf_prog *prog,
			   struct netlink_ext_ack *extack)
{
	struct xsk_rx_check check = {
		.buf_size = pool->chunk_size,
		.headroom = xsk_pool_get_headroom(pool),
		.mtu = mtu,
		.sg = xsk_pool_uses_sg(pool),
		.prog = prog,
	};
	struct netdev_bpf bpf = {
		.command = XDP_VALIDATE_XSK_POOL,
		.xsk_check.check = &check,
		.xsk_check.extack = extack,
	};

	return dev->netdev_ops->ndo_bpf(dev, &bpf);
}

/**
 * xsk_validate_dev - check AF_XDP page pool queues against a new setting
 * @dev: device of the queues
 * @mtu: MTU to check
 * @prog: XDP program to check, or NULL for the current one
 * @mode: XDP mode of @prog
 * @extack: netlink extended ack
 *
 * Context: holds the instance lock of @dev, or RTNL for a device without it.
 * Return: 0 if the driver accepts all queues of @dev that have an AF_XDP
 * memory provider, or its error.
 */
int xsk_validate_dev(struct net_device *dev, unsigned int mtu,
		     struct bpf_prog *prog, enum bpf_xdp_mode mode,
		     struct netlink_ext_ack *extack)
{
	struct netdev_rx_queue *rxq;
	struct xsk_pp *pp;
	unsigned int i;
	int err;

	netdev_assert_locked_ops_compat(dev);

	for (i = 0; i < dev->real_num_rx_queues; i++) {
		rxq = __netif_get_rx_queue(dev, i);
		if (rxq->mp_params.mp_ops != &xsk_pp_ops)
			continue;

		/* Generic XDP runs outside the queue NAPI */
		if (mode == XDP_MODE_SKB) {
			NL_SET_ERR_MSG(extack,
				       "generic XDP cannot feed an AF_XDP page pool socket");
			return -EBUSY;
		}

		pp = rxq->mp_params.mp_priv;
		err = xsk_pp_validate(dev, pp->pool, mtu, prog, extack);
		if (err)
			return err;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(xsk_validate_dev);

/**
 * xsk_rxq_pool - get the AF_XDP pool that provides memory to an RX queue
 * @dev: device of the queue
 * @queue_id: RX queue
 *
 * The pool stays valid while the queue that the caller allocates runs.
 *
 * Context: holds the instance lock of @dev.
 * Return: the buffer pool, or NULL.
 */
struct xsk_buff_pool *xsk_rxq_pool(struct net_device *dev, u16 queue_id)
{
	struct netdev_rx_queue *rxq;
	struct xsk_pp *pp;

	netdev_assert_locked(dev);

	if (queue_id >= dev->real_num_rx_queues)
		return NULL;

	rxq = __netif_get_rx_queue(dev, queue_id);
	if (rxq->mp_params.mp_ops != &xsk_pp_ops)
		return NULL;

	pp = rxq->mp_params.mp_priv;
	return pp->pool;
}
EXPORT_SYMBOL_GPL(xsk_rxq_pool);

bool xsk_pp_supported(struct net_device *dev)
{
	const struct netdev_queue_mgmt_ops *qops = dev->queue_mgmt_ops;

	return qops && qops->xsk_page_pool;
}

/* Called with RTNL and the instance lock of @dev. On error, @pool->pp stays
 * set if an old page pool still owns chunks; copy mode must not take the pool.
 */
int xsk_pp_bind(struct xsk_buff_pool *pool, struct net_device *dev,
		u16 queue_id)
{
	struct pp_memory_provider_params mp = { .mp_ops = &xsk_pp_ops };
	struct device *dma_dev;
	struct xsk_pp *pp;
	int err;

	if (queue_id >= dev->real_num_rx_queues || pool->unaligned)
		return -EOPNOTSUPP;
	if ((dev->xdp_features & NETDEV_XDP_ACT_XSK) != NETDEV_XDP_ACT_XSK ||
	    (xsk_pool_uses_sg(pool) && dev->xdp_zc_max_segs == 1))
		return -EOPNOTSUPP;
	if (dev_xdp_prog_id(dev, XDP_MODE_SKB))
		return -EOPNOTSUPP;
	if (!netif_all_mps_have_cap(dev, MP_CAP_READABLE))
		return -EBUSY;

	err = xsk_pp_validate(dev, pool, dev->mtu, NULL, NULL);
	if (err)
		return err;

	dma_dev = netdev_queue_get_dma_dev(dev, queue_id, NETDEV_QUEUE_TYPE_RX);
	if (!dma_dev)
		return -EOPNOTSUPP;

	err = xp_dma_map(pool, dma_dev, XSK_PP_DMA_ATTR, pool->umem->pgs,
			 pool->umem->npgs);
	if (err)
		return err;

	pp = xsk_pp_create(pool);
	if (IS_ERR(pp)) {
		xp_dma_unmap(pool, XSK_PP_DMA_ATTR);
		return PTR_ERR(pp);
	}

	rcu_assign_pointer(pp->rxq, __netif_get_rx_queue(dev, queue_id));
	mp.mp_priv = pp;
	mp.rx_page_size = pool->chunk_size;
	mp.rx_headroom = xsk_pool_get_headroom(pool);
	err = netif_mp_open_rxq(dev, queue_id, &mp, NULL);
	if (!err) {
		pool->pp = pp;
		pool->xdp_zc_max_segs = dev->xdp_zc_max_segs;
		/* See xsk_pp_refill_done() */
		if (pool->uses_need_wakeup)
			xsk_set_rx_need_wakeup(pool);
		return 0;
	}

	RCU_INIT_POINTER(pp->rxq, NULL);
	synchronize_net();
	xp_dma_unmap(pool, XSK_PP_DMA_ATTR);
	/* Copy mode takes the chunks that the provider holds */
	if (!xp_alloc_heads(pool) && xsk_pp_abandon(pp))
		xsk_pp_put(pp);
	else
		pool->pp = pp;

	return err;
}

/* Called with RTNL and the instance lock of the device */
void xsk_pp_unbind(struct xsk_buff_pool *pool)
{
	struct xsk_pp *pp = pool->pp;
	struct pp_memory_provider_params mp = {
		.mp_ops = &xsk_pp_ops,
		.mp_priv = pp,
	};

	/* Unregister removed the provider already */
	if (!rcu_access_pointer(pp->rxq))
		return;

	netif_mp_close_rxq(pool->netdev, pool->queue_id, &mp);
	xsk_pp_detach(pp);
}
