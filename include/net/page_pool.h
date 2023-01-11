/* SPDX-License-Identifier: GPL-2.0
 *
 * page_pool.h
 *	Author:	Jesper Dangaard Brouer <netoptimizer@brouer.com>
 *	Copyright (C) 2016 Red Hat, Inc.
 */

/**
 * DOC: page_pool allocator
 *
 * This page_pool allocator is optimized for the XDP mode that
 * uses one-frame-per-page, but have fallbacks that act like the
 * regular page allocator APIs.
 *
 * Basic use involve replacing alloc_pages() calls with the
 * page_pool_alloc_netmem() call.  Drivers should likely use
 * page_pool_dev_alloc_pages() replacing dev_alloc_pages().
 *
 * API keeps track of in-flight pages, in-order to let API user know
 * when it is safe to dealloactor page_pool object.  Thus, API users
 * must make sure to call page_pool_release_netmem() when a page is
 * "leaving" the page_pool.  Or call page_pool_put_page() where
 * appropiate.  For maintaining correct accounting.
 *
 * API user must only call page_pool_put_page() once on a page, as it
 * will either recycle the page, or in case of elevated refcnt, it
 * will release the DMA mapping and in-flight state accounting.  We
 * hope to lift this requirement in the future.
 */
#ifndef _NET_PAGE_POOL_H
#define _NET_PAGE_POOL_H

#include <linux/mm.h> /* Needed by ptr_ring */
#include <linux/ptr_ring.h>
#include <linux/dma-direction.h>

#define PP_FLAG_DMA_MAP		BIT(0) /* Should page_pool do the DMA
					* map/unmap
					*/
#define PP_FLAG_DMA_SYNC_DEV	BIT(1) /* If set all pages that the driver gets
					* from page_pool will be
					* DMA-synced-for-device according to
					* the length provided by the device
					* driver.
					* Please note DMA-sync-for-CPU is still
					* device driver responsibility
					*/
#define PP_FLAG_PAGE_FRAG	BIT(2) /* for page frag feature */
#define PP_FLAG_ALL		(PP_FLAG_DMA_MAP |\
				 PP_FLAG_DMA_SYNC_DEV |\
				 PP_FLAG_PAGE_FRAG)

/**
 * struct netmem - A memory allocation from a &struct page_pool.
 * @flags: The same as the page flags.  Do not use directly.
 * @pp_magic: Magic value to avoid recycling non page_pool allocated pages.
 * @pp: The page pool this netmem was allocated from.
 * @dma_addr: Call netmem_get_dma_addr() to read this value.
 * @dma_addr_upper: Might need to be 64-bit on 32-bit architectures.
 * @pp_frag_count: For frag page support, not supported in 32-bit
 *   architectures with 64-bit DMA.
 * @_mapcount: Do not access this member directly.
 * @_refcount: Do not access this member directly.  Read it using
 *   netmem_ref_count() and manipulate it with netmem_get() and netmem_put().
 *
 * This struct overlays struct page for now.  Do not modify without a
 * good understanding of the issues.
 */
struct netmem {
	unsigned long flags;
	unsigned long pp_magic;
	struct page_pool *pp;
	/* private: no need to document this padding */
	unsigned long _pp_mapping_pad;	/* aliases with folio->mapping */
	/* public: */
	unsigned long dma_addr;
	union {
		unsigned long dma_addr_upper;
		atomic_long_t pp_frag_count;
	};
	atomic_t _mapcount;
	atomic_t _refcount;
};

#define NETMEM_MATCH(pg, nm)						\
	static_assert(offsetof(struct page, pg) == offsetof(struct netmem, nm))
NETMEM_MATCH(flags, flags);
NETMEM_MATCH(lru, pp_magic);
NETMEM_MATCH(mapping, _pp_mapping_pad);
NETMEM_MATCH(_mapcount, _mapcount);
NETMEM_MATCH(_refcount, _refcount);
#undef NETMEM_MATCH
static_assert(sizeof(struct netmem) <= sizeof(struct page));

#define netmem_page(nmem) (_Generic((nmem),				\
	const struct netmem *:	(const struct page *)nmem,		\
	struct netmem *:	(struct page *)nmem))

static inline struct netmem *page_netmem(struct page *page)
{
	VM_BUG_ON_PAGE(PageTail(page), page);
	return (struct netmem *)page;
}

static inline unsigned long netmem_pfn(const struct netmem *nmem)
{
	return page_to_pfn(netmem_page(nmem));
}

static inline unsigned long netmem_nid(const struct netmem *nmem)
{
	return page_to_nid(netmem_page(nmem));
}

static inline struct netmem *virt_to_netmem(const void *x)
{
	return page_netmem(virt_to_head_page(x));
}

static inline void *netmem_to_virt(const struct netmem *nmem)
{
	return page_to_virt(netmem_page(nmem));
}

static inline void *netmem_address(const struct netmem *nmem)
{
	return page_address(netmem_page(nmem));
}

static inline int netmem_ref_count(const struct netmem *nmem)
{
	return page_ref_count(netmem_page(nmem));
}

static inline void netmem_get(struct netmem *nmem)
{
	struct folio *folio = (struct folio *)nmem;

	folio_get(folio);
}

static inline void netmem_put(struct netmem *nmem)
{
	struct folio *folio = (struct folio *)nmem;

	folio_put(folio);
}

static inline bool netmem_is_pfmemalloc(const struct netmem *nmem)
{
	return nmem->pp_magic & BIT(1);
}

/*
 * Fast allocation side cache array/stack
 *
 * The cache size and refill watermark is related to the network
 * use-case.  The NAPI budget is 64 packets.  After a NAPI poll the RX
 * ring is usually refilled and the max consumed elements will be 64,
 * thus a natural max size of objects needed in the cache.
 *
 * Keeping room for more objects, is due to XDP_DROP use-case.  As
 * XDP_DROP allows the opportunity to recycle objects directly into
 * this array, as it shares the same softirq/NAPI protection.  If
 * cache is already full (or partly full) then the XDP_DROP recycles
 * would have to take a slower code path.
 */
#define PP_ALLOC_CACHE_SIZE	128
#define PP_ALLOC_CACHE_REFILL	64
struct pp_alloc_cache {
	u32 count;
	struct netmem *cache[PP_ALLOC_CACHE_SIZE];
};

struct page_pool_params {
	unsigned int	flags;
	unsigned int	order;
	unsigned int	pool_size;
	int		nid;  /* Numa node id to allocate from pages from */
	struct device	*dev; /* device, for DMA pre-mapping purposes */
	enum dma_data_direction dma_dir; /* DMA mapping direction */
	unsigned int	max_len; /* max DMA sync memory size */
	unsigned int	offset;  /* DMA addr offset */
	void (*init_callback)(struct page *page, void *arg);
	void *init_arg;
};

#ifdef CONFIG_PAGE_POOL_STATS
struct page_pool_alloc_stats {
	u64 fast; /* fast path allocations */
	u64 slow; /* slow-path order 0 allocations */
	u64 slow_high_order; /* slow-path high order allocations */
	u64 empty; /* failed refills due to empty ptr ring, forcing
		    * slow path allocation
		    */
	u64 refill; /* allocations via successful refill */
	u64 waive;  /* failed refills due to numa zone mismatch */
};

struct page_pool_recycle_stats {
	u64 cached;	/* recycling placed page in the cache. */
	u64 cache_full; /* cache was full */
	u64 ring;	/* recycling placed page back into ptr ring */
	u64 ring_full;	/* page was released from page-pool because
			 * PTR ring was full.
			 */
	u64 released_refcnt; /* page released because of elevated
			      * refcnt
			      */
};

/* This struct wraps the above stats structs so users of the
 * page_pool_get_stats API can pass a single argument when requesting the
 * stats for the page pool.
 */
struct page_pool_stats {
	struct page_pool_alloc_stats alloc_stats;
	struct page_pool_recycle_stats recycle_stats;
};

int page_pool_ethtool_stats_get_count(void);
u8 *page_pool_ethtool_stats_get_strings(u8 *data);
u64 *page_pool_ethtool_stats_get(u64 *data, void *stats);

/*
 * Drivers that wish to harvest page pool stats and report them to users
 * (perhaps via ethtool, debugfs, or another mechanism) can allocate a
 * struct page_pool_stats call page_pool_get_stats to get stats for the specified pool.
 */
bool page_pool_get_stats(struct page_pool *pool,
			 struct page_pool_stats *stats);
#else

static inline int page_pool_ethtool_stats_get_count(void)
{
	return 0;
}

static inline u8 *page_pool_ethtool_stats_get_strings(u8 *data)
{
	return data;
}

static inline u64 *page_pool_ethtool_stats_get(u64 *data, void *stats)
{
	return data;
}

#endif

struct page_pool {
	struct page_pool_params p;

	struct delayed_work release_dw;
	void (*disconnect)(void *);
	unsigned long defer_start;
	unsigned long defer_warn;

	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct netmem *frag_nmem;
	long frag_users;

#ifdef CONFIG_PAGE_POOL_STATS
	/* these stats are incremented while in softirq context */
	struct page_pool_alloc_stats alloc_stats;
#endif
	u32 xdp_mem_id;

	/*
	 * Data structure for allocation side
	 *
	 * Drivers allocation side usually already perform some kind
	 * of resource protection.  Piggyback on this protection, and
	 * require driver to protect allocation side.
	 *
	 * For NIC drivers this means, allocate a page_pool per
	 * RX-queue. As the RX-queue is already protected by
	 * Softirq/BH scheduling and napi_schedule. NAPI schedule
	 * guarantee that a single napi_struct will only be scheduled
	 * on a single CPU (see napi_schedule).
	 */
	struct pp_alloc_cache alloc ____cacheline_aligned_in_smp;

	/* Data structure for storing recycled pages.
	 *
	 * Returning/freeing pages is more complicated synchronization
	 * wise, because free's can happen on remote CPUs, with no
	 * association with allocation resource.
	 *
	 * Use ptr_ring, as it separates consumer and producer
	 * effeciently, it a way that doesn't bounce cache-lines.
	 *
	 * TODO: Implement bulk return pages into this structure.
	 */
	struct ptr_ring ring;

#ifdef CONFIG_PAGE_POOL_STATS
	/* recycle stats are per-cpu to avoid locking */
	struct page_pool_recycle_stats __percpu *recycle_stats;
#endif
	atomic_t pages_state_release_cnt;

	/* A page_pool is strictly tied to a single RX-queue being
	 * protected by NAPI, due to above pp_alloc_cache. This
	 * refcnt serves purpose is to simplify drivers error handling.
	 */
	refcount_t user_cnt;

	u64 destroy_cnt;
};

struct netmem *page_pool_alloc_netmem(struct page_pool *pool, gfp_t gfp);

static inline struct netmem *page_pool_dev_alloc_netmem(struct page_pool *pool)
{
	return page_pool_alloc_netmem(pool, GFP_ATOMIC | __GFP_NOWARN);
}

/* Compat, remove when all users gone */
static inline
struct page *page_pool_alloc_pages(struct page_pool *pool, gfp_t gfp)
{
	return netmem_page(page_pool_alloc_netmem(pool, gfp));
}

static inline struct page *page_pool_dev_alloc_pages(struct page_pool *pool)
{
	gfp_t gfp = (GFP_ATOMIC | __GFP_NOWARN);

	return page_pool_alloc_pages(pool, gfp);
}

struct netmem *page_pool_alloc_frag(struct page_pool *pool,
		unsigned int *offset, unsigned int size, gfp_t gfp);

static inline struct page *page_pool_dev_alloc_frag(struct page_pool *pool,
						    unsigned int *offset,
						    unsigned int size)
{
	gfp_t gfp = (GFP_ATOMIC | __GFP_NOWARN);

	return netmem_page(page_pool_alloc_frag(pool, offset, size, gfp));
}

/* get the stored dma direction. A driver might decide to treat this locally and
 * avoid the extra cache line from page_pool to determine the direction
 */
static
inline enum dma_data_direction page_pool_get_dma_dir(struct page_pool *pool)
{
	return pool->p.dma_dir;
}

bool page_pool_return_skb_page(struct page *page);

struct page_pool *page_pool_create(const struct page_pool_params *params);

struct xdp_mem_info;

#ifdef CONFIG_PAGE_POOL
void page_pool_destroy(struct page_pool *pool);
void page_pool_use_xdp_mem(struct page_pool *pool, void (*disconnect)(void *),
			   struct xdp_mem_info *mem);
void page_pool_release_netmem(struct page_pool *pool, struct netmem *nmem);
void page_pool_put_page_bulk(struct page_pool *pool, void **data,
			     int count);
#else
static inline void page_pool_destroy(struct page_pool *pool)
{
}

static inline void page_pool_use_xdp_mem(struct page_pool *pool,
					 void (*disconnect)(void *),
					 struct xdp_mem_info *mem)
{
}
static inline void page_pool_release_netmem(struct page_pool *pool,
					  struct netmem *nmem)
{
}

static inline void page_pool_put_page_bulk(struct page_pool *pool, void **data,
					   int count)
{
}
#endif

/* Compat, remove when all users gone */
static inline void page_pool_release_page(struct page_pool *pool,
					struct page *page)
{
	page_pool_release_netmem(pool, page_netmem(page));
}

void page_pool_put_defragged_netmem(struct page_pool *pool, struct netmem *nmem,
				  unsigned int dma_sync_size,
				  bool allow_direct);

static inline void page_pool_fragment_netmem(struct netmem *nmem, long nr)
{
	atomic_long_set(&nmem->pp_frag_count, nr);
}

static inline long page_pool_defrag_netmem(struct netmem *nmem, long nr)
{
	long ret;

	/* If nr == pp_frag_count then we have cleared all remaining
	 * references to the page. No need to actually overwrite it, instead
	 * we can leave this to be overwritten by the calling function.
	 *
	 * The main advantage to doing this is that an atomic_read is
	 * generally a much cheaper operation than an atomic update,
	 * especially when dealing with a page that may be partitioned
	 * into only 2 or 3 pieces.
	 */
	if (atomic_long_read(&nmem->pp_frag_count) == nr)
		return 0;

	ret = atomic_long_sub_return(nr, &nmem->pp_frag_count);
	WARN_ON(ret < 0);
	return ret;
}

static inline bool page_pool_is_last_frag(struct page_pool *pool,
					  struct netmem *nmem)
{
	/* If fragments aren't enabled or count is 0 we were the last user */
	return !(pool->p.flags & PP_FLAG_PAGE_FRAG) ||
	       (page_pool_defrag_netmem(nmem, 1) == 0);
}

static inline void page_pool_put_netmem(struct page_pool *pool,
				      struct netmem *nmem,
				      unsigned int dma_sync_size,
				      bool allow_direct)
{
	/* When page_pool isn't compiled-in, net/core/xdp.c doesn't
	 * allow registering MEM_TYPE_PAGE_POOL, but shield linker.
	 */
#ifdef CONFIG_PAGE_POOL
	if (!page_pool_is_last_frag(pool, nmem))
		return;

	page_pool_put_defragged_netmem(pool, nmem, dma_sync_size, allow_direct);
#endif
}

/* Compat, remove when all users gone */
static inline void page_pool_put_page(struct page_pool *pool,
				      struct page *page,
				      unsigned int dma_sync_size,
				      bool allow_direct)
{
	page_pool_put_netmem(pool, page_netmem(page), dma_sync_size,
				allow_direct);
}

/* Same as above but will try to sync the entire area pool->max_len */
static inline void page_pool_put_full_netmem(struct page_pool *pool,
		struct netmem *nmem, bool allow_direct)
{
	page_pool_put_netmem(pool, nmem, -1, allow_direct);
}

/* Compat, remove when all users gone */
static inline void page_pool_put_full_page(struct page_pool *pool,
					   struct page *page, bool allow_direct)
{
	page_pool_put_full_netmem(pool, page_netmem(page), allow_direct);
}

/* Same as above but the caller must guarantee safe context. e.g NAPI */
static inline void __page_pool_recycle_direct(struct page_pool *pool,
					    struct netmem *nmem)
{
	page_pool_put_full_netmem(pool, nmem, true);
}

static inline void __page_pool_recycle_page_direct(struct page_pool *pool,
					    struct page *page)
{
	page_pool_put_full_netmem(pool, page_netmem(page), true);
}

#define page_pool_recycle_direct(pool, mem)	_Generic((mem),		\
	struct netmem *: __page_pool_recycle_direct(pool, (struct netmem *)mem),		\
	struct page *:	 __page_pool_recycle_page_direct(pool, (struct page *)mem))

#define PAGE_POOL_DMA_USE_PP_FRAG_COUNT	\
		(sizeof(dma_addr_t) > sizeof(unsigned long))

static inline dma_addr_t netmem_get_dma_addr(struct netmem *nmem)
{
	dma_addr_t ret = nmem->dma_addr;

	if (PAGE_POOL_DMA_USE_PP_FRAG_COUNT)
		ret |= (dma_addr_t)nmem->dma_addr_upper << 16 << 16;

	return ret;
}

/* Compat, remove when all users gone */
static inline dma_addr_t page_pool_get_dma_addr(struct page *page)
{
	return netmem_get_dma_addr(page_netmem(page));
}

static inline void netmem_set_dma_addr(struct netmem *nmem, dma_addr_t addr)
{
	nmem->dma_addr = addr;
	if (PAGE_POOL_DMA_USE_PP_FRAG_COUNT)
		nmem->dma_addr_upper = upper_32_bits(addr);
}

/* Compat, remove when all users gone */
static inline void page_pool_set_dma_addr(struct page *page, dma_addr_t addr)
{
	netmem_set_dma_addr(page_netmem(page), addr);
}

static inline bool is_page_pool_compiled_in(void)
{
#ifdef CONFIG_PAGE_POOL
	return true;
#else
	return false;
#endif
}

static inline bool page_pool_put(struct page_pool *pool)
{
	return refcount_dec_and_test(&pool->user_cnt);
}

/* Caller must provide appropriate safe context, e.g. NAPI. */
void page_pool_update_nid(struct page_pool *pool, int new_nid);
static inline void page_pool_nid_changed(struct page_pool *pool, int new_nid)
{
	if (unlikely(pool->p.nid != new_nid))
		page_pool_update_nid(pool, new_nid);
}

static inline void page_pool_ring_lock(struct page_pool *pool)
	__acquires(&pool->ring.producer_lock)
{
	if (in_serving_softirq())
		spin_lock(&pool->ring.producer_lock);
	else
		spin_lock_bh(&pool->ring.producer_lock);
}

static inline void page_pool_ring_unlock(struct page_pool *pool)
	__releases(&pool->ring.producer_lock)
{
	if (in_serving_softirq())
		spin_unlock(&pool->ring.producer_lock);
	else
		spin_unlock_bh(&pool->ring.producer_lock);
}

#endif /* _NET_PAGE_POOL_H */
