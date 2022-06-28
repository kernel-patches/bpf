// SPDX-License-Identifier: GPL-2.0-only

#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <net/xdp_sock.h>
#include <trace/events/xdp.h>

BPF_CALL_1(bpf_xdp_get_buff_len, struct  xdp_buff*, xdp)
{
	return xdp_get_buff_len(xdp);
}

static const struct bpf_func_proto bpf_xdp_get_buff_len_proto = {
	.func		= bpf_xdp_get_buff_len,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

BTF_ID_LIST_SINGLE(bpf_xdp_get_buff_len_bpf_ids, struct, xdp_buff)

const struct bpf_func_proto bpf_xdp_get_buff_len_trace_proto = {
	.func		= bpf_xdp_get_buff_len,
	.gpl_only	= false,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_xdp_get_buff_len_bpf_ids[0],
};

static unsigned long xdp_get_metalen(const struct xdp_buff *xdp)
{
	return xdp_data_meta_unsupported(xdp) ? 0 :
	       xdp->data - xdp->data_meta;
}

BPF_CALL_2(bpf_xdp_adjust_head, struct xdp_buff *, xdp, int, offset)
{
	void *xdp_frame_end = xdp->data_hard_start + sizeof(struct xdp_frame);
	unsigned long metalen = xdp_get_metalen(xdp);
	void *data_start = xdp_frame_end + metalen;
	void *data = xdp->data + offset;

	if (unlikely(data < data_start ||
		     data > xdp->data_end - ETH_HLEN))
		return -EINVAL;

	if (metalen)
		memmove(xdp->data_meta + offset,
			xdp->data_meta, metalen);
	xdp->data_meta += offset;
	xdp->data = data;

	return 0;
}

static const struct bpf_func_proto bpf_xdp_adjust_head_proto = {
	.func		= bpf_xdp_adjust_head,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

static void bpf_xdp_copy_buf(struct xdp_buff *xdp, unsigned long off,
			     void *buf, unsigned long len, bool flush)
{
	unsigned long ptr_len, ptr_off = 0;
	skb_frag_t *next_frag, *end_frag;
	struct skb_shared_info *sinfo;
	void *src, *dst;
	u8 *ptr_buf;

	if (likely(xdp->data_end - xdp->data >= off + len)) {
		src = flush ? buf : xdp->data + off;
		dst = flush ? xdp->data + off : buf;
		memcpy(dst, src, len);
		return;
	}

	sinfo = xdp_get_shared_info_from_buff(xdp);
	end_frag = &sinfo->frags[sinfo->nr_frags];
	next_frag = &sinfo->frags[0];

	ptr_len = xdp->data_end - xdp->data;
	ptr_buf = xdp->data;

	while (true) {
		if (off < ptr_off + ptr_len) {
			unsigned long copy_off = off - ptr_off;
			unsigned long copy_len = min(len, ptr_len - copy_off);

			src = flush ? buf : ptr_buf + copy_off;
			dst = flush ? ptr_buf + copy_off : buf;
			memcpy(dst, src, copy_len);

			off += copy_len;
			len -= copy_len;
			buf += copy_len;
		}

		if (!len || next_frag == end_frag)
			break;

		ptr_off += ptr_len;
		ptr_buf = skb_frag_address(next_frag);
		ptr_len = skb_frag_size(next_frag);
		next_frag++;
	}
}

static void *bpf_xdp_pointer(struct xdp_buff *xdp, u32 offset, u32 len)
{
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);
	u32 size = xdp->data_end - xdp->data;
	void *addr = xdp->data;
	int i;

	if (unlikely(offset > 0xffff || len > 0xffff))
		return ERR_PTR(-EFAULT);

	if (offset + len > xdp_get_buff_len(xdp))
		return ERR_PTR(-EINVAL);

	if (offset < size) /* linear area */
		goto out;

	offset -= size;
	for (i = 0; i < sinfo->nr_frags; i++) { /* paged area */
		u32 frag_size = skb_frag_size(&sinfo->frags[i]);

		if  (offset < frag_size) {
			addr = skb_frag_address(&sinfo->frags[i]);
			size = frag_size;
			break;
		}
		offset -= frag_size;
	}
out:
	return offset + len < size ? addr + offset : NULL;
}

BPF_CALL_4(bpf_xdp_load_bytes, struct xdp_buff *, xdp, u32, offset,
	   void *, buf, u32, len)
{
	void *ptr;

	ptr = bpf_xdp_pointer(xdp, offset, len);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	if (!ptr)
		bpf_xdp_copy_buf(xdp, offset, buf, len, false);
	else
		memcpy(buf, ptr, len);

	return 0;
}

static const struct bpf_func_proto bpf_xdp_load_bytes_proto = {
	.func		= bpf_xdp_load_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

BPF_CALL_4(bpf_xdp_store_bytes, struct xdp_buff *, xdp, u32, offset,
	   void *, buf, u32, len)
{
	void *ptr;

	ptr = bpf_xdp_pointer(xdp, offset, len);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	if (!ptr)
		bpf_xdp_copy_buf(xdp, offset, buf, len, true);
	else
		memcpy(ptr, buf, len);

	return 0;
}

static const struct bpf_func_proto bpf_xdp_store_bytes_proto = {
	.func		= bpf_xdp_store_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

static int bpf_xdp_frags_increase_tail(struct xdp_buff *xdp, int offset)
{
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);
	skb_frag_t *frag = &sinfo->frags[sinfo->nr_frags - 1];
	struct xdp_rxq_info *rxq = xdp->rxq;
	unsigned int tailroom;

	if (!rxq->frag_size || rxq->frag_size > xdp->frame_sz)
		return -EOPNOTSUPP;

	tailroom = rxq->frag_size - skb_frag_size(frag) - skb_frag_off(frag);
	if (unlikely(offset > tailroom))
		return -EINVAL;

	memset(skb_frag_address(frag) + skb_frag_size(frag), 0, offset);
	skb_frag_size_add(frag, offset);
	sinfo->xdp_frags_size += offset;

	return 0;
}

static int bpf_xdp_frags_shrink_tail(struct xdp_buff *xdp, int offset)
{
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);
	int i, n_frags_free = 0, len_free = 0;

	if (unlikely(offset > (int)xdp_get_buff_len(xdp) - ETH_HLEN))
		return -EINVAL;

	for (i = sinfo->nr_frags - 1; i >= 0 && offset > 0; i--) {
		skb_frag_t *frag = &sinfo->frags[i];
		int shrink = min_t(int, offset, skb_frag_size(frag));

		len_free += shrink;
		offset -= shrink;

		if (skb_frag_size(frag) == shrink) {
			struct page *page = skb_frag_page(frag);

			__xdp_return(page_address(page), &xdp->rxq->mem,
				     false, NULL);
			n_frags_free++;
		} else {
			skb_frag_size_sub(frag, shrink);
			break;
		}
	}
	sinfo->nr_frags -= n_frags_free;
	sinfo->xdp_frags_size -= len_free;

	if (unlikely(!sinfo->nr_frags)) {
		xdp_buff_clear_frags_flag(xdp);
		xdp->data_end -= offset;
	}

	return 0;
}

BPF_CALL_2(bpf_xdp_adjust_tail, struct xdp_buff *, xdp, int, offset)
{
	void *data_hard_end = xdp_data_hard_end(xdp); /* use xdp->frame_sz */
	void *data_end = xdp->data_end + offset;

	if (unlikely(xdp_buff_has_frags(xdp))) { /* non-linear xdp buff */
		if (offset < 0)
			return bpf_xdp_frags_shrink_tail(xdp, -offset);

		return bpf_xdp_frags_increase_tail(xdp, offset);
	}

	/* Notice that xdp_data_hard_end have reserved some tailroom */
	if (unlikely(data_end > data_hard_end))
		return -EINVAL;

	/* ALL drivers MUST init xdp->frame_sz, chicken check below */
	if (unlikely(xdp->frame_sz > PAGE_SIZE)) {
		WARN_ONCE(1, "Too BIG xdp->frame_sz = %d\n", xdp->frame_sz);
		return -EINVAL;
	}

	if (unlikely(data_end < xdp->data + ETH_HLEN))
		return -EINVAL;

	/* Clear memory area on grow, can contain uninit kernel memory */
	if (offset > 0)
		memset(xdp->data_end, 0, offset);

	xdp->data_end = data_end;

	return 0;
}

static const struct bpf_func_proto bpf_xdp_adjust_tail_proto = {
	.func		= bpf_xdp_adjust_tail,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_xdp_adjust_meta, struct xdp_buff *, xdp, int, offset)
{
	void *xdp_frame_end = xdp->data_hard_start + sizeof(struct xdp_frame);
	void *meta = xdp->data_meta + offset;
	unsigned long metalen = xdp->data - meta;

	if (xdp_data_meta_unsupported(xdp))
		return -ENOTSUPP;
	if (unlikely(meta < xdp_frame_end ||
		     meta > xdp->data))
		return -EINVAL;
	if (unlikely(xdp_metalen_invalid(metalen)))
		return -EACCES;

	xdp->data_meta = meta;

	return 0;
}

static const struct bpf_func_proto bpf_xdp_adjust_meta_proto = {
	.func		= bpf_xdp_adjust_meta,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* XDP_REDIRECT works by a three-step process, implemented in the functions
 * below:
 *
 * 1. The bpf_redirect() and bpf_redirect_map() helpers will lookup the target
 *    of the redirect and store it (along with some other metadata) in a per-CPU
 *    struct bpf_redirect_info.
 *
 * 2. When the program returns the XDP_REDIRECT return code, the driver will
 *    call xdp_do_redirect() which will use the information in struct
 *    bpf_redirect_info to actually enqueue the frame into a map type-specific
 *    bulk queue structure.
 *
 * 3. Before exiting its NAPI poll loop, the driver will call xdp_do_flush(),
 *    which will flush all the different bulk queues, thus completing the
 *    redirect.
 *
 * Pointers to the map entries will be kept around for this whole sequence of
 * steps, protected by RCU. However, there is no top-level rcu_read_lock() in
 * the core code; instead, the RCU protection relies on everything happening
 * inside a single NAPI poll sequence, which means it's between a pair of calls
 * to local_bh_disable()/local_bh_enable().
 *
 * The map entries are marked as __rcu and the map code makes sure to
 * dereference those pointers with rcu_dereference_check() in a way that works
 * for both sections that to hold an rcu_read_lock() and sections that are
 * called from NAPI without a separate rcu_read_lock(). The code below does not
 * use RCU annotations, but relies on those in the map code.
 */
void xdp_do_flush(void)
{
	__dev_flush();
	__cpu_map_flush();
	__xsk_map_flush();
}
EXPORT_SYMBOL_GPL(xdp_do_flush);

void bpf_clear_redirect_map(struct bpf_map *map)
{
	struct bpf_redirect_info *ri;
	int cpu;

	for_each_possible_cpu(cpu) {
		ri = per_cpu_ptr(&bpf_redirect_info, cpu);
		/* Avoid polluting remote cacheline due to writes if
		 * not needed. Once we pass this test, we need the
		 * cmpxchg() to make sure it hasn't been changed in
		 * the meantime by remote CPU.
		 */
		if (unlikely(READ_ONCE(ri->map) == map))
			cmpxchg(&ri->map, map, NULL);
	}
}

DEFINE_STATIC_KEY_FALSE(bpf_master_redirect_enabled_key);
EXPORT_SYMBOL_GPL(bpf_master_redirect_enabled_key);

u32 xdp_master_redirect(struct xdp_buff *xdp)
{
	struct net_device *master, *slave;
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);

	master = netdev_master_upper_dev_get_rcu(xdp->rxq->dev);
	slave = master->netdev_ops->ndo_xdp_get_xmit_slave(master, xdp);
	if (slave && slave != xdp->rxq->dev) {
		/* The target device is different from the receiving device, so
		 * redirect it to the new device.
		 * Using XDP_REDIRECT gets the correct behaviour from XDP enabled
		 * drivers to unmap the packet from their rx ring.
		 */
		ri->tgt_index = slave->ifindex;
		ri->map_id = INT_MAX;
		ri->map_type = BPF_MAP_TYPE_UNSPEC;
		return XDP_REDIRECT;
	}
	return XDP_TX;
}
EXPORT_SYMBOL_GPL(xdp_master_redirect);

static inline int __xdp_do_redirect_xsk(struct bpf_redirect_info *ri,
					struct net_device *dev,
					struct xdp_buff *xdp,
					struct bpf_prog *xdp_prog)
{
	enum bpf_map_type map_type = ri->map_type;
	void *fwd = ri->tgt_value;
	u32 map_id = ri->map_id;
	int err;

	ri->map_id = 0; /* Valid map id idr range: [1,INT_MAX[ */
	ri->map_type = BPF_MAP_TYPE_UNSPEC;

	err = __xsk_map_redirect(fwd, xdp);
	if (unlikely(err))
		goto err;

	_trace_xdp_redirect_map(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index);
	return 0;
err:
	_trace_xdp_redirect_map_err(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index, err);
	return err;
}

static __always_inline int __xdp_do_redirect_frame(struct bpf_redirect_info *ri,
						   struct net_device *dev,
						   struct xdp_frame *xdpf,
						   struct bpf_prog *xdp_prog)
{
	enum bpf_map_type map_type = ri->map_type;
	void *fwd = ri->tgt_value;
	u32 map_id = ri->map_id;
	struct bpf_map *map;
	int err;

	ri->map_id = 0; /* Valid map id idr range: [1,INT_MAX[ */
	ri->map_type = BPF_MAP_TYPE_UNSPEC;

	if (unlikely(!xdpf)) {
		err = -EOVERFLOW;
		goto err;
	}

	switch (map_type) {
	case BPF_MAP_TYPE_DEVMAP:
		fallthrough;
	case BPF_MAP_TYPE_DEVMAP_HASH:
		map = READ_ONCE(ri->map);
		if (unlikely(map)) {
			WRITE_ONCE(ri->map, NULL);
			err = dev_map_enqueue_multi(xdpf, dev, map,
						    ri->flags & BPF_F_EXCLUDE_INGRESS);
		} else {
			err = dev_map_enqueue(fwd, xdpf, dev);
		}
		break;
	case BPF_MAP_TYPE_CPUMAP:
		err = cpu_map_enqueue(fwd, xdpf, dev);
		break;
	case BPF_MAP_TYPE_UNSPEC:
		if (map_id == INT_MAX) {
			fwd = dev_get_by_index_rcu(dev_net(dev), ri->tgt_index);
			if (unlikely(!fwd)) {
				err = -EINVAL;
				break;
			}
			err = dev_xdp_enqueue(fwd, xdpf, dev);
			break;
		}
		fallthrough;
	default:
		err = -EBADRQC;
	}

	if (unlikely(err))
		goto err;

	_trace_xdp_redirect_map(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index);
	return 0;
err:
	_trace_xdp_redirect_map_err(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index, err);
	return err;
}

int xdp_do_redirect(struct net_device *dev, struct xdp_buff *xdp,
		    struct bpf_prog *xdp_prog)
{
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
	enum bpf_map_type map_type = ri->map_type;

	/* XDP_REDIRECT is not fully supported yet for xdp frags since
	 * not all XDP capable drivers can map non-linear xdp_frame in
	 * ndo_xdp_xmit.
	 */
	if (unlikely(xdp_buff_has_frags(xdp) &&
		     map_type != BPF_MAP_TYPE_CPUMAP))
		return -EOPNOTSUPP;

	if (map_type == BPF_MAP_TYPE_XSKMAP)
		return __xdp_do_redirect_xsk(ri, dev, xdp, xdp_prog);

	return __xdp_do_redirect_frame(ri, dev, xdp_convert_buff_to_frame(xdp),
				       xdp_prog);
}
EXPORT_SYMBOL_GPL(xdp_do_redirect);

int xdp_do_redirect_frame(struct net_device *dev, struct xdp_buff *xdp,
			  struct xdp_frame *xdpf, struct bpf_prog *xdp_prog)
{
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
	enum bpf_map_type map_type = ri->map_type;

	if (map_type == BPF_MAP_TYPE_XSKMAP)
		return __xdp_do_redirect_xsk(ri, dev, xdp, xdp_prog);

	return __xdp_do_redirect_frame(ri, dev, xdpf, xdp_prog);
}
EXPORT_SYMBOL_GPL(xdp_do_redirect_frame);

static int xdp_do_generic_redirect_map(struct net_device *dev,
				       struct sk_buff *skb,
				       struct xdp_buff *xdp,
				       struct bpf_prog *xdp_prog,
				       void *fwd,
				       enum bpf_map_type map_type, u32 map_id)
{
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
	struct bpf_map *map;
	int err;

	switch (map_type) {
	case BPF_MAP_TYPE_DEVMAP:
		fallthrough;
	case BPF_MAP_TYPE_DEVMAP_HASH:
		map = READ_ONCE(ri->map);
		if (unlikely(map)) {
			WRITE_ONCE(ri->map, NULL);
			err = dev_map_redirect_multi(dev, skb, xdp_prog, map,
						     ri->flags & BPF_F_EXCLUDE_INGRESS);
		} else {
			err = dev_map_generic_redirect(fwd, skb, xdp_prog);
		}
		if (unlikely(err))
			goto err;
		break;
	case BPF_MAP_TYPE_XSKMAP:
		err = xsk_generic_rcv(fwd, xdp);
		if (err)
			goto err;
		consume_skb(skb);
		break;
	case BPF_MAP_TYPE_CPUMAP:
		err = cpu_map_generic_redirect(fwd, skb);
		if (unlikely(err))
			goto err;
		break;
	default:
		err = -EBADRQC;
		goto err;
	}

	_trace_xdp_redirect_map(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index);
	return 0;
err:
	_trace_xdp_redirect_map_err(dev, xdp_prog, fwd, map_type, map_id, ri->tgt_index, err);
	return err;
}

int xdp_do_generic_redirect(struct net_device *dev, struct sk_buff *skb,
			    struct xdp_buff *xdp, struct bpf_prog *xdp_prog)
{
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);
	enum bpf_map_type map_type = ri->map_type;
	void *fwd = ri->tgt_value;
	u32 map_id = ri->map_id;
	int err;

	ri->map_id = 0; /* Valid map id idr range: [1,INT_MAX[ */
	ri->map_type = BPF_MAP_TYPE_UNSPEC;

	if (map_type == BPF_MAP_TYPE_UNSPEC && map_id == INT_MAX) {
		fwd = dev_get_by_index_rcu(dev_net(dev), ri->tgt_index);
		if (unlikely(!fwd)) {
			err = -EINVAL;
			goto err;
		}

		err = xdp_ok_fwd_dev(fwd, skb->len);
		if (unlikely(err))
			goto err;

		skb->dev = fwd;
		_trace_xdp_redirect(dev, xdp_prog, ri->tgt_index);
		generic_xdp_tx(skb, xdp_prog);
		return 0;
	}

	return xdp_do_generic_redirect_map(dev, skb, xdp, xdp_prog, fwd, map_type, map_id);
err:
	_trace_xdp_redirect_err(dev, xdp_prog, ri->tgt_index, err);
	return err;
}

BPF_CALL_2(bpf_xdp_redirect, u32, ifindex, u64, flags)
{
	struct bpf_redirect_info *ri = this_cpu_ptr(&bpf_redirect_info);

	if (unlikely(flags))
		return XDP_ABORTED;

	/* NB! Map type UNSPEC and map_id == INT_MAX (never generated
	 * by map_idr) is used for ifindex based XDP redirect.
	 */
	ri->tgt_index = ifindex;
	ri->map_id = INT_MAX;
	ri->map_type = BPF_MAP_TYPE_UNSPEC;

	return XDP_REDIRECT;
}

static const struct bpf_func_proto bpf_xdp_redirect_proto = {
	.func           = bpf_xdp_redirect,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_ANYTHING,
	.arg2_type      = ARG_ANYTHING,
};

BPF_CALL_3(bpf_xdp_redirect_map, struct bpf_map *, map, u32, ifindex,
	   u64, flags)
{
	return map->ops->map_redirect(map, ifindex, flags);
}

static const struct bpf_func_proto bpf_xdp_redirect_map_proto = {
	.func           = bpf_xdp_redirect_map,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_CONST_MAP_PTR,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_ANYTHING,
};


static unsigned long bpf_xdp_copy(void *dst, const void *ctx,
				  unsigned long off, unsigned long len)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;

	bpf_xdp_copy_buf(xdp, off, dst, len, false);
	return 0;
}

BPF_CALL_5(bpf_xdp_event_output, struct xdp_buff *, xdp, struct bpf_map *, map,
	   u64, flags, void *, meta, u64, meta_size)
{
	u64 xdp_size = (flags & BPF_F_CTXLEN_MASK) >> 32;

	if (unlikely(flags & ~(BPF_F_CTXLEN_MASK | BPF_F_INDEX_MASK)))
		return -EINVAL;

	if (unlikely(!xdp || xdp_size > xdp_get_buff_len(xdp)))
		return -EFAULT;

	return bpf_event_output(map, flags, meta, meta_size, xdp,
				xdp_size, bpf_xdp_copy);
}

static const struct bpf_func_proto bpf_xdp_event_output_proto = {
	.func		= bpf_xdp_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

BTF_ID_LIST_SINGLE(bpf_xdp_output_btf_ids, struct, xdp_buff)

const struct bpf_func_proto bpf_xdp_output_proto = {
	.func		= bpf_xdp_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_xdp_output_btf_ids[0],
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

#ifdef CONFIG_INET
bool bpf_xdp_sock_is_valid_access(int off, int size, enum bpf_access_type type,
				  struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= offsetofend(struct bpf_xdp_sock, queue_id))
		return false;

	if (off % size != 0)
		return false;

	switch (off) {
	default:
		return size == sizeof(__u32);
	}
}

u32 bpf_xdp_sock_convert_ctx_access(enum bpf_access_type type,
				    const struct bpf_insn *si,
				    struct bpf_insn *insn_buf,
				    struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

#define BPF_XDP_SOCK_GET(FIELD)						\
	do {								\
		BUILD_BUG_ON(sizeof_field(struct xdp_sock, FIELD) >	\
			     sizeof_field(struct bpf_xdp_sock, FIELD));	\
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_sock, FIELD),\
				      si->dst_reg, si->src_reg,		\
				      offsetof(struct xdp_sock, FIELD)); \
	} while (0)

	switch (si->off) {
	case offsetof(struct bpf_xdp_sock, queue_id):
		BPF_XDP_SOCK_GET(queue_id);
		break;
	}

	return insn - insn_buf;
}
#endif /* CONFIG_INET */

static int xdp_noop_prologue(struct bpf_insn *insn_buf, bool direct_write,
			     const struct bpf_prog *prog)
{
	/* Neither direct read nor direct write requires any preliminary
	 * action.
	 */
	return 0;
}

static bool __is_valid_xdp_access(int off, int size)
{
	if (off < 0 || off >= sizeof(struct xdp_md))
		return false;
	if (off % size != 0)
		return false;
	if (size != sizeof(__u32))
		return false;

	return true;
}

static bool xdp_is_valid_access(int off, int size,
				enum bpf_access_type type,
				const struct bpf_prog *prog,
				struct bpf_insn_access_aux *info)
{
	if (prog->expected_attach_type != BPF_XDP_DEVMAP) {
		switch (off) {
		case offsetof(struct xdp_md, egress_ifindex):
			return false;
		}
	}

	if (type == BPF_WRITE) {
		if (bpf_prog_is_dev_bound(prog->aux)) {
			switch (off) {
			case offsetof(struct xdp_md, rx_queue_index):
				return __is_valid_xdp_access(off, size);
			}
		}
		return false;
	}

	switch (off) {
	case offsetof(struct xdp_md, data):
		info->reg_type = PTR_TO_PACKET;
		break;
	case offsetof(struct xdp_md, data_meta):
		info->reg_type = PTR_TO_PACKET_META;
		break;
	case offsetof(struct xdp_md, data_end):
		info->reg_type = PTR_TO_PACKET_END;
		break;
	}

	return __is_valid_xdp_access(off, size);
}

void bpf_warn_invalid_xdp_action(struct net_device *dev, struct bpf_prog *prog, u32 act)
{
	const u32 act_max = XDP_REDIRECT;

	pr_warn_once("%s XDP return value %u on prog %s (id %d) dev %s, expect packet loss!\n",
		     act > act_max ? "Illegal" : "Driver unsupported",
		     act, prog->aux->name, prog->aux->id, dev ? dev->name : "N/A");
}
EXPORT_SYMBOL_GPL(bpf_warn_invalid_xdp_action);

static u32 xdp_convert_ctx_access(enum bpf_access_type type,
				  const struct bpf_insn *si,
				  struct bpf_insn *insn_buf,
				  struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct xdp_md, data):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, data),
				      si->dst_reg, si->src_reg,
				      offsetof(struct xdp_buff, data));
		break;
	case offsetof(struct xdp_md, data_meta):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, data_meta),
				      si->dst_reg, si->src_reg,
				      offsetof(struct xdp_buff, data_meta));
		break;
	case offsetof(struct xdp_md, data_end):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, data_end),
				      si->dst_reg, si->src_reg,
				      offsetof(struct xdp_buff, data_end));
		break;
	case offsetof(struct xdp_md, ingress_ifindex):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, rxq),
				      si->dst_reg, si->src_reg,
				      offsetof(struct xdp_buff, rxq));
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_rxq_info, dev),
				      si->dst_reg, si->dst_reg,
				      offsetof(struct xdp_rxq_info, dev));
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
				      offsetof(struct net_device, ifindex));
		break;
	case offsetof(struct xdp_md, rx_queue_index):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, rxq),
				      si->dst_reg, si->src_reg,
				      offsetof(struct xdp_buff, rxq));
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
				      offsetof(struct xdp_rxq_info,
					       queue_index));
		break;
	case offsetof(struct xdp_md, egress_ifindex):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_buff, txq),
				      si->dst_reg, si->src_reg,
				      offsetof(struct xdp_buff, txq));
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct xdp_txq_info, dev),
				      si->dst_reg, si->dst_reg,
				      offsetof(struct xdp_txq_info, dev));
		*insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->dst_reg,
				      offsetof(struct net_device, ifindex));
		break;
	}

	return insn - insn_buf;
}

bool xdp_helper_changes_pkt_data(const void *func)
{
	return func == bpf_xdp_adjust_head ||
	       func == bpf_xdp_adjust_meta ||
	       func == bpf_xdp_adjust_tail;
}

static const struct bpf_func_proto *
xdp_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_perf_event_output:
		return &bpf_xdp_event_output_proto;
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_smp_processor_id_proto;
	case BPF_FUNC_xdp_adjust_head:
		return &bpf_xdp_adjust_head_proto;
	case BPF_FUNC_xdp_adjust_meta:
		return &bpf_xdp_adjust_meta_proto;
	case BPF_FUNC_redirect:
		return &bpf_xdp_redirect_proto;
	case BPF_FUNC_redirect_map:
		return &bpf_xdp_redirect_map_proto;
	case BPF_FUNC_xdp_adjust_tail:
		return &bpf_xdp_adjust_tail_proto;
	case BPF_FUNC_xdp_get_buff_len:
		return &bpf_xdp_get_buff_len_proto;
	case BPF_FUNC_xdp_load_bytes:
		return &bpf_xdp_load_bytes_proto;
	case BPF_FUNC_xdp_store_bytes:
		return &bpf_xdp_store_bytes_proto;
	default:
		return xdp_inet_func_proto(func_id);
	}
}

const struct bpf_verifier_ops xdp_verifier_ops = {
	.get_func_proto		= xdp_func_proto,
	.is_valid_access	= xdp_is_valid_access,
	.convert_ctx_access	= xdp_convert_ctx_access,
	.gen_prologue		= xdp_noop_prologue,
};

const struct bpf_prog_ops xdp_prog_ops = {
	.test_run		= bpf_prog_test_run_xdp,
};

DEFINE_BPF_DISPATCHER(xdp)

void bpf_prog_change_xdp(struct bpf_prog *prev_prog, struct bpf_prog *prog)
{
	bpf_dispatcher_change_prog(BPF_DISPATCHER_PTR(xdp), prev_prog, prog);
}
