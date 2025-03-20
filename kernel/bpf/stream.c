// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/percpu.h>
#include <linux/refcount.h>
#include <linux/gfp.h>
#include <linux/memory.h>
#include <linux/local_lock.h>

/*
 * Simple per-CPU NMI-safe bump allocation mechanism, backed by the NMI-safe
 * try_alloc_pages()/free_pages_nolock() primitives. We allocate a page and
 * stash it in a local per-CPU variable, and bump allocate from the page
 * whenever items need to be printed to a stream. Each page holds a global
 * atomic refcount in its first 4 bytes, and then records of variable length
 * that describe the printed messages. Once the global refcount has dropped to
 * zero, it is a signal to free the page back to the kernel's page allocator,
 * given all the individual records in it have been consumed.
 *
 * It is possible the same page is used to serve allocations across different
 * programs, which may be consumed at different times individually, hence
 * maintaining a reference count per-page is critical for correct lifetime
 * tracking.
 *
 * Ideally, we'd have a kmalloc() equivalent that just allowed allocating items
 * of different sizes directly leading to less fragmentation overall. Let's use
 * this scheme until support for that arrives, and when we cannot capture memory
 * from bpf_mem_alloc() reserves.
 */

struct bpf_stream_page {
	refcount_t ref;
	u32 consumed;
	char buf[];
};

/* Available room to add data to a refcounted page. */
#define BPF_STREAM_PAGE_SZ (PAGE_SIZE - offsetofend(struct bpf_stream_page, consumed))

static DEFINE_PER_CPU(local_trylock_t, stream_local_lock) = INIT_LOCAL_TRYLOCK(stream_local_lock);
static DEFINE_PER_CPU(struct bpf_stream_page *, stream_pcpu_page);

static bool bpf_stream_page_local_lock(unsigned long *flags)
{
	return local_trylock_irqsave(&stream_local_lock, *flags);
}

static void bpf_stream_page_local_unlock(unsigned long *flags)
{
	local_unlock_irqrestore(&stream_local_lock, *flags);
}

static void bpf_stream_page_free(struct bpf_stream_page *stream_page)
{
	struct page *p;

	if (!stream_page)
		return;
	p = virt_to_page(stream_page);
	free_pages_nolock(p, 0);
}

static void bpf_stream_page_get(struct bpf_stream_page *stream_page)
{
	refcount_inc(&stream_page->ref);
}

static void bpf_stream_page_put(struct bpf_stream_page *stream_page)
{
	if (refcount_dec_and_test(&stream_page->ref))
		bpf_stream_page_free(stream_page);
}

static void bpf_stream_page_init(struct bpf_stream_page *stream_page)
{
	refcount_set(&stream_page->ref, 1);
	stream_page->consumed = 0;
}

static struct bpf_stream_page *bpf_stream_page_replace(void)
{
	struct bpf_stream_page *stream_page, *old_stream_page;
	struct page *page;

	page = __bpf_alloc_page(NUMA_NO_NODE);
	if (!page)
		return NULL;
	stream_page = page_address(page);
	bpf_stream_page_init(stream_page);

	old_stream_page = this_cpu_read(stream_pcpu_page);
	if (old_stream_page)
		bpf_stream_page_put(old_stream_page);
	this_cpu_write(stream_pcpu_page, stream_page);
	return stream_page;
}

static int bpf_stream_page_check_room(struct bpf_stream_page *stream_page, int len)
{
	int min = offsetof(struct bpf_stream_elem, str[0]);
	int consumed = stream_page->consumed;
	int total = BPF_STREAM_PAGE_SZ;
	int rem = max(0, total - consumed - min);

	/* Let's give room of at least 8 bytes. */
	WARN_ON_ONCE(rem % 8 != 0);
	return rem < 8 ? 0 : rem;
}

static void bpf_stream_elem_init(struct bpf_stream_elem *elem, int len)
{
	init_llist_node(&elem->node);
	elem->mem_slice.ptr = elem->str;
	elem->mem_slice.len = len;
	elem->flags = 0;
}

static struct bpf_stream_page *bpf_stream_page_from_elem(struct bpf_stream_elem *elem)
{
	unsigned long addr = (unsigned long)elem;

	return (struct bpf_stream_page *)PAGE_ALIGN_DOWN(addr);
}

static struct bpf_stream_elem *bpf_stream_page_push_elem(struct bpf_stream_page *stream_page, int len)
{
	u32 consumed = stream_page->consumed;

	stream_page->consumed += round_up(offsetof(struct bpf_stream_elem, str[len]), 8);
	return (struct bpf_stream_elem *)&stream_page->buf[consumed];
}

static noinline struct bpf_stream_elem *bpf_stream_page_reserve_elem(int len)
{
	struct bpf_stream_elem *elem = NULL, *next_elem;
	struct bpf_stream_page *p1, *p2;
	int room = 0;

	p1 = this_cpu_read(stream_pcpu_page);
	if (!p1)
		p1 = bpf_stream_page_replace();
	if (!p1)
		return NULL;

	room = bpf_stream_page_check_room(p1, len);
	room = min(len, room);

	/*
	 * We have three cases to handle, all data in first page, some in first
	 * and some in second page, and all data in second page.
	 *
	 * Some or all data in first page, bump p1's refcount.
	 */
	if (room)
		bpf_stream_page_get(p1);

	/* Some or all data in second page, replace p1 with it. */
	if (room < len) {
		p2 = bpf_stream_page_replace();
		if (!p2) {
			bpf_stream_page_put(p1);
			return NULL;
		}
		bpf_stream_page_get(p2);
	}

	if (!room)
		goto second;

	elem = bpf_stream_page_push_elem(p1, room);
	bpf_stream_elem_init(elem, room);
	elem->flags |= BPF_STREAM_ELEM_F_PAGE;

	if (room == len)
		return elem;
second:
	next_elem = bpf_stream_page_push_elem(p2, len - room);
	bpf_stream_elem_init(next_elem, len - room);
	next_elem->flags |= BPF_STREAM_ELEM_F_PAGE;
	if (!room)
		return next_elem;

	elem->next = next_elem;
	elem->flags |= (BPF_STREAM_ELEM_F_PAGE | BPF_STREAM_ELEM_F_NEXT);
	return elem;
}

static struct bpf_stream_elem *bpf_stream_elem_alloc_from_bpf_ma(int len)
{
	struct bpf_stream_elem *elem;

	elem = bpf_mem_alloc(&bpf_global_ma, offsetof(typeof(*elem), str[len]));
	if (!elem)
		return NULL;
	bpf_stream_elem_init(elem, len);
	return elem;
}

static struct bpf_stream_elem *bpf_stream_elem_alloc_from_stream_page(int len)
{
	struct bpf_stream_elem *elem;
	unsigned long flags;

	/*
	 * Let's not try any harder, caller tried bpf_mem_alloc() before us, so
	 * we've exhausted the per-CPU caches and cannot refill, and so we're
	 * either an NMI hitting between the local_lock() critical section, or
	 * some nested program invocation in that path (e.g. in RT, preemption
	 * is enabled, hardirq (apart from NMIs) are still allowed, etc.).
	 */
	if (!bpf_stream_page_local_lock(&flags))
		return NULL;
	elem = bpf_stream_page_reserve_elem(len);
	bpf_stream_page_local_unlock(&flags);
	return elem;
}

static struct bpf_stream_elem *bpf_stream_elem_alloc(int len)
{
	const int max_len = ARRAY_SIZE((struct bpf_bprintf_buffers){}.buf);
	struct bpf_stream_elem *elem;

	/*
	 * We may overflow, but we should never need more than one page size
	 * worth of memory. This can be lifted, but we'd need to adjust the
	 * other code to keep allocating more pages to overflow messages.
	 */
	BUILD_BUG_ON(max_len > BPF_STREAM_PAGE_SZ);
	/*
	 * Length denotes the amount of data to be written as part of stream element,
	 * thus includes '\0' byte. We're capped by how much bpf_bprintf_buffers can
	 * accomodate, therefore deny allocations that won't fit into them.
	 */
	if (len < 0 || len > max_len)
		return NULL;

	elem = bpf_stream_elem_alloc_from_bpf_ma(len);
	if (!elem)
		elem = bpf_stream_elem_alloc_from_stream_page(len);
	return elem;
}

__bpf_kfunc_start_defs();

static int bpf_stream_push_str(struct bpf_stream *stream, const char *str, int len)
{
	struct bpf_stream_elem *elem, *next = NULL;
	int room = 0, rem = 0;

	/*
	 * Allocate a bpf_prog_stream_elem and push it to the bpf_prog_stream
	 * log, elements will be popped at once and reversed to print the log.
	 */
	elem = bpf_stream_elem_alloc(len);
	if (!elem)
		return -ENOMEM;
	room = elem->mem_slice.len;
	if (elem->flags & BPF_STREAM_ELEM_F_NEXT) {
		next = (struct bpf_stream_elem *)((unsigned long)elem->next & ~BPF_STREAM_ELEM_F_MASK);
		rem = next->mem_slice.len;
	}

	memcpy(elem->str, str, room);
	if (next)
		memcpy(next->str, str + room, rem);

	if (next) {
		elem->node.next = &next->node;
		next->node.next = NULL;

		llist_add_batch(&elem->node, &next->node, &stream->log);
	} else {
		llist_add(&elem->node, &stream->log);
	}

	return 0;
}

__bpf_kfunc int bpf_stream_vprintk(struct bpf_stream *stream, const char *fmt__str, const void *args, u32 len__sz)
{
	struct bpf_bprintf_data data = {
		.get_bin_args	= true,
		.get_buf	= true,
	};
	u32 fmt_size = strlen(fmt__str) + 1;
	u32 data_len = len__sz;
	int ret, num_args;

	if (data_len & 7 || data_len > MAX_BPRINTF_VARARGS * 8 ||
	    (data_len && !args))
		return -EINVAL;
	num_args = data_len / 8;

	ret = bpf_bprintf_prepare(fmt__str, fmt_size, args, num_args, &data);
	if (ret < 0)
		return ret;

	ret = bstr_printf(data.buf, MAX_BPRINTF_BUF, fmt__str, data.bin_args);
	/* If the string was truncated, we only wrote until the size of buffer. */
	ret = min_t(u32, ret + 1, MAX_BPRINTF_BUF);
	ret = bpf_stream_push_str(stream, data.buf, ret);
	bpf_bprintf_cleanup(&data);

	return ret;
}

__bpf_kfunc struct bpf_stream *bpf_stream_get(enum bpf_stream_id stream_id, void *aux__ign)
{
	struct bpf_prog_aux *aux = aux__ign;

	if (stream_id != BPF_STDOUT && stream_id != BPF_STDERR)
		return NULL;
	return &aux->stream[stream_id - 1];
}

__bpf_kfunc struct bpf_stream_elem_batch *bpf_stream_next_elem_batch(struct bpf_stream *stream)
{
	struct bpf_stream_elem_batch *elem_batch;
	struct llist_node *batch;

	if (llist_empty(&stream->log))
		return NULL;
	/* Allocate our cursor. */
	migrate_disable();
	elem_batch = bpf_mem_alloc(&bpf_global_ma, sizeof(*elem_batch));
	migrate_enable();
	if (!elem_batch)
		return NULL;
	/*
	 * This is the linearization point for the readers; every reader
	 * consumes the whole batch of messages queued on the stream at this
	 * point, and can see everything queued before this. Anything that is
	 * queued after this can only be observed if the next batch is
	 * requested.
	 */
	batch = llist_del_all(&stream->log);
	batch = llist_reverse_order(batch);
	elem_batch->node = batch;
	return elem_batch;
}

__bpf_kfunc struct bpf_stream_elem *
bpf_stream_next_elem(struct bpf_stream_elem_batch *elem_batch)
{
	struct llist_node *node = elem_batch->node;
	struct bpf_stream_elem *elem;

	if (!node)
		return NULL;
	elem = container_of(node, struct bpf_stream_elem, node);
	elem_batch->node = node->next;
	return elem;
}

__bpf_kfunc void bpf_stream_free_elem(struct bpf_stream_elem *elem)
{
	struct bpf_stream_page *p;

	if (elem->flags & BPF_STREAM_ELEM_F_PAGE) {
		p = bpf_stream_page_from_elem(elem);
		bpf_stream_page_put(p);
		return;
	}

	migrate_disable();
	bpf_mem_free(&bpf_global_ma, elem);
	migrate_enable();
}

static void bpf_stream_free_list(struct llist_node *list)
{
	struct bpf_stream_elem *elem, *tmp;

	llist_for_each_entry_safe(elem, tmp, list, node)
		bpf_stream_free_elem(elem);
}

__bpf_kfunc void bpf_stream_free_elem_batch(struct bpf_stream_elem_batch *elem_batch)
{

	migrate_disable();
	bpf_stream_free_list(elem_batch->node);
	bpf_mem_free(&bpf_global_ma, elem_batch);
	migrate_enable();
}

__bpf_kfunc struct bpf_stream *bpf_prog_stream_get(enum bpf_stream_id stream_id, u32 prog_id)
{
	struct bpf_stream *stream;
	struct bpf_prog *prog;

	prog = bpf_prog_by_id(prog_id);
	if (!prog)
		return NULL;
	stream = bpf_stream_get(stream_id, prog->aux);
	if (!stream)
		bpf_prog_put(prog);
	return stream;
}

__bpf_kfunc void bpf_prog_stream_put(struct bpf_stream *stream)
{
	enum bpf_stream_id stream_id = stream->stream_id;
	struct bpf_prog *prog;

	prog = container_of(stream, struct bpf_prog_aux, stream[stream_id - 1])->prog;
	bpf_prog_put(prog);
}

void bpf_prog_stream_init(struct bpf_prog *prog)
{
	prog->aux->stream[0].stream_id = BPF_STDOUT;
	init_llist_head(&prog->aux->stream[0].log);

	prog->aux->stream[1].stream_id = BPF_STDERR;
	init_llist_head(&prog->aux->stream[1].log);
}

void bpf_prog_stream_free(struct bpf_prog *prog)
{
	struct llist_node *list;

	list = llist_del_all(&prog->aux->stream[0].log);
	bpf_stream_free_list(list);

	list = llist_del_all(&prog->aux->stream[1].log);
	bpf_stream_free_list(list);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(stream_kfunc_set)
BTF_ID_FLAGS(func, bpf_stream_get, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_stream_vprintk, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(stream_kfunc_set)

BTF_KFUNCS_START(stream_consumer_kfunc_set)
BTF_ID_FLAGS(func, bpf_stream_next_elem_batch, KF_ACQUIRE | KF_RET_NULL | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_stream_free_elem_batch, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_stream_next_elem, KF_ACQUIRE | KF_RET_NULL | KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_stream_free_elem, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_prog_stream_get, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_prog_stream_put, KF_RELEASE)
BTF_KFUNCS_END(stream_consumer_kfunc_set)

BTF_ID_LIST(bpf_stream_dtor_ids)
BTF_ID(struct, bpf_stream_elem_batch)
BTF_ID(func, bpf_stream_free_elem_batch)

static const struct btf_kfunc_id_set bpf_stream_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &stream_kfunc_set,
};

static const struct btf_kfunc_id_set bpf_stream_consumer_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &stream_consumer_kfunc_set,
};

static int __init bpf_stream_kfunc_init(void)
{
	const struct btf_id_dtor_kfunc bpf_stream_dtors[] = {
		{
			.btf_id		= bpf_stream_dtor_ids[0],
			.kfunc_btf_id	= bpf_stream_dtor_ids[1],
		},
	};
	int ret;

	ret = register_btf_id_dtor_kfuncs(bpf_stream_dtors, ARRAY_SIZE(bpf_stream_dtors), THIS_MODULE);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &bpf_stream_kfunc_set);
	return ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_stream_consumer_kfunc_set);
}
late_initcall(bpf_stream_kfunc_init);

int bpf_prog_stderr_printk(struct bpf_prog *prog, const char *fmt, ...)
{
	struct bpf_stream *stream = bpf_stream_get(BPF_STDERR, prog->aux);
	struct bpf_bprintf_buffers *buf;
	va_list args;
	int ret;

	if (bpf_try_get_buffers(&buf))
		return -EBUSY;

	va_start(args, fmt);
	ret = vsnprintf(buf->buf, ARRAY_SIZE(buf->buf), fmt, args);
	va_end(args);
	/* If the string was truncated, we only wrote until the size of buffer. */
	ret = min_t(u32, ret + 1, ARRAY_SIZE(buf->buf));
	ret = bpf_stream_push_str(stream, buf->buf, ret);
	bpf_put_buffers();
	return ret;
}
