// SPDX-License-Identifier: GPL-2.0
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/vmalloc.h>
#include <linux/bpf.h>

#define BPF_CONTEXT_HASH_BITS 10

static DEFINE_SPINLOCK(bpf_parser_context_lock);
static DEFINE_HASHTABLE(bpf_parser_context_map, BPF_CONTEXT_HASH_BITS);

/* Generate a simple hash key from pointer address */
static inline unsigned int bpf_parser_context_hash_key(struct bpf_parser_context *ctx)
{
	return hash_ptr(ctx, BPF_CONTEXT_HASH_BITS);
}

static void release_bpf_parser_context(struct kref *kref)
{
	struct bpf_parser_context *ctx = container_of(kref, struct bpf_parser_context, ref);

	if (ctx->buf) {
		vfree(ctx->buf->buf);
		kfree(ctx->buf);
	}
	spin_lock(&bpf_parser_context_lock);
	hash_del(&ctx->hash_node);
	spin_unlock(&bpf_parser_context_lock);
	kfree(ctx);
}

struct bpf_parser_context *alloc_bpf_parser_context(bpf_parser_handler_t func,
		void *data)
{
	struct bpf_parser_context *ctx;
	unsigned int key;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;
	ctx->func = func;
	ctx->data = data;
	kref_init(&ctx->ref);
	key = bpf_parser_context_hash_key(ctx);
	spin_lock(&bpf_parser_context_lock);
	hash_add(bpf_parser_context_map, &ctx->hash_node, key);
	spin_unlock(&bpf_parser_context_lock);

	return ctx;
}

void put_bpf_parser_context(struct bpf_parser_context *ctx)
{
	if (!ctx)
		return;
	kref_put(&ctx->ref, release_bpf_parser_context);
}

static struct bpf_parser_context *find_bpf_parser_context(unsigned long id)
{
	struct bpf_parser_context *ctx;
	unsigned int key;
	int cnt;

	key = bpf_parser_context_hash_key((struct bpf_parser_context *)id);
	spin_lock(&bpf_parser_context_lock);
	hash_for_each_possible(bpf_parser_context_map, ctx, hash_node, key) {
		if (ctx == (struct bpf_parser_context *)id) {
			cnt = kref_get_unless_zero(&ctx->ref);
			if (!cnt)
				ctx = NULL;
			spin_unlock(&bpf_parser_context_lock);
			return ctx;
		}
	}
	spin_unlock(&bpf_parser_context_lock);

	return NULL;
}

__bpf_kfunc_start_defs()

__bpf_kfunc struct bpf_parser_context *bpf_get_parser_context(unsigned long id)
{
	struct bpf_parser_context *ctx;

	ctx = find_bpf_parser_context(id);

	return ctx;
}

__bpf_kfunc void bpf_put_parser_context(struct bpf_parser_context *ctx)
{
	put_bpf_parser_context(ctx);
}

__bpf_kfunc void bpf_parser_context_release_dtor(void *ctx)
{
	put_bpf_parser_context(ctx);
}
CFI_NOSEAL(bpf_parser_context_release_dtor);

__bpf_kfunc int bpf_buffer_parser(char *buf, int buf_sz,
		struct bpf_parser_context *context)
{
	struct bpf_parser_buf *parser_buf;
	void *old_val;
	int ret;
	char *b;

	if (buf == NULL || buf_sz <= 0)
		return -EINVAL;

	if (unlikely(context->func == NULL))
		return -EINVAL;

	/* Lock the pointer */
	old_val = cmpxchg(&context->buf, NULL, (void *)1);
	if (old_val != NULL)
		return -EBUSY;
	b = __vmalloc(buf_sz, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!b) {
		context->buf = NULL;
		return -ENOMEM;
	}
	ret = copy_from_kernel_nofault(b, buf, buf_sz);
	if (!!ret) {
		context->buf = NULL;
		vfree(b);
		return ret;
	}

	parser_buf = kmalloc(sizeof(struct bpf_parser_buf), GFP_KERNEL);
	if (!parser_buf) {
		vfree(b);
		context->buf = NULL;
		return -ENOMEM;
	}
	parser_buf->buf = b;
	parser_buf->size = buf_sz;
	context->buf = parser_buf;
	/* @func should be a sync call */
	ret = context->func(context);
	context->buf = NULL;
	vfree(b);
	kfree(parser_buf);

	return ret;
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(buffer_parser_ids)
BTF_ID_FLAGS(func, bpf_get_parser_context, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_put_parser_context, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_buffer_parser, KF_SLEEPABLE)
BTF_KFUNCS_END(buffer_parser_ids)

static const struct btf_kfunc_id_set buffer_parser_kfunc_set = {
        .owner = THIS_MODULE,
        .set   = &buffer_parser_ids,
};


BTF_ID_LIST(buffer_parser_dtor_ids)
BTF_ID(struct, bpf_parser_context)
BTF_ID(func, bpf_parser_context_release_dtor)

static int __init buffer_parser_kfunc_init(void)
{
	int ret;
	const struct btf_id_dtor_kfunc buffer_parser_dtors[] = {
		{
			.btf_id	      = buffer_parser_dtor_ids[0],
			.kfunc_btf_id = buffer_parser_dtor_ids[1]
		},
	};

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &buffer_parser_kfunc_set);
	return  ret ?: register_btf_id_dtor_kfuncs(buffer_parser_dtors,
						   ARRAY_SIZE(buffer_parser_dtors),
						   THIS_MODULE);
}

late_initcall(buffer_parser_kfunc_init);
