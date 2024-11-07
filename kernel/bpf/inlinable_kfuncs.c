// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/skbuff.h>
#include <linux/filter.h>

__bpf_kfunc bool bpf_dynptr_is_null(const struct bpf_dynptr *p);
__bpf_kfunc bool bpf_dynptr_is_rdonly(const struct bpf_dynptr *p);
__bpf_kfunc __u32 bpf_dynptr_size(const struct bpf_dynptr *p);
__bpf_kfunc void *bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset,
				   void *buffer__opt, u32 buffer__szk);

__bpf_kfunc bool bpf_dynptr_is_null(const struct bpf_dynptr *p)
{
	struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;

	return !ptr->data;
}

__bpf_kfunc bool bpf_dynptr_is_rdonly(const struct bpf_dynptr *p)
{
	struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;

	if (!ptr->data)
		return false;

	return __bpf_dynptr_is_rdonly(ptr);
}

__bpf_kfunc __u32 bpf_dynptr_size(const struct bpf_dynptr *p)
{
	struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;

	if (!ptr->data)
		return -EINVAL;

	return __bpf_dynptr_size(ptr);
}

/**
 * bpf_dynptr_slice() - Obtain a read-only pointer to the dynptr data.
 * @p: The dynptr whose data slice to retrieve
 * @offset: Offset into the dynptr
 * @buffer__opt: User-provided buffer to copy contents into.  May be NULL
 * @buffer__szk: Size (in bytes) of the buffer if present. This is the
 *               length of the requested slice. This must be a constant.
 *
 * For non-skb and non-xdp type dynptrs, there is no difference between
 * bpf_dynptr_slice and bpf_dynptr_data.
 *
 *  If buffer__opt is NULL, the call will fail if buffer_opt was needed.
 *
 * If the intention is to write to the data slice, please use
 * bpf_dynptr_slice_rdwr.
 *
 * The user must check that the returned pointer is not null before using it.
 *
 * Please note that in the case of skb and xdp dynptrs, bpf_dynptr_slice
 * does not change the underlying packet data pointers, so a call to
 * bpf_dynptr_slice will not invalidate any ctx->data/data_end pointers in
 * the bpf program.
 *
 * Return: NULL if the call failed (eg invalid dynptr), pointer to a read-only
 * data slice (can be either direct pointer to the data or a pointer to the user
 * provided buffer, with its contents containing the data, if unable to obtain
 * direct pointer)
 */
__bpf_kfunc void *bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset,
				   void *buffer__opt, u32 buffer__szk)
{
	const struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;
	enum bpf_dynptr_type type;
	u32 len = buffer__szk;
	int err;

	if (!ptr->data)
		return NULL;

	err = bpf_dynptr_check_off_len(ptr, offset, len);
	if (err)
		return NULL;

	type = bpf_dynptr_get_type(ptr);

	switch (type) {
	case BPF_DYNPTR_TYPE_LOCAL:
	case BPF_DYNPTR_TYPE_RINGBUF:
		return ptr->data + ptr->offset + offset;
	case BPF_DYNPTR_TYPE_SKB:
		if (buffer__opt)
			return skb_header_pointer(ptr->data, ptr->offset + offset, len, buffer__opt);
		else
			return skb_pointer_if_linear(ptr->data, ptr->offset + offset, len);
	case BPF_DYNPTR_TYPE_XDP:
	{
		void *xdp_ptr = bpf_xdp_pointer(ptr->data, ptr->offset + offset, len);
		if (!IS_ERR_OR_NULL(xdp_ptr))
			return xdp_ptr;

		if (!buffer__opt)
			return NULL;
		bpf_xdp_copy_buf(ptr->data, ptr->offset + offset, buffer__opt, len, false);
		return buffer__opt;
	}
	default:
	// TODO: can't handle inline assembly inside this when compiling to BPF
#ifndef __FOR_BPF
		WARN_ONCE(true, "unknown dynptr type %d\n", type);
#endif
		return NULL;
	}
}
