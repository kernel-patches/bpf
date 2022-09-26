// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Google LLC

#include <linux/filter.h>
#include <linux/bpf_fuse.h>

static const struct bpf_func_proto *
fuse_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_trace_printk:
			return bpf_get_trace_printk_proto();

	case BPF_FUNC_get_current_uid_gid:
			return &bpf_get_current_uid_gid_proto;

	case BPF_FUNC_get_current_pid_tgid:
			return &bpf_get_current_pid_tgid_proto;

	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;

	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;

	case BPF_FUNC_fuse_get_writeable_in:
		return &bpf_fuse_get_writeable_in_proto;

	case BPF_FUNC_fuse_get_writeable_out:
		return &bpf_fuse_get_writeable_out_proto;

	default:
		pr_debug("Invalid fuse bpf func %d\n", func_id);
		return NULL;
	}
}

static bool fuse_arg_valid_access(int off, int start, int size, struct bpf_insn_access_aux *info)
{
	int arg_off = (off - start) % sizeof(struct __bpf_fuse_arg);
	int arg_start = off - arg_off;

	switch (arg_off) {
	case bpf_ctx_range(struct __bpf_fuse_arg, value):
	case offsetof(struct __bpf_fuse_arg, end_offset):
		if (size != sizeof(__u64))
			return false;
		break;

	case offsetof(struct __bpf_fuse_arg, max_size):
	case offsetof(struct __bpf_fuse_arg, size):
		if (size != sizeof(__u32))
			return false;
		break;

	}

	switch (arg_off) {
	case bpf_ctx_range(struct __bpf_fuse_arg, value):
		info->reg_type = PTR_TO_PACKET;
		info->data_id = arg_start;
		return true;

	case offsetof(struct __bpf_fuse_arg, end_offset):
		info->reg_type = PTR_TO_PACKET_END;
		info->data_id = arg_start;
		return true;

	case offsetof(struct __bpf_fuse_arg, max_size):
	case offsetof(struct __bpf_fuse_arg, size):
		info->reg_type = SCALAR_VALUE;
		return true;
	}
	return false;
}

static bool fuse_prog_is_valid_access(int off, int size,
				enum bpf_access_type type,
				const struct bpf_prog *prog,
				struct bpf_insn_access_aux *info)
{
	if (off < 0 || off > offsetofend(struct bpf_fuse_args, out_args))
		return false;

	/* No fields should be written directly. Writable buffers are requested via helper function
	 * The size fields is set by helper. If bpfs have a need to adjust the size smaller, we may
	 * revisit this...
	 */
	if (type == BPF_WRITE)
		return false;

	switch (off) {
	case bpf_ctx_range(struct __bpf_fuse_args, nodeid):
		info->reg_type = SCALAR_VALUE;
		if (size == sizeof(__u64))
			return true;
		break;
	case bpf_ctx_range(struct __bpf_fuse_args, opcode):
	case bpf_ctx_range(struct __bpf_fuse_args, error_in):
	case bpf_ctx_range(struct __bpf_fuse_args, in_numargs):
	case bpf_ctx_range(struct __bpf_fuse_args, out_numargs):
	case bpf_ctx_range(struct __bpf_fuse_args, flags):
		info->reg_type = SCALAR_VALUE;
		if (size == sizeof(__u32))
			return true;
		break;
	case bpf_ctx_range_till(struct __bpf_fuse_args, in_args[0], in_args[2]):
		if (fuse_arg_valid_access(off, offsetof(struct __bpf_fuse_args, in_args[0]),
					  size, info))
			return true;
		break;
	case bpf_ctx_range_till(struct __bpf_fuse_args, out_args[0], out_args[1]):
		if (fuse_arg_valid_access(off, offsetof(struct __bpf_fuse_args, out_args[0]),
					  size, info))
			return true;
		break;
	}

	return false;
}

static struct bpf_insn *fuse_arg_convert_access(int off, int start, int converted_start,
						const struct bpf_insn *si, struct bpf_insn *insn)
{
	int arg_off = (off - start) % sizeof(struct __bpf_fuse_arg);
	int arg_num = (off - start) / sizeof(struct __bpf_fuse_arg);
	int arg_start = converted_start + arg_num * sizeof(struct bpf_fuse_arg);

	switch (arg_off) {
	case offsetof(struct __bpf_fuse_arg, value):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_arg, value),
				      si->dst_reg, si->src_reg,
				      arg_start + offsetof(struct bpf_fuse_arg, value));
		break;

	case offsetof(struct __bpf_fuse_arg, end_offset):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_arg, end_offset),
				      si->dst_reg, si->src_reg,
				      arg_start + offsetof(struct bpf_fuse_arg, end_offset));
		break;

	case offsetof(struct __bpf_fuse_arg, size):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_arg, size),
				      si->dst_reg, si->src_reg,
				      arg_start + offsetof(struct bpf_fuse_arg, size));
		break;

	case offsetof(struct __bpf_fuse_arg, max_size):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_arg, max_size),
				      si->dst_reg, si->src_reg,
				      arg_start + offsetof(struct bpf_fuse_arg, max_size));
		break;
	}
	return insn;
}

static u32 fuse_prog_convert_ctx_access(enum bpf_access_type type,
		     const struct bpf_insn *si,
		     struct bpf_insn *insn_buf,
		     struct bpf_prog *prog,
		     u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct __bpf_fuse_args, nodeid):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_args, nodeid),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_fuse_args, nodeid));
		break;

	case offsetof(struct __bpf_fuse_args, opcode):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_args, opcode),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_fuse_args, opcode));
		break;

	case offsetof(struct __bpf_fuse_args, error_in):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_args, error_in),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_fuse_args, error_in));
		break;

	case offsetof(struct __bpf_fuse_args, in_numargs):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_args, in_numargs),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_fuse_args, in_numargs));
		break;

	case offsetof(struct __bpf_fuse_args, out_numargs):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_args, out_numargs),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_fuse_args, out_numargs));
		break;

	case offsetof(struct __bpf_fuse_args, flags):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_fuse_args, flags),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_fuse_args, flags));
		break;

	case bpf_ctx_range_till(struct __bpf_fuse_args, in_args[0], in_args[2]):
		insn = fuse_arg_convert_access(si->off,
					       offsetof(struct __bpf_fuse_args, in_args[0]),
					       offsetof(struct bpf_fuse_args, in_args[0]),
					       si, insn);
		break;

	case bpf_ctx_range_till(struct __bpf_fuse_args, out_args[0], out_args[1]):
		insn = fuse_arg_convert_access(si->off,
					       offsetof(struct __bpf_fuse_args, out_args[0]),
					       offsetof(struct bpf_fuse_args, out_args[0]),
					       si, insn);
		break;

	}

	return insn - insn_buf;
}

static int fuse_prog_get_prologue(struct bpf_insn *insn_buf,
				   bool direct_write,
				   const struct bpf_prog *prog)
{
	return 0;
}

static int buff_size(struct bpf_fuse_arg *arg)
{
	return ((char *)arg->end_offset - (char *)arg->value);
}

void *bpf_fuse_get_writeable(struct bpf_fuse_arg *arg, u64 size, bool copy)
{
	void *writeable_val;

	if (arg->flags & BPF_FUSE_IMMUTABLE)
		return 0;

	if (size <= buff_size(arg) &&
			(!(arg->flags & BPF_FUSE_MUST_ALLOCATE) ||
			  (arg->flags & BPF_FUSE_ALLOCATED))) {
		if (arg->flags & BPF_FUSE_VARIABLE_SIZE)
			arg->size = size;
		arg->flags |= BPF_FUSE_MODIFIED;
		return arg->value;
	}
	/* Variable sized arrays must stay below max size. If the buffer must be fixed size,
	 * don't change the allocated size. Verifier will enforce requested size for accesses
	 */
	if (arg->flags & BPF_FUSE_VARIABLE_SIZE) {
		if (size > arg->max_size)
			return 0;
	} else {
		if (size > arg->size)
			return 0;
		size = arg->size;
	}

	if (size != arg->size && size > arg->max_size)
		return 0;
	writeable_val = kzalloc(size, GFP_KERNEL);
	if (!writeable_val)
		return 0;

	/* If we're copying the buffer, assume the same amount is used. If that isn't the case,
	 * caller must change size. Otherwise, assume entirety of new buffer is used.
	 */
	if (copy)
		memcpy(writeable_val, arg->value, (arg->size > size) ? size : arg->size);
	else
		arg->size = size;

	if (arg->flags & BPF_FUSE_ALLOCATED)
		kfree(arg->value);
	arg->value = writeable_val;
	arg->end_offset = (char *)writeable_val + size;

	arg->flags |= BPF_FUSE_ALLOCATED | BPF_FUSE_MODIFIED;

	return arg->value;
}
EXPORT_SYMBOL(bpf_fuse_get_writeable);

BPF_CALL_5(bpf_fuse_get_writeable_in, struct bpf_fuse_args *, ctx, u32, index, void *, value,
		u64, size, bool, copy)
{
	if (ctx->in_args[index].value != value)
		return 0;
	return (unsigned long) bpf_fuse_get_writeable(&ctx->in_args[index], size, copy);
}

BPF_CALL_5(bpf_fuse_get_writeable_out, struct bpf_fuse_args *, ctx, u32, index, void *, value,
		u64, size, bool, copy)
{
	if (ctx->out_args[index].value != value)
		return 0;
	return (unsigned long) bpf_fuse_get_writeable(&ctx->out_args[index], size, copy);
}

bool bpf_helper_changes_one_pkt_data(void *func)
{
	if (func == bpf_fuse_get_writeable_in || func == bpf_fuse_get_writeable_out)
		return true;
	return false;
}

const struct bpf_func_proto bpf_fuse_get_writeable_in_proto = {
	.func		= bpf_fuse_get_writeable_in,
	.ret_type	= RET_PTR_TO_ALLOC_MEM_OR_NULL,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_PACKET,
	.arg4_type	= ARG_CONST_ALLOC_SIZE_OR_ZERO,
	.arg5_type	= ARG_ANYTHING,
	.gpl_only	= false,
	.pkt_access	= true,
};

const struct bpf_func_proto bpf_fuse_get_writeable_out_proto = {
	.func		= bpf_fuse_get_writeable_out,
	.ret_type	= RET_PTR_TO_ALLOC_MEM_OR_NULL,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_PACKET,
	.arg4_type	= ARG_CONST_ALLOC_SIZE_OR_ZERO,
	.arg5_type	= ARG_ANYTHING,
	.gpl_only	= false,
	.pkt_access	= true,
};


const struct bpf_verifier_ops fuse_verifier_ops = {
	.get_func_proto  = fuse_prog_func_proto,
	.is_valid_access = fuse_prog_is_valid_access,
	.convert_ctx_access = fuse_prog_convert_ctx_access,
	.gen_prologue = fuse_prog_get_prologue,
};

const struct bpf_prog_ops fuse_prog_ops = {
};

