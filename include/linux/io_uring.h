/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_IO_URING_H
#define _LINUX_IO_URING_H

#include <linux/io_uring_types.h>
#include <linux/sched.h>
#include <linux/xarray.h>
#include <uapi/linux/io_uring.h>

/*
 * clang likes to set/clear flag bits using the narrowest possible or/and
 * instructions (e.g. an 8-bit or if all flag bits are in the same byte).
 * This causes store-to-load forwarding failures on subsequent wider loads
 * of req->flags.
 * Store to req->flags using volatile writes to prevent this "optimization".
 */
static inline void io_req_switch_flags(struct io_kiocb *req,
				       io_req_flags_t clear_flags,
				       io_req_flags_t set_flags)
{
	WRITE_ONCE(req->flags, (req->flags | set_flags) & ~clear_flags);
}

static inline void io_req_set_flags(struct io_kiocb *req, io_req_flags_t flags)
{
	io_req_switch_flags(req, 0, flags);
}

static inline void io_req_clear_flags(struct io_kiocb *req,
				      io_req_flags_t flags)
{
	io_req_switch_flags(req, flags, 0);
}

static inline void req_set_fail(struct io_kiocb *req)
{
	req->flags |= REQ_F_FAIL;
	if (req->flags & REQ_F_CQE_SKIP) {
		req->flags &= ~REQ_F_CQE_SKIP;
		req->flags |= REQ_F_SKIP_LINK_CQES;
	}
}

static inline void io_req_set_res(struct io_kiocb *req, s32 res, u32 cflags)
{
	req->cqe.res = res;
	req->cqe.flags = cflags;
}

static inline u32 ctx_cqe32_flags(struct io_ring_ctx *ctx)
{
	if (ctx->flags & IORING_SETUP_CQE_MIXED)
		return IORING_CQE_F_32;
	return 0;
}

static inline void io_req_set_res32(struct io_kiocb *req, s32 res, u32 cflags,
				    __u64 extra1, __u64 extra2)
{
	req->cqe.res = res;
	req->cqe.flags = cflags | ctx_cqe32_flags(req->ctx);
	req->big_cqe.extra1 = extra1;
	req->big_cqe.extra2 = extra2;
}

#if defined(CONFIG_IO_URING)
void __io_uring_cancel(bool cancel_all);
void __io_uring_free(struct task_struct *tsk);
void io_uring_unreg_ringfd(void);
const char *io_uring_get_opcode(u8 opcode);
bool io_is_uring_fops(struct file *file);
int __io_uring_fork(struct task_struct *tsk);

static inline void io_uring_files_cancel(void)
{
	if (current->io_uring)
		__io_uring_cancel(false);
}
static inline void io_uring_task_cancel(void)
{
	if (current->io_uring)
		__io_uring_cancel(true);
}
static inline void io_uring_free(struct task_struct *tsk)
{
	if (tsk->io_uring || tsk->io_uring_restrict)
		__io_uring_free(tsk);
}
static inline int io_uring_fork(struct task_struct *tsk)
{
	if (tsk->io_uring_restrict)
		return __io_uring_fork(tsk);

	return 0;
}
#else
static inline void io_uring_task_cancel(void)
{
}
static inline void io_uring_files_cancel(void)
{
}
static inline void io_uring_free(struct task_struct *tsk)
{
}
static inline const char *io_uring_get_opcode(u8 opcode)
{
	return "";
}
static inline bool io_is_uring_fops(struct file *file)
{
	return false;
}
static inline int io_uring_fork(struct task_struct *tsk)
{
	return 0;
}
#endif

#endif
