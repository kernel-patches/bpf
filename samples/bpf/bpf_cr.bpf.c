// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpf_cr.h"

/* struct file -> int fd */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, int);
	__uint(max_entries, 16);
} fdtable_map SEC(".maps");

struct ctx_map_val {
	int fd;
	bool init;
};

/* io_ring_ctx -> int fd */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct ctx_map_val);
	__uint(max_entries, 16);
} io_ring_ctx_map SEC(".maps");

/* ctx->sq_data -> int fd */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, int);
	__uint(max_entries, 16);
} sq_data_map SEC(".maps");

/* eventfd_ctx -> int fd */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, int);
	__uint(max_entries, 16);
} eventfd_ctx_map SEC(".maps");

const volatile pid_t tgid = 0;

extern void eventfd_fops __ksym;
extern void io_uring_fops __ksym;

SEC("iter/task_file")
int dump_task(struct bpf_iter__task_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	struct ctx_map_val val = {};
	__u64 f_priv;
	int fd;

	if (!task)
		return 0;
	if (task->tgid != tgid)
		return 0;
	if (!file)
		return 0;

	f_priv = (__u64)file->private_data;
	fd = ctx->fd;
	val.fd = fd;
	if (file->f_op == &eventfd_fops) {
		bpf_map_update_elem(&eventfd_ctx_map, &f_priv, &fd, 0);
	} else if (file->f_op == &io_uring_fops) {
		struct io_ring_ctx *ctx;
		void *sq_data;
		__u64 key;

		bpf_map_update_elem(&io_ring_ctx_map, &f_priv, &val, 0);
		ctx = file->private_data;
		bpf_probe_read_kernel(&sq_data, sizeof(sq_data), &ctx->sq_data);
		key = (__u64)sq_data;
		bpf_map_update_elem(&sq_data_map, &key, &fd, BPF_NOEXIST);
	}
	f_priv = (__u64)file;
	bpf_map_update_elem(&fdtable_map, &f_priv, &fd, BPF_NOEXIST);
	return 0;
}

static void dump_io_ring_ctx(struct seq_file *seq, struct io_ring_ctx *ctx, int ring_fd)
{
	struct io_uring_dump dump;
	struct ctx_map_val *val;
	__u64 key;
	int *fd;

	key = (__u64)ctx;
	val = bpf_map_lookup_elem(&io_ring_ctx_map, &key);
	if (val && val->init)
		return;
	__builtin_memset(&dump, 0, sizeof(dump));
	if (val)
		val->init = true;
	dump.type = DUMP_SETUP;
	dump.io_uring_fd = ring_fd;
	key = (__u64)ctx->sq_data;
#define ATTACH_WQ_FLAG (1 << 5)
	if (ctx->flags & ATTACH_WQ_FLAG) {
		fd = bpf_map_lookup_elem(&sq_data_map, &key);
		if (fd)
			dump.desc.setup.wq_fd = *fd;
	}
	dump.desc.setup.flags = ctx->flags;
	dump.desc.setup.sq_entries = ctx->sq_entries;
	dump.desc.setup.cq_entries = ctx->cq_entries;
	dump.desc.setup.sq_thread_cpu = ctx->sq_data->sq_cpu;
	dump.desc.setup.sq_thread_idle = ctx->sq_data->sq_thread_idle;
	bpf_seq_write(seq, &dump, sizeof(dump));
	if (ctx->cq_ev_fd) {
		dump.type = DUMP_EVENTFD;
		key = (__u64)ctx->cq_ev_fd;
		fd = bpf_map_lookup_elem(&eventfd_ctx_map, &key);
		if (fd)
			dump.desc.eventfd.eventfd = *fd;
		dump.desc.eventfd.async = ctx->eventfd_async;
		bpf_seq_write(seq, &dump, sizeof(dump));
	}
}

SEC("iter/io_uring_buf")
int dump_io_uring_buf(struct bpf_iter__io_uring_buf *ctx)
{
	struct io_mapped_ubuf *ubuf = ctx->ubuf;
	struct seq_file *seq = ctx->meta->seq;
	struct io_uring_dump dump;
	__u64 key;
	int *fd;

	__builtin_memset(&dump, 0, sizeof(dump));
	key = (__u64)ctx->ctx;
	fd = bpf_map_lookup_elem(&io_ring_ctx_map, &key);
	if (!ctx->meta->seq_num)
		dump_io_ring_ctx(seq, ctx->ctx, fd ? *fd : 0);
	if (!ubuf)
		return 0;
	dump.type = DUMP_REG_BUF;
	if (fd)
		dump.io_uring_fd = *fd;
	dump.desc.reg_buf.index = ctx->index;
	if (ubuf != ctx->ctx->dummy_ubuf) {
		dump.desc.reg_buf.addr = ubuf->ubuf;
		dump.desc.reg_buf.len = ubuf->ubuf_end - ubuf->ubuf;
	}
	bpf_seq_write(seq, &dump, sizeof(dump));
	return 0;
}

SEC("iter/io_uring_file")
int dump_io_uring_file(struct bpf_iter__io_uring_file *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct file *file = ctx->file;
	struct io_uring_dump dump;
	__u64 key;
	int *fd;

	__builtin_memset(&dump, 0, sizeof(dump));
	key = (__u64)ctx->ctx;
	fd = bpf_map_lookup_elem(&io_ring_ctx_map, &key);
	if (!ctx->meta->seq_num)
		dump_io_ring_ctx(seq, ctx->ctx, fd ? *fd : 0);
	if (!file)
		return 0;
	dump.type = DUMP_REG_FD;
	if (fd)
		dump.io_uring_fd = *fd;
	dump.desc.reg_fd.index = ctx->index;
	key = (__u64)file;
	fd = bpf_map_lookup_elem(&fdtable_map, &key);
	if (fd)
		dump.desc.reg_fd.reg_fd = *fd;
	bpf_seq_write(seq, &dump, sizeof(dump));
	return 0;
}

char _license[] SEC("license") = "GPL";
