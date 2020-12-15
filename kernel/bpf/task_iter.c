// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2020 Facebook */

#include <linux/init.h>
#include <linux/namei.h>
#include <linux/pid_namespace.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/filter.h>
#include <linux/btf_ids.h>

struct bpf_iter_seq_task_common {
	struct pid_namespace *ns;
};

struct bpf_iter_seq_task_info {
	/* The first field must be struct bpf_iter_seq_task_common.
	 * this is assumed by {init, fini}_seq_pidns() callback functions.
	 */
	struct bpf_iter_seq_task_common common;
	u32 tid;
};

static struct task_struct *task_seq_get_next(struct pid_namespace *ns,
					     u32 *tid,
					     bool skip_if_dup_files)
{
	struct task_struct *task = NULL;
	struct pid *pid;

	rcu_read_lock();
retry:
	pid = find_ge_pid(*tid, ns);
	if (pid) {
		*tid = pid_nr_ns(pid, ns);
		task = get_pid_task(pid, PIDTYPE_PID);
		if (!task) {
			++*tid;
			goto retry;
		} else if (skip_if_dup_files && task->tgid != task->pid &&
			   task->files == task->group_leader->files) {
			put_task_struct(task);
			task = NULL;
			++*tid;
			goto retry;
		}
	}
	rcu_read_unlock();

	return task;
}

static void *task_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_iter_seq_task_info *info = seq->private;
	struct task_struct *task;

	task = task_seq_get_next(info->common.ns, &info->tid, false);
	if (!task)
		return NULL;

	if (*pos == 0)
		++*pos;
	return task;
}

static void *task_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct bpf_iter_seq_task_info *info = seq->private;
	struct task_struct *task;

	++*pos;
	++info->tid;
	put_task_struct((struct task_struct *)v);
	task = task_seq_get_next(info->common.ns, &info->tid, false);
	if (!task)
		return NULL;

	return task;
}

struct bpf_iter__task {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct task_struct *, task);
};

DEFINE_BPF_ITER_FUNC(task, struct bpf_iter_meta *meta, struct task_struct *task)

static int __task_seq_show(struct seq_file *seq, struct task_struct *task,
			   bool in_stop)
{
	struct bpf_iter_meta meta;
	struct bpf_iter__task ctx;
	struct bpf_prog *prog;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, in_stop);
	if (!prog)
		return 0;

	meta.seq = seq;
	ctx.meta = &meta;
	ctx.task = task;
	return bpf_iter_run_prog(prog, &ctx);
}

static int task_seq_show(struct seq_file *seq, void *v)
{
	return __task_seq_show(seq, v, false);
}

static void task_seq_stop(struct seq_file *seq, void *v)
{
	if (!v)
		(void)__task_seq_show(seq, v, true);
	else
		put_task_struct((struct task_struct *)v);
}

static const struct seq_operations task_seq_ops = {
	.start	= task_seq_start,
	.next	= task_seq_next,
	.stop	= task_seq_stop,
	.show	= task_seq_show,
};

struct bpf_iter_seq_task_file_info {
	/* The first field must be struct bpf_iter_seq_task_common.
	 * this is assumed by {init, fini}_seq_pidns() callback functions.
	 */
	struct bpf_iter_seq_task_common common;
	struct task_struct *task;
	struct files_struct *files;
	u32 tid;
	u32 fd;
};

static struct file *
task_file_seq_get_next(struct bpf_iter_seq_task_file_info *info)
{
	struct pid_namespace *ns = info->common.ns;
	u32 curr_tid = info->tid, max_fds;
	struct files_struct *curr_files;
	struct task_struct *curr_task;
	int curr_fd = info->fd;

	/* If this function returns a non-NULL file object,
	 * it held a reference to the task/files_struct/file.
	 * Otherwise, it does not hold any reference.
	 */
again:
	if (info->task) {
		curr_task = info->task;
		curr_files = info->files;
		curr_fd = info->fd;
	} else {
		curr_task = task_seq_get_next(ns, &curr_tid, true);
		if (!curr_task) {
			info->task = NULL;
			info->files = NULL;
			return NULL;
		}

		curr_files = get_files_struct(curr_task);
		if (!curr_files) {
			put_task_struct(curr_task);
			curr_tid = ++(info->tid);
			info->fd = 0;
			goto again;
		}

		info->files = curr_files;
		info->task = curr_task;
		if (curr_tid == info->tid) {
			curr_fd = info->fd;
		} else {
			info->tid = curr_tid;
			curr_fd = 0;
		}
	}

	rcu_read_lock();
	max_fds = files_fdtable(curr_files)->max_fds;
	for (; curr_fd < max_fds; curr_fd++) {
		struct file *f;

		f = fcheck_files(curr_files, curr_fd);
		if (!f)
			continue;
		if (!get_file_rcu(f))
			continue;

		/* set info->fd */
		info->fd = curr_fd;
		rcu_read_unlock();
		return f;
	}

	/* the current task is done, go to the next task */
	rcu_read_unlock();
	put_files_struct(curr_files);
	put_task_struct(curr_task);
	info->task = NULL;
	info->files = NULL;
	info->fd = 0;
	curr_tid = ++(info->tid);
	goto again;
}

static void *task_file_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_iter_seq_task_file_info *info = seq->private;
	struct file *file;

	info->task = NULL;
	info->files = NULL;
	file = task_file_seq_get_next(info);
	if (file && *pos == 0)
		++*pos;

	return file;
}

static void *task_file_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct bpf_iter_seq_task_file_info *info = seq->private;

	++*pos;
	++info->fd;
	fput((struct file *)v);
	return task_file_seq_get_next(info);
}

struct bpf_iter__task_file {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct task_struct *, task);
	u32 fd __aligned(8);
	__bpf_md_ptr(struct file *, file);
};

DEFINE_BPF_ITER_FUNC(task_file, struct bpf_iter_meta *meta,
		     struct task_struct *task, u32 fd,
		     struct file *file)

static int __task_file_seq_show(struct seq_file *seq, struct file *file,
				bool in_stop)
{
	struct bpf_iter_seq_task_file_info *info = seq->private;
	struct bpf_iter__task_file ctx;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, in_stop);
	if (!prog)
		return 0;

	ctx.meta = &meta;
	ctx.task = info->task;
	ctx.fd = info->fd;
	ctx.file = file;
	return bpf_iter_run_prog(prog, &ctx);
}

static int task_file_seq_show(struct seq_file *seq, void *v)
{
	return __task_file_seq_show(seq, v, false);
}

static void task_file_seq_stop(struct seq_file *seq, void *v)
{
	struct bpf_iter_seq_task_file_info *info = seq->private;

	if (!v) {
		(void)__task_file_seq_show(seq, v, true);
	} else {
		fput((struct file *)v);
		put_files_struct(info->files);
		put_task_struct(info->task);
		info->files = NULL;
		info->task = NULL;
	}
}

static int init_seq_pidns(void *priv_data, struct bpf_iter_aux_info *aux)
{
	struct bpf_iter_seq_task_common *common = priv_data;

	common->ns = get_pid_ns(task_active_pid_ns(current));
	return 0;
}

static void fini_seq_pidns(void *priv_data)
{
	struct bpf_iter_seq_task_common *common = priv_data;

	put_pid_ns(common->ns);
}

static const struct seq_operations task_file_seq_ops = {
	.start	= task_file_seq_start,
	.next	= task_file_seq_next,
	.stop	= task_file_seq_stop,
	.show	= task_file_seq_show,
};

/*
 * Key information from vm_area_struct. We need this because we cannot
 * assume the vm_area_struct is still valid after each iteration.
 */
struct __vm_area_struct {
	__u64 start;
	__u64 end;
	__u64 flags;
	__u64 pgoff;
};

struct bpf_iter_seq_task_vma_info {
	/* The first field must be struct bpf_iter_seq_task_common.
	 * this is assumed by {init, fini}_seq_pidns() callback functions.
	 */
	struct bpf_iter_seq_task_common common;
	struct task_struct *task;
	struct __vm_area_struct vma;
	struct file *file;
	u32 tid;
};

static struct __vm_area_struct *
task_vma_seq_get_next(struct bpf_iter_seq_task_vma_info *info)
{
	struct pid_namespace *ns = info->common.ns;
	struct task_struct *curr_task;
	struct vm_area_struct *vma;
	u32 curr_tid = info->tid;
	bool new_task = false;

	/* If this function returns a non-NULL __vm_area_struct, it held
	 * a reference to the task_struct. If info->file is non-NULL, it
	 * also holds a reference to the file. If this function returns
	 * NULL, it does not hold any reference.
	 */
again:
	if (info->task) {
		curr_task = info->task;
	} else {
		curr_task = task_seq_get_next(ns, &curr_tid, true);
		if (!curr_task) {
			info->task = NULL;
			info->tid++;
			return NULL;
		}

		if (curr_tid != info->tid) {
			info->tid = curr_tid;
			new_task = true;
		}

		if (!curr_task->mm)
			goto next_task;
		info->task = curr_task;
	}

	mmap_read_lock(curr_task->mm);
	if (new_task) {
		vma = curr_task->mm->mmap;
	} else {
		/* We drop the lock between each iteration, so it is
		 * necessary to use find_vma() to find the next vma. This
		 * is similar to the mechanism in show_smaps_rollup().
		 */
		vma = find_vma(curr_task->mm, info->vma.end - 1);
		/* same vma as previous iteration, use vma->next */
		if (vma && (vma->vm_start == info->vma.start))
			vma = vma->vm_next;
	}
	if (!vma) {
		mmap_read_unlock(curr_task->mm);
		goto next_task;
	}
	info->task = curr_task;
	info->vma.start = vma->vm_start;
	info->vma.end = vma->vm_end;
	info->vma.pgoff = vma->vm_pgoff;
	info->vma.flags = vma->vm_flags;
	if (vma->vm_file)
		info->file = get_file(vma->vm_file);
	mmap_read_unlock(curr_task->mm);
	return &info->vma;

next_task:
	put_task_struct(curr_task);
	info->task = NULL;
	curr_tid = ++(info->tid);
	goto again;
}

static void *task_vma_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct bpf_iter_seq_task_vma_info *info = seq->private;
	struct __vm_area_struct *vma;

	vma = task_vma_seq_get_next(info);
	if (vma && *pos == 0)
		++*pos;

	return vma;
}

static void *task_vma_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct bpf_iter_seq_task_vma_info *info = seq->private;

	++*pos;
	if (info->file) {
		fput(info->file);
		info->file = NULL;
	}
	return task_vma_seq_get_next(info);
}

struct bpf_iter__task_vma {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct task_struct *, task);
	__bpf_md_ptr(struct __vm_area_struct *, vma);
	__bpf_md_ptr(struct file *, file);
};

DEFINE_BPF_ITER_FUNC(task_vma, struct bpf_iter_meta *meta,
		     struct task_struct *task, struct __vm_area_struct *vma,
		     struct file *file)

static int __task_vma_seq_show(struct seq_file *seq, bool in_stop)
{
	struct bpf_iter_seq_task_vma_info *info = seq->private;
	struct bpf_iter__task_vma ctx;
	struct bpf_iter_meta meta;
	struct bpf_prog *prog;

	meta.seq = seq;
	prog = bpf_iter_get_info(&meta, in_stop);
	if (!prog)
		return 0;

	ctx.meta = &meta;
	ctx.task = info->task;
	ctx.vma = &info->vma;
	ctx.file = info->file;
	return bpf_iter_run_prog(prog, &ctx);
}

static int task_vma_seq_show(struct seq_file *seq, void *v)
{
	return __task_vma_seq_show(seq, false);
}

static void task_vma_seq_stop(struct seq_file *seq, void *v)
{
	struct bpf_iter_seq_task_vma_info *info = seq->private;

	if (!v) {
		(void)__task_vma_seq_show(seq, true);
	} else {
		put_task_struct(info->task);
		if (info->file) {
			fput(info->file);
			info->file = NULL;
		}
		info->task = NULL;
	}
}

static const struct seq_operations task_vma_seq_ops = {
	.start	= task_vma_seq_start,
	.next	= task_vma_seq_next,
	.stop	= task_vma_seq_stop,
	.show	= task_vma_seq_show,
};

BTF_ID_LIST(btf_task_file_ids)
BTF_ID(struct, task_struct)
BTF_ID(struct, file)
BTF_ID(struct, __vm_area_struct)

static const struct bpf_iter_seq_info task_seq_info = {
	.seq_ops		= &task_seq_ops,
	.init_seq_private	= init_seq_pidns,
	.fini_seq_private	= fini_seq_pidns,
	.seq_priv_size		= sizeof(struct bpf_iter_seq_task_info),
};

static struct bpf_iter_reg task_reg_info = {
	.target			= "task",
	.feature		= BPF_ITER_RESCHED,
	.ctx_arg_info_size	= 1,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__task, task),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &task_seq_info,
};

static const struct bpf_iter_seq_info task_file_seq_info = {
	.seq_ops		= &task_file_seq_ops,
	.init_seq_private	= init_seq_pidns,
	.fini_seq_private	= fini_seq_pidns,
	.seq_priv_size		= sizeof(struct bpf_iter_seq_task_file_info),
};

static struct bpf_iter_reg task_file_reg_info = {
	.target			= "task_file",
	.feature		= BPF_ITER_RESCHED,
	.ctx_arg_info_size	= 2,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__task_file, task),
		  PTR_TO_BTF_ID_OR_NULL },
		{ offsetof(struct bpf_iter__task_file, file),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &task_file_seq_info,
};

static const struct bpf_iter_seq_info task_vma_seq_info = {
	.seq_ops		= &task_vma_seq_ops,
	.init_seq_private	= init_seq_pidns,
	.fini_seq_private	= fini_seq_pidns,
	.seq_priv_size		= sizeof(struct bpf_iter_seq_task_vma_info),
};

static struct bpf_iter_reg task_vma_reg_info = {
	.target			= "task_vma",
	.feature		= BPF_ITER_RESCHED,
	.ctx_arg_info_size	= 3,
	.ctx_arg_info		= {
		{ offsetof(struct bpf_iter__task_vma, task),
		  PTR_TO_BTF_ID_OR_NULL },
		{ offsetof(struct bpf_iter__task_vma, vma),
		  PTR_TO_BTF_ID_OR_NULL },
		{ offsetof(struct bpf_iter__task_vma, file),
		  PTR_TO_BTF_ID_OR_NULL },
	},
	.seq_info		= &task_vma_seq_info,
};

static int __init task_iter_init(void)
{
	int ret;

	task_reg_info.ctx_arg_info[0].btf_id = btf_task_file_ids[0];
	ret = bpf_iter_reg_target(&task_reg_info);
	if (ret)
		return ret;

	task_file_reg_info.ctx_arg_info[0].btf_id = btf_task_file_ids[0];
	task_file_reg_info.ctx_arg_info[1].btf_id = btf_task_file_ids[1];
	ret =  bpf_iter_reg_target(&task_file_reg_info);
	if (ret)
		return ret;

	task_vma_reg_info.ctx_arg_info[0].btf_id = btf_task_file_ids[0];
	task_vma_reg_info.ctx_arg_info[1].btf_id = btf_task_file_ids[2];
	task_vma_reg_info.ctx_arg_info[2].btf_id = btf_task_file_ids[1];
	return bpf_iter_reg_target(&task_vma_reg_info);
}
late_initcall(task_iter_init);
