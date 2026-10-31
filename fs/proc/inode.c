// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/proc/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/cache.h>
#include <linux/compat.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/pid_namespace.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/completion.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/uio.h>
#include <linux/mount.h>
#include <linux/bug.h>
#include <linux/wait_bit.h>

#include "internal.h"

static void proc_evict_inode(struct inode *inode)
{
	struct ctl_table_header *head;
	struct proc_inode *ei = PROC_I(inode);

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	/* Stop tracking associated processes */
	if (ei->pid)
		proc_pid_evict_inode(ei);

	head = ei->sysctl;
	if (head) {
		WRITE_ONCE(ei->sysctl, NULL);
		proc_sys_evict_inode(inode, head);
	}
}

static struct kmem_cache *proc_inode_cachep __ro_after_init;
static struct kmem_cache *pde_opener_cache __ro_after_init;

static struct inode *proc_alloc_inode(struct super_block *sb)
{
	struct proc_inode *ei;

	ei = alloc_inode_sb(sb, proc_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	ei->pid = NULL;
	ei->fd = 0;
	ei->op.proc_get_link = NULL;
	ei->pde = NULL;
	ei->sysctl = NULL;
	ei->sysctl_entry = NULL;
	INIT_HLIST_NODE(&ei->sibling_inodes);
	ei->ns_ops = NULL;
	return &ei->vfs_inode;
}

static void proc_free_inode(struct inode *inode)
{
	struct proc_inode *ei = PROC_I(inode);

	if (ei->pid)
		put_pid(ei->pid);
	/* Let go of any associated proc directory entry */
	if (ei->pde)
		pde_put(ei->pde);
	kmem_cache_free(proc_inode_cachep, PROC_I(inode));
}

static void init_once(void *foo)
{
	struct proc_inode *ei = (struct proc_inode *) foo;

	inode_init_once(&ei->vfs_inode);
}

void __init proc_init_kmemcache(void)
{
	proc_inode_cachep = kmem_cache_create("proc_inode_cache",
					     sizeof(struct proc_inode),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_ACCOUNT|
						SLAB_PANIC),
					     init_once);
	pde_opener_cache =
		kmem_cache_create("pde_opener", sizeof(struct pde_opener), 0,
				  SLAB_ACCOUNT|SLAB_PANIC, NULL);
	proc_dir_entry_cache = kmem_cache_create_usercopy(
		"proc_dir_entry", SIZEOF_PDE, 0, SLAB_PANIC,
		offsetof(struct proc_dir_entry, inline_name),
		SIZEOF_PDE_INLINE_NAME, NULL);
	BUILD_BUG_ON(sizeof(struct proc_dir_entry) >= SIZEOF_PDE);
}

void proc_invalidate_siblings_dcache(struct hlist_head *inodes, spinlock_t *lock)
{
	struct hlist_node *node;
	struct super_block *old_sb = NULL;

	rcu_read_lock();
	while ((node = hlist_first_rcu(inodes))) {
		struct proc_inode *ei = hlist_entry(node, struct proc_inode, sibling_inodes);
		struct super_block *sb;
		struct inode *inode;

		spin_lock(lock);
		hlist_del_init_rcu(&ei->sibling_inodes);
		spin_unlock(lock);

		inode = &ei->vfs_inode;
		sb = inode->i_sb;
		if ((sb != old_sb) && !atomic_inc_not_zero(&sb->s_active))
			continue;
		inode = igrab(inode);
		rcu_read_unlock();
		if (sb != old_sb) {
			if (old_sb)
				deactivate_super(old_sb);
			old_sb = sb;
		}
		if (unlikely(!inode)) {
			rcu_read_lock();
			continue;
		}

		if (S_ISDIR(inode->i_mode)) {
			struct dentry *dir = d_find_any_alias(inode);
			if (dir) {
				d_invalidate(dir);
				dput(dir);
			}
		} else {
			struct dentry *dentry;
			while ((dentry = d_find_alias(inode))) {
				d_invalidate(dentry);
				dput(dentry);
			}
		}
		iput(inode);

		rcu_read_lock();
	}
	rcu_read_unlock();
	if (old_sb)
		deactivate_super(old_sb);
}

static inline const char *hidepid2str(enum proc_hidepid v)
{
	switch (v) {
		case HIDEPID_OFF: return "off";
		case HIDEPID_NO_ACCESS: return "noaccess";
		case HIDEPID_INVISIBLE: return "invisible";
		case HIDEPID_NOT_PTRACEABLE: return "ptraceable";
	}
	WARN_ONCE(1, "bad hide_pid value: %d\n", v);
	return "unknown";
}

static int proc_show_options(struct seq_file *seq, struct dentry *root)
{
	struct proc_fs_info *fs_info = proc_sb_info(root->d_sb);

	if (!gid_eq(fs_info->pid_gid, GLOBAL_ROOT_GID))
		seq_printf(seq, ",gid=%u", from_kgid_munged(&init_user_ns, fs_info->pid_gid));
	if (fs_info->hide_pid != HIDEPID_OFF)
		seq_printf(seq, ",hidepid=%s", hidepid2str(fs_info->hide_pid));
	if (fs_info->pidonly != PROC_PIDONLY_OFF)
		seq_printf(seq, ",subset=pid");

	return 0;
}

const struct super_operations proc_sops = {
	.alloc_inode	= proc_alloc_inode,
	.free_inode	= proc_free_inode,
	.drop_inode	= inode_just_drop,
	.evict_inode	= proc_evict_inode,
	.statfs		= simple_statfs,
	.show_options	= proc_show_options,
};

enum {BIAS = -1U<<31};

/*
 * To lockdep the pin is a read lock and proc_entry_rundown() takes the write
 * side, see pde_lockdep_init(). So a method that takes a lock while pinned
 * and a removal under that lock are the deadlock lockdep knows how to report.
 */
static inline int use_pde(struct proc_dir_entry *pde)
{
	if (unlikely(!atomic_inc_unless_negative(&pde->in_use)))
		return 0;
	if (pde_lockdep(pde))
		rwsem_acquire_read(&pde->dep_map, 0, 1, _RET_IP_);
	return 1;
}

static void unuse_pde(struct proc_dir_entry *pde)
{
	if (pde_lockdep(pde))
		rwsem_release(&pde->dep_map, _RET_IP_);
	if (unlikely(atomic_dec_return(&pde->in_use) == BIAS))
		wake_up_var(&pde->in_use);
}

/* Pin an entry that can go away around a call into it, see use_pde(). */
static bool pde_pin(struct proc_dir_entry *pde)
{
	return pde_is_permanent(pde) || use_pde(pde);
}

static void pde_unpin(struct proc_dir_entry *pde)
{
	if (!pde_is_permanent(pde))
		unuse_pde(pde);
}

/*
 * procfs owns the seq_file of a seq_file entry and only calls into the entry
 * with it pinned. A read copies to userspace without the pin, so a reader
 * that faults on its buffer doesn't hold up remove_proc_entry().
 *
 * The seq_operations the seq_file runs are the entry's own next and show
 * with procfs's start and stop around them, see pde_init_seq_direct(): the
 * pin is taken in start and dropped in stop, and nothing sits between the
 * seq_file and the entry's per record code. An entry that only has a show
 * function is iterated like single_open() does it.
 *
 * If the pin fails start switches the seq_file to seq_operations whose stop
 * doesn't unpin, so that the entry's own start or next can return any error
 * they like, ERR_PTR(-EIO) included.
 */
static struct proc_dir_entry *seq_pde(struct seq_file *m)
{
	return PDE(file_inode(m->file));
}

static void pde_seq_stop_unpinned(struct seq_file *m, void *v)
{
	m->op = seq_pde(m)->seq_direct;
}

static const struct seq_operations pde_seq_ops_unpinned = {
	.start	= pde_seq_start,
	.stop	= pde_seq_stop_unpinned,
};

void *pde_seq_start(struct seq_file *m, loff_t *pos)
{
	struct proc_dir_entry *pde = seq_pde(m);

	if (!pde_pin(pde)) {
		m->op = &pde_seq_ops_unpinned;
		return ERR_PTR(-EIO);
	}
	m->op = pde->seq_direct;
	if (!pde_has_proc_seq_ops(pde))
		return single_start(m, pos);
	return pde->seq_ops->start(m, pos);
}

void pde_seq_stop(struct seq_file *m, void *v)
{
	struct proc_dir_entry *pde = seq_pde(m);

	if (pde_has_proc_seq_ops(pde))
		pde->seq_ops->stop(m, v);
	pde_unpin(pde);
}

/* what single_open() iterates with, seq_file keeps its own private */
void *pde_single_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static int pde_seq_open(struct proc_dir_entry *pde, struct file *file)
{
	int err;

	if (pde->state_size)
		return seq_open_private(file, pde->seq_direct, pde->state_size);
	err = seq_open(file, pde->seq_direct);
	if (!err && pde_has_proc_show(pde))
		((struct seq_file *)file->private_data)->private = pde->data;
	return err;
}

static void pde_seq_release(struct proc_dir_entry *pde, struct inode *inode,
			    struct file *file)
{
	if (pde->state_size)
		seq_release_private(inode, file);
	else
		seq_release(inode, file);
}

/*
 * At most 2 contexts can enter this function: the one doing the last
 * close on the descriptor and whoever is deleting PDE itself.
 *
 * First to enter calls ->proc_release hook and signals its completion
 * to the second one which waits and then does nothing.
 *
 * PDE is locked on entry, unlocked on exit.
 */
static void close_pdeo(struct proc_dir_entry *pde, struct pde_opener *pdeo,
		       bool rundown)
	__releases(&pde->pde_unload_lock)
{
	/*
	 * close() (proc_reg_release()) can't delete an entry and proceed:
	 * ->release hook needs to be available at the right moment.
	 *
	 * rmmod (remove_proc_entry() et al) can't delete an entry and proceed:
	 * "struct file" needs to be available at the right moment.
	 */
	if (pdeo->closing) {
		/* somebody else is doing that, just wait */
		DECLARE_COMPLETION_ONSTACK(c);
		pdeo->c = &c;
		spin_unlock(&pde->pde_unload_lock);
		wait_for_completion(&c);
	} else {
		struct file *file;
		struct completion *c;

		pdeo->closing = true;
		spin_unlock(&pde->pde_unload_lock);

		file = pdeo->file;
		/*
		 * A mapping of a removed entry faults, see proc_vm_ops. Like
		 * kernfs this unmaps the entry's own address space. A file
		 * that maps through another one, /proc/bus/pci through the
		 * iomem address space of /dev/mem, keeps its mappings like a
		 * sysfs resource file does.
		 */
		if (rundown && pde->open->vm_ops)
			unmap_mapping_range(file_inode(file)->i_mapping, 0, 0, 1);
		if (pde->proc_ops->proc_release)
			pde->proc_ops->proc_release(file_inode(file), file);

		spin_lock(&pde->pde_unload_lock);
		/* Strictly after ->proc_release, see above. */
		list_del(&pdeo->lh);
		c = pdeo->c;
		spin_unlock(&pde->pde_unload_lock);
		if (unlikely(c))
			complete(c);
		kmem_cache_free(pde_opener_cache, pdeo);
	}
}

void proc_entry_rundown(struct proc_dir_entry *de)
{
	/*
	 * Wait until all existing callers into module are done. That's the
	 * write side of the pin to lockdep, see use_pde().
	 */
	if (pde_lockdep(de))
		rwsem_acquire(&de->dep_map, 0, 0, _RET_IP_);
	if (atomic_add_return(BIAS, &de->in_use) != BIAS) {
		if (pde_lockdep(de))
			lock_contended(&de->dep_map, _RET_IP_);
		wait_var_event(&de->in_use, atomic_read_acquire(&de->in_use) == BIAS);
	}
	if (pde_lockdep(de)) {
		lock_acquired(&de->dep_map, _RET_IP_);
		rwsem_release(&de->dep_map, _RET_IP_);
	}

	if (!de->open)
		return;
	/* a poll of a removed entry reports EPOLLERR, see proc_reg_poll() */
	if (pde_has_proc_poll(de))
		wake_up_interruptible_all(&de->open->poll);

	/* ->open->files can't grow from now on. */
	if (!pde_tracks_files(de))
		return;
	spin_lock(&de->pde_unload_lock);
	while (!list_empty(&de->open->files)) {
		struct pde_opener *pdeo;
		pdeo = list_first_entry(&de->open->files, struct pde_opener, lh);
		close_pdeo(de, pdeo, true);
		spin_lock(&de->pde_unload_lock);
	}
	spin_unlock(&de->pde_unload_lock);
}

static loff_t proc_reg_llseek(struct file *file, loff_t offset, int whence)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	loff_t rv;

	if (!pde_pin(pde))
		return -EINVAL;
	rv = pde->proc_ops->proc_lseek(file, offset, whence);
	pde_unpin(pde);
	return rv;
}

/*
 * The entry fills a kernel buffer and procfs copies that to userspace after
 * unpinning the entry. A reader that faults on its buffer then doesn't hold
 * up remove_proc_entry().
 */
static ssize_t pde_read_buf(struct proc_dir_entry *pde, struct kiocb *iocb,
			    struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	char *buf __free(kvfree) = NULL;
	ssize_t rv, done = 0;
	size_t len, count;
	loff_t pos;

	if (!iov_iter_count(iter))
		return 0;
	/* neither the allocation nor the entry can honor IOCB_NOWAIT */
	if ((iocb->ki_flags & IOCB_NOWAIT) && !(file->f_flags & O_NONBLOCK))
		return -EAGAIN;
	len = min_t(size_t, iov_iter_count(iter), pde->read_size);
	buf = kvmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* PROC_ENTRY_FULL_READS fills the read in pieces */
	do {
		count = min_t(size_t, iov_iter_count(iter), len);
		pos = iocb->ki_pos;
		if (!pde_pin(pde)) {
			rv = -EIO;
			break;
		}
		rv = pde->proc_ops->proc_read_buf(file, buf, count, &pos);
		pde_unpin(pde);
		if (rv <= 0)
			break;
		if (WARN_ON_ONCE(rv > count)) {
			rv = -EIO;
			break;
		}
		if (copy_to_iter(buf, rv, iter) != rv) {
			rv = -EFAULT;
			break;
		}
		iocb->ki_pos = pos;
		done += rv;
		if (!pde_has_full_reads(pde) || rv < count)
			break;
		cond_resched();
	} while (iov_iter_count(iter) && !fatal_signal_pending(current));

	return done ?: rv;
}

static ssize_t proc_reg_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct proc_dir_entry *pde = PDE(file_inode(iocb->ki_filp));
	ssize_t ret;

	if (pde_has_proc_read_buf(pde))
		return pde_read_buf(pde, iocb, iter);
	if (!pde_pin(pde))
		return -EIO;
	ret = pde->proc_ops->proc_read_iter(iocb, iter);
	pde_unpin(pde);
	return ret;
}

static ssize_t pde_read(struct proc_dir_entry *pde, struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	const auto read = pde->proc_ops->proc_read;
	if (read)
		return read(file, buf, count, ppos);
	return -EIO;
}

static ssize_t proc_reg_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	ssize_t rv;

	if (!pde_pin(pde))
		return -EIO;
	rv = pde_read(pde, file, buf, count, ppos);
	pde_unpin(pde);
	return rv;
}

/*
 * procfs copies in what is written before it pins the entry. A writer that
 * faults on its buffer then doesn't hold up remove_proc_entry().
 */
static ssize_t pde_write_buf(struct proc_dir_entry *pde, struct kiocb *iocb,
			     struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	size_t count = iov_iter_count(from), size;
	char *buf __free(kvfree) = NULL;
	ssize_t rv;

	size = pde->write_size;
	if (count > size) {
		if (!pde_has_short_writes(pde))
			return -EINVAL;
		count = size;
	}
	buf = kvmalloc(count + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	if (copy_from_iter(buf, count, from) != count)
		return -EFAULT;
	buf[count] = '\0';

	if (!pde_pin(pde))
		return -EIO;
	/* a stream has no position, like with ->write() */
	rv = pde->proc_ops->proc_write_buf(file, buf, count,
			(file->f_mode & FMODE_STREAM) ? NULL : &iocb->ki_pos);
	pde_unpin(pde);
	return rv;
}

static ssize_t proc_reg_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct proc_dir_entry *pde = PDE(file_inode(iocb->ki_filp));

	if (pde_has_proc_write_buf(pde))
		return pde_write_buf(pde, iocb, from);
	return -EIO;
}

/*
 * The pollers of an entry sleep on a wait queue procfs owns, which is there
 * for as long as the entry's inode is, however the entry's owner goes away.
 * The owner wakes them through proc_poll_notify(), and procfs does when the
 * entry is removed: a poll of a removed entry reports EPOLLERR | EPOLLPRI,
 * like kernfs_fop_poll().
 */
static __poll_t proc_reg_poll(struct file *file, struct poll_table_struct *pts)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	__poll_t rv;

	if (!pde_has_proc_poll(pde))
		return DEFAULT_POLLMASK;
	if (!pde_pin(pde))
		return DEFAULT_POLLMASK | EPOLLERR | EPOLLPRI;
	rv = pde->proc_ops->proc_poll(file, pts);
	pde_unpin(pde);
	return rv;
}

/**
 * proc_poll_notify - wake up the pollers of an entry
 * @pde: an entry with a ->proc_poll(), may be NULL
 *
 * May be called from any context, as long as the entry is still registered.
 * procfs doesn't pin it here, the caller keeps it alive like it does for
 * every other use of the pointer proc_create() returned.
 */
void proc_poll_notify(struct proc_dir_entry *pde)
{
	if (!pde)
		return;
	if (WARN_ON_ONCE(!pde_has_proc_poll(pde)))
		return;
	wake_up_interruptible_all(&pde->open->poll);
}
EXPORT_SYMBOL_GPL(proc_poll_notify);

/**
 * pde_poll_wait - sleep a poller on the wait queue procfs owns for an entry
 * @file: the file ->proc_poll() was called with
 * @pts: the poll_table ->proc_poll() was called with
 *
 * For a ->proc_poll() whose owner wakes the pollers with proc_poll_notify().
 * procfs doesn't do this for every entry yet: one that still sleeps its
 * pollers on a queue of its own would be on two queues for one poll then,
 * and Linux AIO supports one queue per file, see aio_poll_queue_proc(). Once
 * every entry sleeps on the procfs queue the poll_wait() moves into
 * proc_reg_poll().
 */
void pde_poll_wait(struct file *file, struct poll_table_struct *pts)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));

	poll_wait(file, &pde->open->poll, pts);
}
EXPORT_SYMBOL_GPL(pde_poll_wait);

/* the table lives in proc_ops, which goes away with the entry */
static bool pde_ioctl_arg(struct proc_dir_entry *pde, unsigned int cmd,
			  struct proc_ioctl_arg *arg)
{
	const struct proc_ops *proc_ops = pde->proc_ops;
	bool found = false;

	if (!pde_pin(pde))
		return false;
	for (unsigned int i = 0; i < proc_ops->proc_nr_ioctl_args; i++) {
		if (proc_ops->proc_ioctl_args[i].cmd == cmd) {
			*arg = proc_ops->proc_ioctl_args[i];
			found = true;
			break;
		}
	}
	pde_unpin(pde);
	return found;
}

/*
 * procfs copies the argument in before it pins the entry and copies it back
 * out after unpinning it. An ioctl that faults on its argument then doesn't
 * hold up remove_proc_entry().
 */
static long pde_ioctl_buf(struct proc_dir_entry *pde, struct file *file,
			  unsigned int cmd, void __user *uarg, unsigned long arg)
{
	void *buf __free(kvfree) = NULL;
	struct proc_ioctl_arg a;
	size_t size;
	long rv;

	if (!pde_ioctl_arg(pde, cmd, &a))
		return -ENOTTY;
	size = max(a.in, a.out);
	if (size) {
		buf = kvzalloc(size, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		if (a.in && copy_from_user(buf, uarg, a.in))
			return -EFAULT;
	}

	if (!pde_pin(pde))
		return -ENOTTY;
	rv = pde->proc_ops->proc_ioctl_buf(file, cmd, buf ?: (void *)arg);
	pde_unpin(pde);
	if (rv >= 0 && a.out && copy_to_user(uarg, buf, a.out))
		return -EFAULT;
	return rv;
}

static long proc_reg_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));

	if (pde_has_proc_ioctl_buf(pde))
		return pde_ioctl_buf(pde, file, cmd, (void __user *)arg, arg);
	return -ENOTTY;
}

#ifdef CONFIG_COMPAT
static long proc_reg_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));

	if (pde_has_proc_ioctl_buf(pde))
		return pde_ioctl_buf(pde, file, cmd, compat_ptr(arg), arg);
	return -ENOTTY;
}
#else
#define proc_reg_compat_ioctl NULL
#endif

/*
 * The vm_operations of an entry's mappings run with the entry pinned, like
 * the entry's file methods do, and a mapping of a removed entry faults.
 * proc_entry_rundown() unmaps the mappings of every open file and a fault
 * after that finds the entry gone. Like kernfs_vm_ops, and like there only
 * these four methods of the entry's vm_operations are called.
 */
static void proc_vma_open(struct vm_area_struct *vma)
{
	struct proc_dir_entry *pde = PDE(file_inode(vma->vm_file));
	const struct vm_operations_struct *vm_ops = pde->open->vm_ops;

	if (!pde_pin(pde))
		return;
	if (vm_ops->open)
		vm_ops->open(vma);
	pde_unpin(pde);
}

static vm_fault_t proc_vma_fault(struct vm_fault *vmf)
{
	struct proc_dir_entry *pde = PDE(file_inode(vmf->vma->vm_file));
	const struct vm_operations_struct *vm_ops = pde->open->vm_ops;
	vm_fault_t ret = VM_FAULT_SIGBUS;

	if (!pde_pin(pde))
		return VM_FAULT_SIGBUS;
	if (vm_ops->fault)
		ret = vm_ops->fault(vmf);
	pde_unpin(pde);
	return ret;
}

static vm_fault_t proc_vma_page_mkwrite(struct vm_fault *vmf)
{
	struct proc_dir_entry *pde = PDE(file_inode(vmf->vma->vm_file));
	const struct vm_operations_struct *vm_ops = pde->open->vm_ops;
	vm_fault_t ret = 0;

	if (!pde_pin(pde))
		return VM_FAULT_SIGBUS;
	if (vm_ops->page_mkwrite)
		ret = vm_ops->page_mkwrite(vmf);
	else
		file_update_time(vmf->vma->vm_file);
	pde_unpin(pde);
	return ret;
}

static int proc_vma_access(struct vm_area_struct *vma, unsigned long addr,
			   void *buf, int len, int write)
{
	struct proc_dir_entry *pde = PDE(file_inode(vma->vm_file));
	const struct vm_operations_struct *vm_ops = pde->open->vm_ops;
	int ret = -EINVAL;

	if (!pde_pin(pde))
		return -EINVAL;
	if (vm_ops->access)
		ret = vm_ops->access(vma, addr, buf, len, write);
	pde_unpin(pde);
	return ret;
}

static const struct vm_operations_struct proc_vm_ops = {
	.open		= proc_vma_open,
	.fault		= proc_vma_fault,
	.page_mkwrite	= proc_vma_page_mkwrite,
	.access		= proc_vma_access,
};

static int pde_mmap(struct proc_dir_entry *pde, struct file *file,
		    struct vm_area_struct *vma)
{
	const auto mmap = pde->proc_ops->proc_mmap;
	struct pde_open_node *on = pde->open;
	int rv;

	if (!mmap)
		return -EIO;
	rv = mmap(file, vma);
	if (rv || pde_is_permanent(pde))
		return rv;
	/* the entry mapped something else, that isn't ours to wrap */
	if (vma->vm_file != file)
		return 0;
	/*
	 * ->close() can't be wrapped, it runs when the mapping goes away and
	 * that can be after the entry is gone, see close_pdeo().
	 */
	if (!vma->vm_ops || vma->vm_ops->close)
		return -EINVAL;

	/* every mapping of an entry uses the same vm_operations, see above */
	guard(spinlock)(&pde->pde_unload_lock);
	if (on->vm_ops && on->vm_ops != vma->vm_ops)
		return -EINVAL;
	on->vm_ops = vma->vm_ops;
	vma->vm_ops = &proc_vm_ops;
	return 0;
}

static int proc_reg_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	int rv;

	if (!pde_pin(pde))
		return -EIO;
	rv = pde_mmap(pde, file, vma);
	pde_unpin(pde);
	return rv;
}

static unsigned long
pde_get_unmapped_area(struct proc_dir_entry *pde, struct file *file, unsigned long orig_addr,
			   unsigned long len, unsigned long pgoff,
			   unsigned long flags)
{
	if (pde->proc_ops->proc_get_unmapped_area)
		return pde->proc_ops->proc_get_unmapped_area(file, orig_addr, len, pgoff, flags);

#ifdef CONFIG_MMU
	return mm_get_unmapped_area(file, orig_addr, len, pgoff, flags);
#endif

	return orig_addr;
}

static unsigned long
proc_reg_get_unmapped_area(struct file *file, unsigned long orig_addr,
			   unsigned long len, unsigned long pgoff,
			   unsigned long flags)
{
	struct proc_dir_entry *pde = PDE(file_inode(file));
	unsigned long rv;

	if (!pde_pin(pde))
		return -EIO;
	rv = pde_get_unmapped_area(pde, file, orig_addr, len, pgoff, flags);
	pde_unpin(pde);
	return rv;
}

#ifndef CONFIG_MMU
/*
 * NOMMU never calls ->proc_mmap() for a regular file. It reads the file into
 * a private copy instead, with nommu_region_sem held for writing, which
 * reading /proc/maps takes as well. Don't map procfs files at all.
 */
static unsigned int proc_reg_mmap_capabilities(struct file *file)
{
	return 0;
}
#endif

static int pde_open(struct proc_dir_entry *pde, struct inode *inode,
		    struct file *file)
{
	const auto open = pde->proc_ops->proc_open;
	int rv;

	if (!pde_is_seq_file(pde))
		return open ? open(inode, file) : 0;

	rv = pde_seq_open(pde, file);
	if (rv || !open)
		return rv;
	rv = open(inode, file);
	if (rv)
		pde_seq_release(pde, inode, file);
	return rv;
}

static int proc_reg_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	int rv = 0;
	struct pde_opener *pdeo;

	if (!pde_has_proc_lseek(pde))
		file->f_mode &= ~FMODE_LSEEK;

	if (pde_is_permanent(pde))
		return pde_open(pde, inode, file);

	/*
	 * Ensure that
	 * 1) PDE's ->release hook will be called no matter what
	 *    either normally by close()/->release, or forcefully by
	 *    rmmod/remove_proc_entry.
	 *
	 * 2) rmmod isn't blocked by opening file in /proc and sitting on
	 *    the descriptor (including "rmmod foo </proc/foo" scenario).
	 *
	 * Save every "struct file" with custom ->release hook, and every
	 * one that can be mapped, proc_entry_rundown() unmaps those. Those
	 * entries have an open node, see proc_register().
	 */
	if (!use_pde(pde))
		return -ENOENT;

	const bool track = pde_tracks_files(pde);
	if (track) {
		pdeo = kmem_cache_alloc(pde_opener_cache, GFP_KERNEL);
		if (!pdeo) {
			rv = -ENOMEM;
			goto out_unuse;
		}
	}

	rv = pde_open(pde, inode, file);

	if (track) {
		if (rv == 0) {
			/* To know what to release. */
			pdeo->file = file;
			pdeo->closing = false;
			pdeo->c = NULL;
			spin_lock(&pde->pde_unload_lock);
			list_add(&pdeo->lh, &pde->open->files);
			spin_unlock(&pde->pde_unload_lock);
		} else
			kmem_cache_free(pde_opener_cache, pdeo);
	}

out_unuse:
	unuse_pde(pde);
	return rv;
}

static int proc_reg_release(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *pde = PDE(inode);
	struct pde_opener *pdeo;

	if (pde_is_permanent(pde)) {
		const auto release = pde->proc_ops->proc_release;
		if (release)
			release(inode, file);
		goto out;
	}

	if (!pde_tracks_files(pde))
		goto out;
	spin_lock(&pde->pde_unload_lock);
	list_for_each_entry(pdeo, &pde->open->files, lh) {
		if (pdeo->file == file) {
			close_pdeo(pde, pdeo, false);
			goto out;
		}
	}
	spin_unlock(&pde->pde_unload_lock);
out:
	/* ->proc_release() has run, here or in remove_proc_entry() */
	if (pde_is_seq_file(pde))
		pde_seq_release(pde, inode, file);
	return 0;
}

/* For seq_file entries, see pde_seq_ops. */
static const struct file_operations proc_seq_file_ops = {
	.llseek		= seq_lseek,
	.read_iter	= seq_read_iter,
	.splice_read	= copy_splice_read,
	.write_iter	= proc_reg_write_iter,
	.splice_write	= iter_file_splice_write,
	.poll		= proc_reg_poll,
	.unlocked_ioctl	= proc_reg_unlocked_ioctl,
	.compat_ioctl	= proc_reg_compat_ioctl,
	.mmap		= proc_reg_mmap,
	.get_unmapped_area = proc_reg_get_unmapped_area,
#ifndef CONFIG_MMU
	.mmap_capabilities = proc_reg_mmap_capabilities,
#endif
	.open		= proc_reg_open,
	.release	= proc_reg_release,
};

static const struct file_operations proc_reg_file_ops = {
	.llseek		= proc_reg_llseek,
	.read		= proc_reg_read,
	.write_iter	= proc_reg_write_iter,
	.splice_write	= iter_file_splice_write,
	.poll		= proc_reg_poll,
	.unlocked_ioctl	= proc_reg_unlocked_ioctl,
	.compat_ioctl	= proc_reg_compat_ioctl,
	.mmap		= proc_reg_mmap,
	.get_unmapped_area = proc_reg_get_unmapped_area,
#ifndef CONFIG_MMU
	.mmap_capabilities = proc_reg_mmap_capabilities,
#endif
	.open		= proc_reg_open,
	.release	= proc_reg_release,
};

static const struct file_operations proc_iter_file_ops = {
	.llseek		= proc_reg_llseek,
	.read_iter	= proc_reg_read_iter,
	.write_iter	= proc_reg_write_iter,
	.splice_write	= iter_file_splice_write,
	.splice_read	= copy_splice_read,
	.poll		= proc_reg_poll,
	.unlocked_ioctl	= proc_reg_unlocked_ioctl,
	.compat_ioctl	= proc_reg_compat_ioctl,
	.mmap		= proc_reg_mmap,
	.get_unmapped_area = proc_reg_get_unmapped_area,
#ifndef CONFIG_MMU
	.mmap_capabilities = proc_reg_mmap_capabilities,
#endif
	.open		= proc_reg_open,
	.release	= proc_reg_release,
};

static const char *proc_get_link(struct dentry *dentry,
				 struct inode *inode,
				 struct delayed_call *done)
{
	struct proc_dir_entry *pde = PDE(inode);

	/*
	 * No pin. The link lives with the entry, which the inode holds, and a
	 * reader could fault while vfs_readlink() copies it out. Just don't
	 * follow a removed one.
	 */
	if (unlikely(atomic_read(&pde->in_use) < 0))
		return ERR_PTR(-EINVAL);
	return pde->data;
}

const struct inode_operations proc_link_inode_operations = {
	.get_link	= proc_get_link,
};

struct inode *proc_get_inode(struct super_block *sb, struct proc_dir_entry *de)
{
	struct inode *inode = new_inode(sb);

	if (!inode) {
		pde_put(de);
		return NULL;
	}

	inode->i_private = de->data;
	inode->i_ino = de->low_ino;
	simple_inode_init_ts(inode);
	PROC_I(inode)->pde = de;
	if (is_empty_pde(de)) {
		make_empty_dir_inode(inode);
		return inode;
	}

	if (de->mode) {
		inode->i_mode = de->mode;
		inode->i_uid = de->uid;
		inode->i_gid = de->gid;
	}
	if (de->size)
		inode->i_size = de->size;
	if (de->nlink)
		set_nlink(inode, de->nlink);

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = de->proc_iops;
		if (pde_has_proc_fops(de))
			inode->i_fop = de->proc_fops;
		else if (pde_is_seq_file(de))
			inode->i_fop = &proc_seq_file_ops;
		else if (pde_has_proc_read_iter(de) || pde_has_proc_read_buf(de))
			inode->i_fop = &proc_iter_file_ops;
		else
			inode->i_fop = &proc_reg_file_ops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = de->proc_iops;
		inode->i_fop = de->proc_dir_ops;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = de->proc_iops;
		inode->i_fop = NULL;
	} else {
		BUG();
	}
	return inode;
}
