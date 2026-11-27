// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2025, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Copyright (C) 2025 Amazon.com Inc. or its affiliates.
 * Pratyush Yadav <ptyadav@amazon.de>
 */

/**
 * DOC: Memfd Preservation via LUO
 *
 * Overview
 * ========
 *
 * Memory file descriptors (memfd) can be preserved over a kexec using the Live
 * Update Orchestrator (LUO) file preservation. This allows userspace to
 * transfer its memory contents to the next kernel after a kexec.
 *
 * The preservation is not intended to be transparent. Only select properties of
 * the file are preserved. All others are reset to default. The preserved
 * properties are described below.
 *
 * .. note::
 *    The LUO API is not stabilized yet, so the preserved properties of a memfd
 *    are also not stable and are subject to backwards incompatible changes.
 *
 * .. note::
 *    Currently a memfd backed by Hugetlb is not supported. Memfds created
 *    with ``MFD_HUGETLB`` will be rejected.
 *
 * Preserved Properties
 * ====================
 *
 * The following properties of the memfd are preserved across kexec:
 *
 * File Contents
 *   All data stored in the file is preserved.
 *
 * File Size
 *   The size of the file is preserved. Holes in the file are filled by
 *   allocating pages for them during preservation.
 *
 * File Position
 *   The current file position is preserved, allowing applications to continue
 *   reading/writing from their last position.
 *
 * File Status Flags
 *   memfds are always opened with ``O_RDWR`` and ``O_LARGEFILE``. This property
 *   is maintained.
 *
 * Seals
 *   File seals set on the memfd are preserved and re-applied on restore.
 *   Only seals known to this LUO version (see ``MEMFD_LUO_ALL_SEALS``) may
 *   be present; preservation fails with ``-EOPNOTSUPP`` otherwise.
 *
 * Restrictions
 * ============
 *
 * While a memfd is preserved, and after it is retrieved until the session is
 * finished, its size can't be changed and holes can't be punched in it.
 * ``ftruncate()`` and writes past the end of the file fail. ``fallocate()``
 * fails in all modes.
 *
 * Adding ``F_SEAL_WRITE`` also fails with ``-EBUSY`` while the memfd is
 * preserved, and after it is retrieved until the session is finished.
 * memfd_luo holds an extra reference on the memfd's folios, which the seal
 * treats as outstanding pins.
 *
 * Non-Preserved Properties
 * ========================
 *
 * All properties which are not preserved must be assumed to be reset to
 * default. This section describes some of those properties which may be more of
 * note.
 *
 * ``FD_CLOEXEC`` flag
 *   A memfd can be created with the ``MFD_CLOEXEC`` flag that sets the
 *   ``FD_CLOEXEC`` on the file. This flag is not preserved and must be set
 *   again after restore via ``fcntl()``.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bits.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/io.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/memfd.h>
#include <linux/liveupdate.h>
#include <linux/migrate.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/memfd.h>
#include <uapi/linux/memfd.h>

#include "internal.h"

static void memfd_luo_put_folios(const struct memfd_luo_folio_ser *folios_ser,
				 u64 nr_folios)
{
	u64 i;

	for (i = 0; i < nr_folios; i++) {
		const struct memfd_luo_folio_ser *pfolio = &folios_ser[i];
		struct folio *folio;

		if (!pfolio->pfn)
			continue;

		folio = pfn_folio(pfolio->pfn);

		kho_unpreserve_folio(folio);
		folio_put(folio);
	}
}

/* How many times to try migrating a folio that is not longterm pinnable. */
#define MEMFD_LUO_MIGRATE_RETRIES	3

/*
 * Preservation holds a longterm reference on the folio. This would block
 * migration in ZONE_MOVABLE or CMA. Move it out.
 *
 * Must be called with folio unlocked. Drops the reference to folio. The caller
 * must look it up again.
 *
 * Returns 0 on success, -EBUSY if the folio could not be isolated (e.g.
 * because someone else has it isolated right now), or -ENOMEM if migration
 * failed.
 */
static int memfd_luo_migrate_folio(struct folio *folio)
{
	struct migration_target_control mtc = {
		.nid = NUMA_NO_NODE,
		/* Not movable, so the target is neither in ZONE_MOVABLE nor CMA. */
		.gfp_mask = GFP_USER | __GFP_NOWARN,
		.reason = MR_LONGTERM_PIN,
	};
	LIST_HEAD(source);
	bool isolated;

	/* Flush per-CPU LRU batches holding the folio so isolation works. */
	lru_cache_drain_for_folio(folio, 1, NULL);
	isolated = isolate_folio_to_list(folio, &source);
	/* Isolation holds its own reference. */
	folio_put(folio);
	if (!isolated)
		return -EBUSY;

	if (migrate_pages(&source, alloc_migration_target, NULL,
			  (unsigned long)&mtc, MIGRATE_SYNC, MR_LONGTERM_PIN,
			  NULL)) {
		putback_movable_pages(&source);
		return -ENOMEM;
	}

	return 0;
}

/*
 * Look up the folio at @index, allocating it if needed. Preservation holds a
 * longterm reference on the folio, so folios that are not longterm pinnable are
 * migrated out first, giving up after a few attempts.
 *
 * On success, returns 0 with *@foliop locked and holding a reference.
 */
static int memfd_luo_get_folio(struct inode *inode, pgoff_t index,
			       struct folio **foliop)
{
	int err, retries = 0;
	struct folio *folio;

	for (;;) {
		err = shmem_get_folio(inode, index, 0, &folio, SGP_CACHE);
		if (err)
			return err;

		if (likely(folio_is_longterm_pinnable(folio)))
			break;

		folio_unlock(folio);

		if (retries == MEMFD_LUO_MIGRATE_RETRIES) {
			folio_put(folio);
			return -EBUSY;
		}

		err = memfd_luo_migrate_folio(folio);
		/* Someone else might have it isolated, retry a bit. */
		if (err && err != -EBUSY)
			return err;

		retries++;
	}

	*foliop = folio;
	return 0;
}

static int memfd_luo_preserve_folio(struct folio *folio,
				    struct memfd_luo_folio_ser *pfolio)
{
	int err;

	err = kho_preserve_folio(folio);
	if (err)
		return err;

	/*
	 * A dirty folio is one which has been written to. A clean folio
	 * is its opposite. Since a clean folio does not carry user
	 * data, it can be freed by page reclaim under memory pressure.
	 *
	 * Saving the dirty flag at prepare() time doesn't work since it
	 * can change later. Saving it at freeze() also won't work
	 * because the dirty bit is normally synced at unmap and there
	 * might still be a mapping of the file at freeze().
	 *
	 * To see why this is a problem, say a folio is clean at
	 * preserve, but gets dirtied later. The pfolio flags will mark
	 * it as clean. After retrieve, the next kernel might try to
	 * reclaim this folio under memory pressure, losing user data.
	 *
	 * Unconditionally mark it dirty to avoid this problem. This
	 * comes at the cost of making clean folios un-reclaimable after
	 * live update.
	 */
	folio_mark_dirty(folio);

	pfolio->pfn = folio_pfn(folio);
	pfolio->flags = MEMFD_LUO_FOLIO_DIRTY | MEMFD_LUO_FOLIO_UPTODATE;
	pfolio->index = folio->index;

	return 0;
}

static int memfd_luo_preserve_folios(struct file *file,
				     struct kho_vmalloc *kho_vmalloc,
				     struct memfd_luo_folio_ser **out_folios_ser,
				     u64 *nr_foliosp)
{
	struct memfd_luo_folio_ser *folios_ser, *shrunk;
	struct inode *inode = file_inode(file);
	u64 nr_folios = 0, max_folios;
	unsigned int pin_flags;
	pgoff_t index = 0, end;
	int err;
	loff_t size;

	size = i_size_read(inode);
	/*
	 * If the file has zero size, then the folios and nr_folios properties
	 * are not set.
	 */
	if (!size) {
		*nr_foliosp = 0;
		*out_folios_ser = NULL;
		return 0;
	}

	/*
	 * Guess the number of folios based on inode size. Real number might end
	 * up being smaller if there are higher order folios.
	 */
	end = DIV_ROUND_UP_ULL(size, PAGE_SIZE);
	max_folios = end;
	folios_ser = vmalloc_array(max_folios, sizeof(*folios_ser));
	if (!folios_ser)
		return -ENOMEM;

	/*
	 * Preservation holds a longterm reference on the folios, so keep newly
	 * allocated ones out of ZONE_MOVABLE and CMA -- which also ensures they
	 * don't fall in KHO bootmem. Existing ones are migrated below.
	 *
	 * A side effect of this is that it allocates a folio for all indices in
	 * the file. This might waste memory on sparse memfds. If that is really
	 * a problem in the future, this loop can be taught to skip empty slots.
	 */
	pin_flags = memalloc_pin_save();
	while (index < end) {
		struct folio *folio;

		cond_resched();

		if (fatal_signal_pending(current)) {
			err = -EINTR;
			goto err_restore;
		}

		if (WARN_ON_ONCE(nr_folios >= max_folios)) {
			err = -EINVAL;
			goto err_restore;
		}

		err = memfd_luo_get_folio(inode, index, &folio);
		if (err)
			goto err_restore;

		err = memfd_luo_preserve_folio(folio, &folios_ser[nr_folios]);
		index = folio_next_index(folio);
		folio_unlock(folio);
		if (err) {
			folio_put(folio);
			goto err_restore;
		}
		nr_folios++;
	}
	memalloc_pin_restore(pin_flags);

	/*
	 * Free the unused tail so it doesn't get preserved. If vrealloc fails,
	 * the folios_ser is still valid.
	 */
	shrunk = vrealloc(folios_ser, array_size(nr_folios, sizeof(*folios_ser)),
			  GFP_KERNEL);
	if (shrunk)
		folios_ser = shrunk;

	err = kho_preserve_vmalloc(folios_ser, kho_vmalloc);
	if (err)
		goto err_put;

	*nr_foliosp = nr_folios;
	*out_folios_ser = folios_ser;

	/*
	 * Note: folios_ser is purposely not freed here. It is preserved
	 * memory (via KHO). In the 'unpreserve' path, we use the vmap pointer
	 * that is passed via private_data.
	 */
	return 0;

err_restore:
	memalloc_pin_restore(pin_flags);
err_put:
	memfd_luo_put_folios(folios_ser, nr_folios);
	vfree(folios_ser);
	return err;
}

static void memfd_luo_unpreserve_folios(struct kho_vmalloc *kho_vmalloc,
					struct memfd_luo_folio_ser *folios_ser,
					u64 nr_folios)
{
	if (!nr_folios)
		return;

	kho_unpreserve_vmalloc(kho_vmalloc);
	memfd_luo_put_folios(folios_ser, nr_folios);
	vfree(folios_ser);
}

static int memfd_luo_preserve(struct liveupdate_file_op_args *args)
{
	struct inode *inode = file_inode(args->file);
	struct memfd_luo_folio_ser *folios_ser;
	struct memfd_luo_ser *ser;
	u64 nr_folios, inode_size;
	int err = 0, seals;

	inode_lock(inode);
	shmem_freeze(inode, true);

	/* Allocate the main serialization structure in preserved memory */
	ser = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(ser)) {
		err = PTR_ERR(ser);
		goto err_unlock;
	}

	seals = memfd_get_seals(args->file);
	if (seals < 0) {
		err = seals;
		goto err_free_ser;
	}

	/* Make sure the file only has the seals supported by this version. */
	if (seals & ~MEMFD_LUO_ALL_SEALS) {
		err = -EOPNOTSUPP;
		goto err_free_ser;
	}

	ser->pos = args->file->f_pos;
	inode_size = i_size_read(inode);

	ser->size = inode_size;
	ser->seals = seals;

	err = memfd_luo_preserve_folios(args->file, &ser->folios,
					&folios_ser, &nr_folios);
	if (err)
		goto err_free_ser;

	ser->nr_folios = nr_folios;
	inode_unlock(inode);

	args->private_data = folios_ser;
	args->serialized_data = virt_to_phys(ser);

	return 0;

err_free_ser:
	kho_unpreserve_free(ser);
err_unlock:
	shmem_freeze(inode, false);
	inode_unlock(inode);
	return err;
}

static int memfd_luo_freeze(struct liveupdate_file_op_args *args)
{
	struct memfd_luo_ser *ser;

	if (WARN_ON_ONCE(!args->serialized_data))
		return -EINVAL;

	ser = phys_to_virt(args->serialized_data);

	/*
	 * The pos might have changed since prepare. Everything else stays the
	 * same.
	 */
	ser->pos = args->file->f_pos;

	return 0;
}

static void memfd_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	struct inode *inode = file_inode(args->file);
	struct memfd_luo_ser *ser;

	if (WARN_ON_ONCE(!args->serialized_data))
		return;

	inode_lock(inode);
	shmem_freeze(inode, false);

	ser = phys_to_virt(args->serialized_data);

	memfd_luo_unpreserve_folios(&ser->folios, args->private_data,
				    ser->nr_folios);

	kho_unpreserve_free(ser);
	inode_unlock(inode);
}

static void memfd_luo_discard_folios(const struct memfd_luo_folio_ser *folios_ser,
				     u64 nr_folios)
{
	u64 i;

	for (i = 0; i < nr_folios; i++) {
		const struct memfd_luo_folio_ser *pfolio = &folios_ser[i];
		struct folio *folio;
		phys_addr_t phys;

		if (!pfolio->pfn)
			continue;

		phys = PFN_PHYS(pfolio->pfn);
		folio = kho_restore_folio(phys);
		if (!folio) {
			pr_warn_ratelimited("Unable to restore folio at physical address: %llx\n",
					    phys);
			continue;
		}

		folio_put(folio);
	}
}

/* Drop the references retrieve() holds on the folios added to the file. */
static void
memfd_luo_put_retrieved_folios(const struct memfd_luo_folio_ser *folios_ser,
			       u64 nr_folios)
{
	for (u64 i = 0; i < nr_folios; i++) {
		const struct memfd_luo_folio_ser *pfolio = &folios_ser[i];

		if (pfolio->pfn)
			folio_put(pfn_folio(pfolio->pfn));
	}
}

static void memfd_luo_finish(struct liveupdate_file_op_args *args)
{
	struct memfd_luo_folio_ser *folios_ser;
	struct memfd_luo_ser *ser;

	/* If retrieve failed, it already cleaned up everything it could. */
	if (args->retrieve_status < 0)
		return;

	ser = phys_to_virt(args->serialized_data);
	if (!ser)
		return;

	if (args->retrieve_status > 0) {
		/*
		 * Retrieve was successful, release the folios and unfreeze the
		 * file so it can be used normally.
		 */
		struct inode *inode = file_inode(args->file);

		folios_ser = args->private_data;

		inode_lock(inode);
		memfd_luo_put_retrieved_folios(folios_ser, ser->nr_folios);
		shmem_freeze(inode, false);
		inode_unlock(inode);

		vfree(folios_ser);
	} else if (args->retrieve_status == 0 && ser->nr_folios) {
		/* Retrieve was not called, discard the preserved folios. */
		folios_ser = kho_restore_vmalloc(&ser->folios);
		if (folios_ser) {
			memfd_luo_discard_folios(folios_ser, ser->nr_folios);
			vfree(folios_ser);
		}
	}

	kho_restore_free(ser);
}

static int memfd_luo_retrieve_folios(struct file *file,
				     struct memfd_luo_folio_ser *folios_ser,
				     u64 nr_folios)
{
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	struct folio *folio;
	long npages, nr_added_pages = 0;
	int err = -EIO;
	long i;

	for (i = 0; i < nr_folios; i++) {
		const struct memfd_luo_folio_ser *pfolio = &folios_ser[i];
		phys_addr_t phys;
		u64 index;
		int flags;

		if (!pfolio->pfn)
			continue;

		phys = PFN_PHYS(pfolio->pfn);
		folio = kho_restore_folio(phys);
		if (!folio) {
			pr_err("Unable to restore folio at physical address: %llx\n",
			       phys);
			err = -EIO;
			goto put_folios;
		}
		index = pfolio->index;
		flags = pfolio->flags;

		/* Set up the folio for insertion. */
		__folio_set_locked(folio);
		__folio_set_swapbacked(folio);

		err = mem_cgroup_charge(folio, NULL, mapping_gfp_mask(mapping));
		if (err) {
			pr_err("shmem: failed to charge folio index %ld: %d\n",
			       i, err);
			goto unlock_folio;
		}

		err = shmem_add_to_page_cache(folio, mapping, index, NULL,
					      mapping_gfp_mask(mapping));
		if (err) {
			pr_err("shmem: failed to add to page cache folio index %ld: %d\n",
			       i, err);
			goto unlock_folio;
		}

		if (flags & MEMFD_LUO_FOLIO_UPTODATE)
			folio_mark_uptodate(folio);
		if (flags & MEMFD_LUO_FOLIO_DIRTY)
			folio_mark_dirty(folio);

		npages = folio_nr_pages(folio);
		err = shmem_inode_acct_blocks(inode, npages);
		if (err) {
			pr_err("shmem: failed to account folio index %ld(%ld pages): %d\n",
			       i, npages, err);
			goto remove_from_cache;
		}

		nr_added_pages += npages;
		folio_add_lru(folio);
		folio_unlock(folio);
		/*
		 * Keep the reference from kho_restore_folio(). It is dropped
		 * in finish().
		 */
	}

	shmem_recalc_inode(inode, nr_added_pages, 0);

	return 0;

remove_from_cache:
	filemap_remove_folio(folio);
unlock_folio:
	folio_unlock(folio);
	folio_put(folio);
put_folios:
	/*
	 * Drop the references held on the folios already added to the file.
	 * The folios themselves will be freed when the file is freed.
	 */
	memfd_luo_put_retrieved_folios(folios_ser, i);

	/* Free the ones not added yet here. */
	for (long j = i + 1; j < nr_folios; j++) {
		const struct memfd_luo_folio_ser *pfolio = &folios_ser[j];
		phys_addr_t phys;

		if (!pfolio->pfn)
			continue;

		phys = PFN_PHYS(pfolio->pfn);
		folio = kho_restore_folio(phys);
		if (folio)
			folio_put(folio);
	}

	shmem_recalc_inode(inode, nr_added_pages, 0);

	return err;
}

static int memfd_luo_retrieve(struct liveupdate_file_op_args *args)
{
	struct memfd_luo_folio_ser *folios_ser = NULL;
	struct memfd_luo_ser *ser;
	struct file *file;
	int err;

	ser = phys_to_virt(args->serialized_data);
	if (!ser)
		return -EINVAL;

	/* Make sure the file only has seals supported by this version. */
	if (ser->seals & ~MEMFD_LUO_ALL_SEALS) {
		err = -EOPNOTSUPP;
		goto free_ser;
	}

	/*
	 * The seals are preserved. Allow sealing here so they can be added
	 * later.
	 */
	file = memfd_alloc_file("", MFD_ALLOW_SEALING);
	if (IS_ERR(file)) {
		pr_err("failed to setup file: %pe\n", file);
		err = PTR_ERR(file);
		goto free_ser;
	}

	err = memfd_add_seals(file, ser->seals);
	if (err) {
		pr_err("failed to add seals: %pe\n", ERR_PTR(err));
		goto put_file;
	}

	vfs_setpos(file, ser->pos, MAX_LFS_FILESIZE);
	i_size_write(file_inode(file), ser->size);

	/*
	 * Keep the file frozen until finish(). Other preserved objects might
	 * depend on it.
	 *
	 * The file isn't visible to anyone yet, but take the lock anyway since
	 * shmem_freeze() requires it.
	 */
	inode_lock(file_inode(file));
	shmem_freeze(file_inode(file), true);
	inode_unlock(file_inode(file));

	if (ser->nr_folios) {
		folios_ser = kho_restore_vmalloc(&ser->folios);
		if (!folios_ser) {
			err = -EINVAL;
			goto put_file;
		}

		err = memfd_luo_retrieve_folios(file, folios_ser, ser->nr_folios);
		if (err)
			goto free_folios_ser;
	}

	args->file = file;
	args->private_data = folios_ser;

	return 0;

free_folios_ser:
	vfree(folios_ser);
put_file:
	fput(file);
free_ser:
	kho_restore_free(ser);
	return err;
}

static bool memfd_luo_can_preserve(struct liveupdate_file_handler *handler,
				   struct file *file)
{
	struct inode *inode = file_inode(file);

	return shmem_file(file) && !inode->i_nlink;
}

static unsigned long memfd_luo_get_id(struct file *file)
{
	return (unsigned long)file_inode(file);
}

static const struct liveupdate_file_ops memfd_luo_file_ops = {
	.freeze = memfd_luo_freeze,
	.finish = memfd_luo_finish,
	.retrieve = memfd_luo_retrieve,
	.preserve = memfd_luo_preserve,
	.unpreserve = memfd_luo_unpreserve,
	.can_preserve = memfd_luo_can_preserve,
	.get_id = memfd_luo_get_id,
	.owner = THIS_MODULE,
};

static struct liveupdate_file_handler memfd_luo_handler = {
	.ops = &memfd_luo_file_ops,
	.compatible = MEMFD_LUO_FH_COMPATIBLE,
};

static int __init memfd_luo_init(void)
{
	int err = liveupdate_register_file_handler(&memfd_luo_handler);

	if (err && err != -EOPNOTSUPP) {
		pr_err("Could not register luo filesystem handler: %pe\n",
		       ERR_PTR(err));

		return err;
	}

	return 0;
}
late_initcall(memfd_luo_init);
