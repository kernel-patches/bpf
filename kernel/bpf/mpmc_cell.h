/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#ifndef __BPF_MPMC_CELL_H__
#define __BPF_MPMC_CELL_H__
#include <linux/smp.h>

/**
 * DOC: BPF MPMC Cell
 *
 * Multi-producer, multi-consumer lock-free double buffer.
 * Designed for writers producing data in NMI context where locking is not possible.
 *
 * Writers never block or wait, but may fail (return NULL) if another writer is active
 * (assume these writers are overridden)
 * Readers never block writers. Readers may need to retry if a write
 * completes during the read window (return -EAGAIN)
 *
 * User should provide two allocated cells.
 *
 * Typical usage:
 *
 *   // Writer (from NMI or any context):
 *   cell = bpf_mpmc_cell_write_begin(ctl);
 *   if (!IS_ERR(cell)) {
 *       memcpy(cell, data, size);
 *       bpf_mpmc_cell_write_commit(ctl);
 *   }
 *
 *   // Reader (from irq_work or similar):
 *   cell = bpf_mpmc_cell_read_begin(ctl, &seq);
 *   memcpy(local, cell, size);
 *   ret = bpf_mpmc_cell_read_end(ctl, seq);
 *   if (ret == 0)
 *       process(local);  // success, we own this snapshot
 *   else if (ret == -EAGAIN)
 *       retry;           // snapshot changed or lost race
 */

/**
 * struct bpf_mpmc_cell_ctl - control structure for mpmc cell
 * @seq: sequence number (odd = write active, seq/2 = generation)
 * @cell: pointers to two allocated cells to support double buffering
 *
 */
struct bpf_mpmc_cell_ctl {
	atomic_t seq;
	void *cell[2];
};

/**
 * bpf_mpmc_cell_init() - initialize mpmc cell control structure
 * @ctl: pointer to control structure to initialize
 * @cell1: pointer to an allocated cell
 * @cell2: pointer to another same sized cell
 *
 * Must be called before any read/write operations.
 * Caller must allocate two same sized cells (buffers, structs) and pass
 * them to this function, those two cells are used for double-buffering,
 * supporting concurrent reads/writes: readers use one cell, writers another.
 *
 * Context: Any context.
 * Return: void.
 */
void bpf_mpmc_cell_init(struct bpf_mpmc_cell_ctl *ctl, void *cell1, void *cell2);

/**
 * bpf_mpmc_cell_read_begin() - begin a read operation
 * @ctl: pointer to control structure
 * @seq: output parameter, sequence number for this read
 *
 * Returns: pointer to the current read cell. Caller must copy data
 * out and then call bpf_mpmc_cell_read_end() to validate.
 */
void *bpf_mpmc_cell_read_begin(struct bpf_mpmc_cell_ctl *ctl, u32 *seq);

/**
 * bpf_mpmc_cell_read_end() - validate read operation.
 * @ctl: pointer to control structure
 * @seq: sequence number from matching bpf_mpmc_cell_read_begin()
 *
 * Validates that the snapshot read between bpf_mpmc_cell_read_begin()
 * and bpf_mpmc_cell_read_end() is consistent.
 *
 * Return:
 *   0        - success, snapshot is consistent
 *   -EAGAIN  - snapshot invalidated (another writer completed)
 */
int bpf_mpmc_cell_read_end(struct bpf_mpmc_cell_ctl *ctl, u32 seq);

/**
 * bpf_mpmc_cell_write_begin() - begin a write operation
 * @ctl: pointer to control structure
 *
 * Attempts to acquire exclusive writer access. Only one writer can be
 * active at a time. On success, caller must write data and call
 * bpf_mpmc_cell_write_commit(). There is no write abort mechanism.
 *
 * Return: Pointer to the write cell, or NULL if another writer is
 * active.
 */
void *bpf_mpmc_cell_write_begin(struct bpf_mpmc_cell_ctl *ctl);

/**
 * bpf_mpmc_cell_write_commit() - complete a write operation
 * @ctl: pointer to control structure
 *
 * Publishes the written data, making it visible to readers.
 * Must be called after successful bpf_mpmc_cell_write_begin().
 */
void bpf_mpmc_cell_write_commit(struct bpf_mpmc_cell_ctl *ctl);

#endif
