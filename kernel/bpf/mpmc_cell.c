// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "mpmc_cell.h"

static u32 read_cell_idx(struct bpf_mpmc_cell_ctl *ctl, u32 seq)
{
	return (seq & 2) >> 1;
}

void bpf_mpmc_cell_init(struct bpf_mpmc_cell_ctl *ctl, void *cell1, void *cell2)
{
	atomic_set(&ctl->seq, 0);
	ctl->cell[0] = cell1;
	ctl->cell[1] = cell2;
}

void *bpf_mpmc_cell_read_begin(struct bpf_mpmc_cell_ctl *ctl, u32 *seq)
{
	*seq = atomic_read_acquire(&ctl->seq);
	/* Mask out acive writer bit */
	*seq &= ~1;

	return ctl->cell[read_cell_idx(ctl, *seq)];
}

int bpf_mpmc_cell_read_end(struct bpf_mpmc_cell_ctl *ctl, u32 seq)
{
	u32 new_seq;

	/* Ensure cell reads complete before checking seq */
	smp_rmb();

	new_seq = atomic_read_acquire(&ctl->seq);
	new_seq &= ~1; /* Ignore active write bit */
	/* Check if seq changed between begin and end, if it did, new snapshot is available */
	if (new_seq != seq)
		return -EAGAIN;

	return 0;
}

void *bpf_mpmc_cell_write_begin(struct bpf_mpmc_cell_ctl *ctl)
{
	u32 seq;

	/*
	 * Try to set the lowest bit, on success, writer owns cell exclusively,
	 * other writers fail
	 */
	seq = atomic_fetch_or_acquire(1, &ctl->seq);
	if (seq & 1) /* Check if another writer is active */
		return NULL;

	/* Write to opposite to read buffer */
	return ctl->cell[read_cell_idx(ctl, seq) ^ 1];
}

void bpf_mpmc_cell_write_commit(struct bpf_mpmc_cell_ctl *ctl)
{
	atomic_fetch_add_release(1, &ctl->seq);
}
