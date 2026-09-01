/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 KylinSoft Co., Ltd. */
#pragma once

/*
 * Constants shared between the rhtab_fields BPF program (progs/) and its
 * userspace driver (prog_tests/) so the two sides cannot drift apart
 * silently.
 */

/* Magic value stored in the plain bytes of lkmap values ("RHAB"). */
#define LK_MAGIC 0x52484142

/*
 * Marker written into freshly allocated per-cpu objects of pcmap. Distinct
 * from LK_MAGIC on purpose: a hit proves the data came from our own
 * pc_init(), not from anything else.
 */
#define PC_MAGIC 0x43504d47
