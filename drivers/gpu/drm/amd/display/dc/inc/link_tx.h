/*
 * Copyright 2026 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: AMD
 *
 */
#ifndef LINK_TX_H
#define LINK_TX_H

#include "dc/inc/core_types.h"
#include "dc/inc/core_status.h"

struct dc_link;
struct link_resource;
struct link_tx;
struct link_tx_funcs;

/**
 * Private DPMS v2 context, opaque type forward-declared only.
 */
struct link_tx_v2_ctx;

struct link_tx {
	const struct link_tx_funcs *funcs;
	struct dc_link *link;
	struct link_tx_v2_ctx *ctx;
};

/**
 * Virtual table of function pointers for link protocol programming.
 *
 * Analogous to HWSS, but takes link_tx instead of pipe_ctx, as the latter
 * was deemed too broad and open, resulting in synchronization hazards.
 */
struct link_tx_funcs {
	// TODO: Implement
	void (*destroy)(struct link_tx *tx);
};

#endif

