// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2026 Marvell.
 *
 */

#define CREATE_TRACE_POINTS
#if IS_ENABLED(CONFIG_OCTEONTX_SWITCH)
#include "sw_trace.h"
EXPORT_TRACEPOINT_SYMBOL(sw_fl_dump);
EXPORT_TRACEPOINT_SYMBOL(sw_act_dump);
#endif
