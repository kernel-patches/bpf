// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#pragma once

#include <linux/types.h>
#include "libbpf.h"

int tc_get_tcm_parent(enum bpf_tc_attach_point attach_point,
		      __u32 *parent);
