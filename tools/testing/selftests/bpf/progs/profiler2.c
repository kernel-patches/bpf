// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#define barrier_var(var) /**/
/* undef #define UNROLL */
#define INLINE /**/
#define bpf_cmp(lhs, op, rhs) lhs op rhs
#include "profiler.inc.h"
