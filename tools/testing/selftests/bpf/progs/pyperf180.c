// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#define STACK_MAX_LEN 180

/* llvm upstream commit at llvm18
 *   https://github.com/llvm/llvm-project/commit/1a2e77cf9e11dbf56b5720c607313a566eebb16e
 * changed inlining behavior and caused compilation failure as some branch
 * target distance exceeded 16bit representation which is the maximum for
 * cpu v1/v2/v3. To workaround this, for llvm18 and later, let us set unroll_count
 * to be 90, which reduced some branch target distances and resolved the
 * compilation failure.
 */
#if __clang_major__ >= 18
#define UNROLL_COUNT 90
#endif

#include "pyperf.h"
