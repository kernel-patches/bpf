// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#if defined(__clang__) && defined(__TARGET_ARCH_arm64)
#define BPF_USDT_MAX_SPEC_CNT 2
#endif

int my_pid;

#include "test_usdt_multispec.inc.h"
