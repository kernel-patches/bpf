// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#pragma once

#include <stdint.h>

/*
 * Header for the userspace C programs that load
 * and initialize the BPF code.
 */

#define __arena

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

/* Dummy "definition" for userspace. */
#define arena_spinlock_t u64

#include "common.h"
