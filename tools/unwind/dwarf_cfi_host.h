/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
#ifndef _TOOLS_UNWIND_DWARF_CFI_HOST_H
#define _TOOLS_UNWIND_DWARF_CFI_HOST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Note: In C++ files using LLVM headers, include this header AFTER <llvm/...>
 * headers (matching tools/perf/util/llvm-c-helpers.cpp) because
 * tools/include/linux/compiler.h defines macros such as 'noinline' that
 * conflict with LLVM attribute declarations.
 */
#ifdef __cplusplus
extern "C" {
#endif

#ifndef CONFIG_UNWIND_DWARF_CFI
#define CONFIG_UNWIND_DWARF_CFI 1
#endif
#include <linux/unwind_dwarf_cfi.h>

/**
 * struct host_vma_seg - Simulated user VMA backing range for host CFI testing
 * @vma: Starting virtual address of the ELF section/segment.
 * @size: Length in bytes of the backing buffer @data.
 * @data: Pointer to in-memory ELF section contents on the host.
 */
struct host_vma_seg {
	unsigned long vma;
	size_t size;
	const uint8_t *data;
};

void host_set_vma_segs(const struct host_vma_seg *segs, size_t nsegs);

#ifdef __cplusplus
}
#endif

#endif /* _TOOLS_UNWIND_DWARF_CFI_HOST_H */
