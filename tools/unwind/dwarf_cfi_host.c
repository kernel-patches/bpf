// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Host userspace wrapper compiling kernel/unwind/dwarf_cfi.c verbatim against
 * tools/include/ headers so verify_cfi exercises the exact kernel Minimal DWARF
 * CFI interpreter on both the 128-byte windowed user stream path and the direct
 * kmem noinstr path.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dwarf_cfi_host.h"

static const struct host_vma_seg *g_segs;
static size_t g_nsegs;

void host_set_vma_segs(const struct host_vma_seg *segs, size_t nsegs)
{
	g_segs = segs;
	g_nsegs = nsegs;
}

static unsigned long host_copy_from_vma(void *to, const void *from_ptr,
					unsigned long n)
{
	unsigned long addr = (unsigned long)from_ptr;
	unsigned char *dst = to;

	while (n > 0) {
		bool found = false;
		size_t i;

		for (i = 0; i < g_nsegs; i++) {
			unsigned long start = g_segs[i].vma;

			if (addr >= start && (addr - start) < g_segs[i].size) {
				unsigned long off = addr - start;
				unsigned long avail = g_segs[i].size - off;
				unsigned long chunk = n < avail ? n : avail;

				memcpy(dst, g_segs[i].data + off, chunk);
				dst += chunk;
				addr += chunk;
				n -= chunk;
				found = true;
				break;
			}
		}
		if (!found)
			return n;
	}
	return 0;
}

/*
 * In userspace, <linux/limits.h> resolves to the UAPI header rather than
 * kernel-internal include/linux/limits.h, and tools/include/linux/kernel.h
 * avoids defining fixed-width integer bounds globally because other tools/
 * targets define their own U8_MAX/U32_MAX macros.
 */
#ifndef U8_MAX
#define U8_MAX		((u8)~0U)
#endif
#ifndef U32_MAX
#define U32_MAX		((u32)~0U)
#endif
#ifndef S32_MAX
#define S32_MAX		((s32)(U32_MAX >> 1))
#endif
#ifndef S32_MIN
#define S32_MIN		((s32)(-S32_MAX - 1))
#endif
#ifndef noinstr
#define noinstr
#endif
#define copy_from_user(to, from, n) host_copy_from_vma(to, from, n)

#include "../../kernel/unwind/dwarf_cfi.c"
