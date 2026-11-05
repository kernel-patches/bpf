// SPDX-License-Identifier: GPL-2.0
#include <zlib.h>

/*
 * libz-rs-sys's bundled zlib.h defines ZLIB_VER_SUBREVISION to 15 (0xf) to
 * distinguish itself from standard C zlib (which defines it to 0). Verify
 * we are including the zlib-rs header and can link against its zlib C ABI.
 */
#if !defined(ZLIB_VER_SUBREVISION) || ZLIB_VER_SUBREVISION != 15
#error "Not zlib-rs header"
#endif

int main(void)
{
	z_stream zs;

	inflateInit(&zs);
	return 0;
}
