/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_KBUILD_H
#define __LINUX_KBUILD_H

#define _LINE(x, ...) \
	asm volatile( \
		".pushsection \".data.kbuild\"; "\
		".ascii \"" x "\\n\"; "\
		".popsection" : : __VA_ARGS__)

#define DEFINE(sym, val) \
	_LINE("#define " #sym " %c0 /* " #val " */", "i" (val))

#define OFFSET(sym, str, mem) \
	DEFINE(sym, offsetof(struct str, mem))

#define BLANK() \
	_LINE("")

#define COMMENT(x) \
	_LINE("/* " #x " */")

#endif
