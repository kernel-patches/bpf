// SPDX-License-Identifier: GPL-2.0-only
/// Use struct_offset() family of macros
///
// Confidence: High
// Options: --no-includes --ignore ./tools/

virtual patch

@offsetof depends on patch@
expression ptr, member;
@@
- offsetof(typeof(*(ptr)), member)
+ struct_offset(ptr, member)
@offsetofend depends on patch@
expression ptr, member;
@@
- offsetofend(typeof(*(ptr)), member)
+ struct_offsetofend(ptr, member)
