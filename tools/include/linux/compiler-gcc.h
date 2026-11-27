/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_TYPES_H
#error "Please do not include <linux/compiler-gcc.h> directly, include <linux/compiler.h> instead."
#endif /* __LINUX_COMPILER_TYPES_H */

/*
 * Common definitions for all gcc versions go here.
 */
#ifndef GCC_VERSION
#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)
#endif

#if __has_attribute(__fallthrough__)
# define fallthrough                    __attribute__((__fallthrough__))
#else
# define fallthrough                    do {} while (0)  /* fallthrough */
#endif

#if __has_attribute(__error__)
# define __compiletime_error(message) __attribute__((error(message)))
#endif

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

#ifndef __pure
#define  __pure		__attribute__((pure))
#endif
#define  noinline	__attribute__((noinline))
#ifndef __packed
#define __packed	__attribute__((packed))
#endif
#ifndef __noreturn
#define __noreturn	__attribute__((__noreturn__))
#endif
#ifndef __aligned
#define __aligned(x)	__attribute__((aligned(x)))
#endif
#define __printf(a, b)	__attribute__((format(printf, a, b)))
#define __scanf(a, b)	__attribute__((format(scanf, a, b)))

/*
 * Turn individual warnings and errors on and off locally, depending
 * on version.
 */
#define __diag_str1(s)		#s
#define __diag_str(s)		__diag_str1(s)

#ifdef __clang__
#define __diag_clang(version, severity, s) \
	__diag_clang_ ## version(__diag_clang_ ## severity s)

/* Severity used in pragma directives */
#define __diag_clang_ignore	ignored
#define __diag_clang_warn	warning
#define __diag_clang_error	error

#define __diag(s)		_Pragma(__diag_str(clang diagnostic s))

#if __clang_major__ >= 23
#define __diag_clang_23(s)	__diag(s)
#else
#define __diag_clang_23(s)
#endif

#define __diag_clang_all(s)	__diag(s)

#define __diag_ignore_all(option, comment) \
	__diag_clang(all, ignore, option)

/*
 * clang has horrible behavior with "g" or "rm" constraints for asm
 * inputs, turning them into something worse than "m". Avoid using
 * constraints with multiple possible uses (but "ir" seems to be ok):
 *
 *	https://github.com/llvm/llvm-project/issues/20571
 */
#define ASM_INPUT_G "ir"
#define ASM_INPUT_RM "r"
#define ASM_OUTPUT_RM "=r"

#define CC_HAS_TYPEOF_UNQUAL (__clang_major__ > 19 || (__clang_major__ == 19 && __clang_minor__ > 0))
#else /* !__clang__ */
#define __diag_GCC(version, severity, s) \
	__diag_GCC_ ## version(__diag_GCC_ ## severity s)

/* Severity used in pragma directives */
#define __diag_GCC_ignore	ignored
#define __diag_GCC_warn		warning
#define __diag_GCC_error	error

#define __diag(s)		_Pragma(__diag_str(GCC diagnostic s))

#if GCC_VERSION >= 80000
#define __diag_GCC_8(s)		__diag(s)
#else
#define __diag_GCC_8(s)
#endif

#define __diag_GCC_all(s)	__diag(s)

#define __diag_ignore_all(option, comment) \
	__diag(__diag_GCC_ignore option)

#define CC_HAS_TYPEOF_UNQUAL (__GNUC__ >= 14)
#endif /* __clang__ */
