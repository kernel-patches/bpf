/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_TYPES_H
#define __LINUX_COMPILER_TYPES_H

/*
 * __has_builtin is supported on gcc >= 10, clang >= 3 and icc >= 21.
 * In the meantime, to support gcc < 10, we implement __has_builtin
 * by hand.
 */
#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

/* Indirect macros required for expanded argument pasting, eg. __LINE__. */
#define ___PASTE(a, b) a##b
#define __PASTE(a, b) ___PASTE(a, b)

#ifndef __ASSEMBLY__

/*
 * Skipped when running bindgen due to a libclang issue;
 * see https://github.com/rust-lang/rust-bindgen/issues/2244.
 */
#if defined(CONFIG_DEBUG_INFO_BTF) && defined(CONFIG_PAHOLE_HAS_BTF_TAG) && \
	__has_attribute(btf_type_tag) && !defined(__BINDGEN__)
# define BTF_TYPE_TAG(value) __attribute__((btf_type_tag(#value)))
#else
# define BTF_TYPE_TAG(value) /* nothing */
#endif

#include <linux/compiler-context-analysis.h>

/* Compiler specific macros. */
#ifdef __GNUC__
#include <linux/compiler-gcc.h>
#endif

#ifndef __compiletime_error
# define __compiletime_error(message)
#endif

#ifndef __noreturn
# define __noreturn __attribute__((__noreturn__))
#endif

#endif /* __ASSEMBLY__ */

/*
 * When the size of an allocated object is needed, use the best available
 * mechanism to find it. (For cases where sizeof() cannot be used.)
 *
 * Optional: only supported since gcc >= 12
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Object-Size-Checking.html
 * clang: https://clang.llvm.org/docs/LanguageExtensions.html#evaluating-object-size
 */
#if __has_builtin(__builtin_dynamic_object_size)
#define __struct_size(p)	__builtin_dynamic_object_size(p, 0)
#define __member_size(p)	__builtin_dynamic_object_size(p, 1)
#else
#define __struct_size(p)	__builtin_object_size(p, 0)
#define __member_size(p)	__builtin_object_size(p, 1)
#endif

/*
 * Determine if an attribute has been applied to a variable.
 * Using __annotated needs to check for __annotated being available,
 * or negative tests may fail when annotation cannot be checked. For
 * example, see the definition of __is_cstr().
 */
#if __has_builtin(__builtin_has_attribute)
#define __annotated(var, attr)	__builtin_has_attribute(var, attr)
#endif

/*
 * Optional: only supported since gcc >= 15, clang >= 19
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html#index-_005f_005fbuiltin_005fcounted_005fby_005fref
 * clang: https://clang.llvm.org/docs/LanguageExtensions.html#builtin-counted-by-ref
 */
#if __has_builtin(__builtin_counted_by_ref) && \
    !defined(CONFIG_CC_HAS_BROKEN_COUNTED_BY_REF)
#define __flex_counter(FAM)	__builtin_counted_by_ref(FAM)
#else
#define __flex_counter(FAM)	((void *)NULL)
#endif

/*
 * Some versions of gcc do not mark 'asm goto' volatile:
 *
 *  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=103979
 *
 * We do it here by hand, because it doesn't hurt.
 */
#ifndef asm_goto_output
#define asm_goto_output(x...) asm volatile goto(x)
#endif

/*
 * Clang has trouble with constraints with multiple
 * alternative behaviors ("g" , "rm" and "=rm").
 */
#ifndef ASM_INPUT_G
  #define ASM_INPUT_G "g"
  #define ASM_INPUT_RM "rm"
  #define ASM_OUTPUT_RM "=rm"
#endif

#ifdef CONFIG_CC_HAS_ASM_INLINE
#define asm_inline asm __inline
#else
#define asm_inline asm
#endif

#ifndef __ASSEMBLY__
/*
 * Use __typeof_unqual__() when available.
 */
#if (defined(CC_HAS_TYPEOF_UNQUAL) && CC_HAS_TYPEOF_UNQUAL) || defined(__CHECKER__)
# define USE_TYPEOF_UNQUAL 1
#endif

/* Are two types/vars the same type (ignoring qualifiers)? */
#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

/*
 * __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
 *			       non-scalar types unchanged.
 */
#ifndef USE_TYPEOF_UNQUAL
/*
 * Prefer C11 _Generic for better compile-times and simpler code. Note: 'char'
 * is not type-compatible with 'signed char', and we define a separate case.
 */
#define __scalar_type_to_expr_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(signed type)0

#define __unqual_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			 char:	(char)0,				\
			 __scalar_type_to_expr_cases(char),		\
			 __scalar_type_to_expr_cases(short),		\
			 __scalar_type_to_expr_cases(int),		\
			 __scalar_type_to_expr_cases(long),		\
			 __scalar_type_to_expr_cases(long long),	\
			 default: (x)))
#else
#define __unqual_scalar_typeof(x) __typeof_unqual__(x)
#endif

#endif /* !__ASSEMBLY__ */

/*
 * __signed_scalar_typeof(x) - Declare a signed scalar type, leaving
 *			       non-scalar types unchanged.
 */

#define __scalar_type_to_signed_cases(type)				\
		unsigned type:	(signed type)0,				\
		signed type:	(signed type)0

#define __signed_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			 char:	(signed char)0,				\
			 __scalar_type_to_signed_cases(char),		\
			 __scalar_type_to_signed_cases(short),		\
			 __scalar_type_to_signed_cases(int),		\
			 __scalar_type_to_signed_cases(long),		\
			 __scalar_type_to_signed_cases(long long),	\
			 default: (x)))

/* Is this type a native word size -- useful for atomic operations */
#define __native_word(t) \
	(sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
	 sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))

#ifdef __OPTIMIZE__
/*
 * #ifdef __OPTIMIZE__ is only a good approximation; for instance "make
 * CFLAGS_foo.o=-Og" defines __OPTIMIZE__, does not elide the conditional code
 * and can break compilation with wrong error message(s). Combine with
 * -U__OPTIMIZE__ when needed.
 */
# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		/*							\
		 * __noreturn is needed to give the compiler enough	\
		 * information to avoid certain possibly-uninitialized	\
		 * warnings (regardless of the build failing).		\
		 */							\
		__noreturn extern void prefix ## suffix(void)		\
			__compiletime_error(msg);			\
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)
#else
# define __compiletime_assert(condition, msg, prefix, suffix) ((void)(condition))
#endif

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)

#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")

/* Helpers for emitting diagnostics in pragmas. */
#ifndef __diag
#define __diag(string)
#endif

#ifndef __diag_GCC
#define __diag_GCC(version, severity, string)
#endif

#ifndef __diag_clang
#define __diag_clang(version, severity, string)
#endif

#define __diag_push()	__diag(push)
#define __diag_pop()	__diag(pop)

#define __diag_ignore(compiler, version, option, comment) \
	__diag_ ## compiler(version, ignore, option)
#define __diag_warn(compiler, version, option, comment) \
	__diag_ ## compiler(version, warn, option)
#define __diag_error(compiler, version, option, comment) \
	__diag_ ## compiler(version, error, option)

#ifndef __diag_ignore_all
#define __diag_ignore_all(option, comment)
#endif

#endif /* __LINUX_COMPILER_TYPES_H */
