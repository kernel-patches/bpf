/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ERROR_INJECTION_H
#define _LINUX_ERROR_INJECTION_H

#include <linux/compiler.h>
#include <linux/errno.h>
#include <asm-generic/error-injection.h>

struct static_key;

#ifdef CONFIG_FUNCTION_ERROR_INJECTION

bool within_error_injection_list(unsigned long addr);
int get_injectable_error_type(unsigned long addr);
struct static_key *get_injection_key(unsigned long addr);

#else /* !CONFIG_FUNCTION_ERROR_INJECTION */

static inline bool within_error_injection_list(unsigned long addr)
{
	return false;
}

static inline int get_injectable_error_type(unsigned long addr)
{
	return -EOPNOTSUPP;
}

static inline struct static_key *get_injection_key(unsigned long addr)
{
	return NULL;
}

#endif

#endif /* _LINUX_ERROR_INJECTION_H */
