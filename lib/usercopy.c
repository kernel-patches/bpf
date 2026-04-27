// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/uaccess.h>

/* out-of-line parts */

#if !defined(INLINE_COPY_FROM_USER)
unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return _inline_copy_from_user(to, from, n);
}
EXPORT_SYMBOL(_copy_from_user);
#endif

#if !defined(INLINE_COPY_TO_USER)
unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return _inline_copy_to_user(to, from, n);
}
EXPORT_SYMBOL(_copy_to_user);
#endif
