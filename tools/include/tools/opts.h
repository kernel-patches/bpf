/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Options helpers.
 *
 * Originally in tools/lib/bpf/libbpf_internal.h
 */

#ifndef __TOOLS_OPTS_H
#define __TOOLS_OPTS_H

#include <stdint.h>
#include <stdio.h>

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof((((TYPE *)0)->MEMBER)))
#endif

static inline bool lib_is_mem_zeroed(const char *p, ssize_t len)
{
	while (len > 0) {
		if (*p)
			return false;
		p++;
		len--;
	}
	return true;
}

static inline bool lib_validate_opts(const char *opts,
					size_t opts_sz, size_t user_sz,
					const char *type_name)
{
	if (user_sz < sizeof(size_t)) {
		fprintf(stderr, "%s size (%zu) is too small\n", type_name, user_sz);
		return false;
	}
	if (!lib_is_mem_zeroed(opts + opts_sz, (ssize_t)user_sz - opts_sz)) {
		fprintf(stderr, "%s has non-zero extra bytes\n", type_name);
		return false;
	}
	return true;
}

#define OPTS_VALID(opts, type)						      \
	(!(opts) || lib_validate_opts((const char *)opts,		      \
					 offsetofend(struct type,	      \
						     type##__last_field),     \
					 (opts)->sz, #type))
#define OPTS_HAS(opts, field) \
	((opts) && opts->sz >= offsetofend(typeof(*(opts)), field))
#define OPTS_GET(opts, field, fallback_value) \
	(OPTS_HAS(opts, field) ? (opts)->field : fallback_value)
#define OPTS_SET(opts, field, value)		\
	do {					\
		if (OPTS_HAS(opts, field))	\
			(opts)->field = value;	\
	} while (0)

#define OPTS_ZEROED(opts, last_nonzero_field)				      \
({									      \
	ssize_t __off = offsetofend(typeof(*(opts)), last_nonzero_field);     \
	!(opts) || lib_is_mem_zeroed((const void *)opts + __off,	      \
					(opts)->sz - __off);		      \
})

#endif /* __TOOLS_OPTS_H */
