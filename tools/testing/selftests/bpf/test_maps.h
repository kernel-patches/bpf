/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TEST_MAPS_H
#define _TEST_MAPS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define CHECK(condition, tag, format...) ({				\
	int __ret = !!(condition);					\
	if (__ret) {							\
		printf("%s(%d):FAIL:%s ", __func__, __LINE__, tag);	\
		printf(format);						\
		exit(-1);						\
	}								\
})

#define ASSERT_TRUE(actual, name) ({					\
	bool ___ok = (actual);						\
	CHECK(!___ok, (name), "unexpected %s: got FALSE\n", (name));	\
	___ok;								\
})

#define ASSERT_FALSE(actual, name) ({					\
	bool ___ok = !(actual);						\
	CHECK(!___ok, (name), "unexpected %s: got TRUE\n", (name));	\
	___ok;								\
})

#define ASSERT_EQ(actual, expected, name) ({				\
	typeof(actual) ___act = (actual);				\
	typeof(expected) ___exp = (expected);				\
	bool ___ok = ___act == ___exp;					\
	CHECK(!___ok, (name),						\
	      "unexpected %s: actual %lld != expected %lld\n",		\
	      (name), (long long)(___act), (long long)(___exp));	\
	___ok;								\
})

#define ASSERT_OK(res, name) ({						\
	long long ___res = (res);					\
	bool ___ok = ___res == 0;					\
	CHECK(!___ok, (name), "unexpected error: %lld (errno %d)\n",	\
	      ___res, errno);						\
	___ok;								\
})

extern int skips;

typedef bool (*retry_for_error_fn)(int err);
int map_update_retriable(int map_fd, const void *key, const void *value, int flags, int attempts,
			 retry_for_error_fn need_retry);

#endif
