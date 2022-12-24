// SPDX-License-Identifier: GPL-2.0

#include "map-common.h"

#include <linux/err.h>

#include "../../kselftest_harness.h"

FIXTURE(test_map)
{
	struct hsearch_data map;
	const char *key;
	void *expected;
	void *actual;
};

FIXTURE_SETUP(test_map)
{
	const int max_nelements = 100;

	create_map(&self->map, max_nelements);
	self->key = "key";
	self->expected = "expected";
	self->actual = "actual";
}

FIXTURE_TEARDOWN(test_map)
{
	free_map(&self->map);
}

TEST_F(test_map, upsert_and_find)
{
	void *found;

	found = map_find(&self->map, self->key);
	ASSERT_TRUE(IS_ERR(found))
	ASSERT_EQ(-ENOENT, PTR_ERR(found))

	ASSERT_EQ(0, map_upsert(&self->map, self->key, self->expected));
	ASSERT_EQ(0, map_upsert(&self->map, self->key, self->expected));
	ASSERT_EQ(0, map_upsert(&self->map, self->key, self->actual));

	found = map_find(&self->map, self->key);

	ASSERT_FALSE(IS_ERR(found));
	ASSERT_STREQ(self->actual, found);
}

TEST_F(test_map, update)
{
	void *found;

	ASSERT_EQ(0, map_upsert(&self->map, self->key, self->actual));
	ASSERT_EQ(0, map_upsert(&self->map, self->key, self->expected));

	found = map_find(&self->map, self->key);

	ASSERT_FALSE(IS_ERR(found));
	ASSERT_STREQ(self->expected, found);
}

TEST_HARNESS_MAIN
