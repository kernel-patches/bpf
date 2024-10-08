// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024. Huawei Technologies Co., Ltd */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <test_progs.h>

#include "htab_dynkey_test_success.skel.h"
#include "htab_dynkey_test_failure.skel.h"

struct id_dname_key {
	int id;
	struct bpf_dynptr_user name;
};

struct dname_key {
	struct bpf_dynptr_user name;
};

struct multiple_dynptr_key {
	struct dname_key f_1;
	unsigned long f_2;
	struct id_dname_key f_3;
	unsigned long f_4;
};

static char *name_list[] = {
	"systemd",
	"[rcu_sched]",
	"[kworker/42:0H-events_highpri]",
	"[ksoftirqd/58]",
	"[rcu_tasks_trace]",
};

#define INIT_VALUE 100
#define INIT_ID 1000

static void setup_pure_dynptr_key_map(int fd)
{
	struct bpf_dynptr_user key, _cur_key, _next_key;
	struct bpf_dynptr_user *cur_key, *next_key;
	bool marked[ARRAY_SIZE(name_list)];
	unsigned int i, next_idx, size;
	unsigned long value, got;
	char name[2][64];
	char msg[64];
	void *data;
	int err;

	/* lookup non-existent keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u bad lookup", i);
		/* Use strdup() to ensure that the content pointed by dynptr is
		 * used for lookup instead of the pointer in dynptr. sys_bpf()
		 * will handle the NULL case properly.
		 */
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key);
		err = bpf_map_lookup_elem(fd, &key, &value);
		ASSERT_EQ(err, -ENOENT, msg);
		free(data);
	}

	/* update keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u insert", i);
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key);
		value = INIT_VALUE + i;
		err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
		ASSERT_OK(err, msg);
		free(data);
	}

	/* lookup existent keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u lookup", i);
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key);
		got = 0;
		err = bpf_map_lookup_elem(fd, &key, &got);
		ASSERT_OK(err, msg);
		free(data);

		value = INIT_VALUE + i;
		ASSERT_EQ(got, value, msg);
	}

	/* delete keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u delete", i);
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key);
		err = bpf_map_delete_elem(fd, &key);
		ASSERT_OK(err, msg);
		free(data);
	}

	/* re-insert keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u re-insert", i);
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key);
		value = 0;
		err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
		ASSERT_OK(err, msg);
		free(data);
	}

	/* overwrite keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u overwrite", i);
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key);
		value = INIT_VALUE + i;
		err = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
		ASSERT_OK(err, msg);
		free(data);
	}

	/* get_next keys */
	next_idx = 0;
	cur_key = NULL;
	next_key = &_next_key;
	memset(&marked, 0, sizeof(marked));
	while (true) {
		bpf_dynptr_user_init(name[next_idx], sizeof(name[next_idx]), next_key);
		err = bpf_map_get_next_key(fd, cur_key, next_key);
		if (err) {
			ASSERT_EQ(err, -ENOENT, "get_next_key");
			break;
		}

		size = bpf_dynptr_user_size(next_key);
		data = bpf_dynptr_user_data(next_key);
		for (i = 0; i < ARRAY_SIZE(name_list); i++) {
			if (size == strlen(name_list[i]) + 1 &&
			    !memcmp(name_list[i], data, size)) {
				ASSERT_FALSE(marked[i], name_list[i]);
				marked[i] = true;
				break;
			}
		}
		ASSERT_EQ(next_key->rsvd, 0, "rsvd");

		if (!cur_key)
			cur_key = &_cur_key;
		*cur_key = *next_key;
		next_idx ^= 1;
	}

	for (i = 0; i < ARRAY_SIZE(marked); i++)
		ASSERT_TRUE(marked[i], name_list[i]);

	/* lookup_and_delete all elements except the first one */
	for (i = 1; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u lookup_delete", i);
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key);
		got = 0;
		err = bpf_map_lookup_and_delete_elem(fd, &key, &got);
		ASSERT_OK(err, msg);
		free(data);

		value = INIT_VALUE + i;
		ASSERT_EQ(got, value, msg);
	}

	/* get the key after the first element */
	cur_key = &_cur_key;
	strncpy(name[0], name_list[0], sizeof(name[0]) - 1);
	name[0][sizeof(name[0]) - 1] = 0;
	bpf_dynptr_user_init(name[0], strlen(name[0]) + 1, cur_key);

	next_key = &_next_key;
	bpf_dynptr_user_init(name[1], sizeof(name[1]), next_key);
	err = bpf_map_get_next_key(fd, cur_key, next_key);
	ASSERT_EQ(err, -ENOENT, "get_last");
}

static void setup_mixed_dynptr_key_map(int fd)
{
	struct id_dname_key key, _cur_key, _next_key;
	struct id_dname_key *cur_key, *next_key;
	bool marked[ARRAY_SIZE(name_list)];
	unsigned int i, next_idx, size;
	unsigned long value;
	char name[2][64];
	char msg[64];
	void *data;
	int err;

	/* Zero the hole */
	memset(&key, 0, sizeof(key));

	/* lookup non-existent keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u bad lookup", i);
		key.id = INIT_ID + i;
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key.name);
		err = bpf_map_lookup_elem(fd, &key, &value);
		ASSERT_EQ(err, -ENOENT, msg);
		free(data);
	}

	/* update keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u insert", i);
		key.id = INIT_ID + i;
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key.name);
		value = INIT_VALUE + i;
		err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
		ASSERT_OK(err, msg);
		free(data);
	}

	/* lookup existent keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		unsigned long got = 0;

		snprintf(msg, sizeof(msg), "#%u lookup", i);
		key.id = INIT_ID + i;
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key.name);
		err = bpf_map_lookup_elem(fd, &key, &got);
		ASSERT_OK(err, msg);
		free(data);

		value = INIT_VALUE + i;
		ASSERT_EQ(got, value, msg);
	}

	/* delete keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u delete", i);
		key.id = INIT_ID + i;
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key.name);
		err = bpf_map_delete_elem(fd, &key);
		ASSERT_OK(err, msg);
		free(data);
	}

	/* re-insert keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u re-insert", i);
		key.id = INIT_ID + i;
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key.name);
		value = 0;
		err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
		ASSERT_OK(err, msg);
		free(data);
	}

	/* overwrite keys */
	for (i = 0; i < ARRAY_SIZE(name_list); i++) {
		snprintf(msg, sizeof(msg), "#%u overwrite", i);
		key.id = INIT_ID + i;
		data = strdup(name_list[i]);
		bpf_dynptr_user_init(data, strlen(name_list[i]) + 1, &key.name);
		value = INIT_VALUE + i;
		err = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
		ASSERT_OK(err, msg);
		free(data);
	}

	/* get_next keys */
	next_idx = 0;
	cur_key = NULL;
	next_key = &_next_key;
	memset(&marked, 0, sizeof(marked));
	while (true) {
		bpf_dynptr_user_init(name[next_idx], sizeof(name[next_idx]), &next_key->name);
		err = bpf_map_get_next_key(fd, cur_key, next_key);
		if (err) {
			ASSERT_EQ(err, -ENOENT, "last get_next");
			break;
		}

		size = bpf_dynptr_user_size(&next_key->name);
		data = bpf_dynptr_user_data(&next_key->name);
		for (i = 0; i < ARRAY_SIZE(name_list); i++) {
			if (size == strlen(name_list[i]) + 1 &&
			    !memcmp(name_list[i], data, size)) {
				ASSERT_FALSE(marked[i], name_list[i]);
				ASSERT_EQ(next_key->id, INIT_ID + i, name_list[i]);
				marked[i] = true;
				break;
			}
		}
		ASSERT_EQ(next_key->name.rsvd, 0, "rsvd");

		if (!cur_key)
			cur_key = &_cur_key;
		*cur_key = *next_key;
		next_idx ^= 1;
	}

	for (i = 0; i < ARRAY_SIZE(marked); i++)
		ASSERT_TRUE(marked[i], name_list[i]);
}

static void setup_multiple_dynptr_key_map(int fd)
{
	struct multiple_dynptr_key key, cur_key, next_key;
	unsigned long value;
	unsigned int size;
	char name[4][64];
	void *data[2];
	int err;

	/* Zero the hole */
	memset(&key, 0, sizeof(key));

	key.f_2 = 2;
	key.f_3.id = 3;
	key.f_4 = 4;

	/* lookup a non-existent key */
	data[0] = strdup(name_list[0]);
	data[1] = strdup(name_list[1]);
	bpf_dynptr_user_init(data[0], strlen(name_list[0]) + 1, &key.f_1.name);
	bpf_dynptr_user_init(data[1], strlen(name_list[1]) + 1, &key.f_3.name);
	err = bpf_map_lookup_elem(fd, &key, &value);
	ASSERT_EQ(err, -ENOENT, "lookup");

	/* update key */
	value = INIT_VALUE;
	err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	ASSERT_OK(err, "update");
	free(data[0]);
	free(data[1]);

	/* lookup key */
	data[0] = strdup(name_list[0]);
	data[1] = strdup(name_list[1]);
	bpf_dynptr_user_init(data[0], strlen(name_list[0]) + 1, &key.f_1.name);
	bpf_dynptr_user_init(data[1], strlen(name_list[1]) + 1, &key.f_3.name);
	err = bpf_map_lookup_elem(fd, &key, &value);
	ASSERT_OK(err, "lookup");
	ASSERT_EQ(value, INIT_VALUE, "lookup");

	/* delete key */
	err = bpf_map_delete_elem(fd, &key);
	ASSERT_OK(err, "delete");
	free(data[0]);
	free(data[1]);

	/* re-insert keys */
	bpf_dynptr_user_init(name_list[0], strlen(name_list[0]) + 1, &key.f_1.name);
	bpf_dynptr_user_init(name_list[1], strlen(name_list[1]) + 1, &key.f_3.name);
	value = 0;
	err = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
	ASSERT_OK(err, "re-insert");

	/* overwrite keys */
	data[0] = strdup(name_list[0]);
	data[1] = strdup(name_list[1]);
	bpf_dynptr_user_init(data[0], strlen(name_list[0]) + 1, &key.f_1.name);
	bpf_dynptr_user_init(data[1], strlen(name_list[1]) + 1, &key.f_3.name);
	value = INIT_VALUE;
	err = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
	ASSERT_OK(err, "overwrite");
	free(data[0]);
	free(data[1]);

	/* get_next_key */
	bpf_dynptr_user_init(name[0], sizeof(name[0]), &next_key.f_1.name);
	bpf_dynptr_user_init(name[1], sizeof(name[1]), &next_key.f_3.name);
	err = bpf_map_get_next_key(fd, NULL, &next_key);
	ASSERT_OK(err, "first get_next");

	size = bpf_dynptr_user_size(&next_key.f_1.name);
	data[0] = bpf_dynptr_user_data(&next_key.f_1.name);
	if (ASSERT_EQ(size, strlen(name_list[0]) + 1, "f_1 size"))
		ASSERT_TRUE(!memcmp(name_list[0], data[0], size), "f_1 data");
	ASSERT_EQ(next_key.f_1.name.rsvd, 0, "f_1 rsvd");

	ASSERT_EQ(next_key.f_2, 2, "f_2");

	ASSERT_EQ(next_key.f_3.id, 3, "f_3 id");
	size = bpf_dynptr_user_size(&next_key.f_3.name);
	data[0] = bpf_dynptr_user_data(&next_key.f_3.name);
	if (ASSERT_EQ(size, strlen(name_list[1]) + 1, "f_3 size"))
		ASSERT_TRUE(!memcmp(name_list[1], data[0], size), "f_3 data");
	ASSERT_EQ(next_key.f_3.name.rsvd, 0, "f_3 rsvd");

	ASSERT_EQ(next_key.f_4, 4, "f_4");

	cur_key = next_key;
	bpf_dynptr_user_init(name[2], sizeof(name[2]), &next_key.f_1.name);
	bpf_dynptr_user_init(name[3], sizeof(name[3]), &next_key.f_3.name);
	err = bpf_map_get_next_key(fd, &cur_key, &next_key);
	ASSERT_EQ(err, -ENOENT, "last get_next_key");
}

static void test_htab_dynptr_key(bool pure, bool multiple)
{
	struct htab_dynkey_test_success *skel;
	struct bpf_program *prog;
	int err;

	skel = htab_dynkey_test_success__open();
	if (!ASSERT_OK_PTR(skel, "open()"))
		return;

	prog = pure ? skel->progs.pure_dynptr_key :
	       (multiple ? skel->progs.multiple_dynptr_key : skel->progs.mixed_dynptr_key);
	bpf_program__set_autoload(prog, true);

	err = htab_dynkey_test_success__load(skel);
	if (!ASSERT_OK(err, "load()"))
		goto out;

	if (pure) {
		setup_pure_dynptr_key_map(bpf_map__fd(skel->maps.htab_1));
		setup_pure_dynptr_key_map(bpf_map__fd(skel->maps.htab_2));
	} else if (multiple) {
		setup_multiple_dynptr_key_map(bpf_map__fd(skel->maps.htab_4));
	} else {
		setup_mixed_dynptr_key_map(bpf_map__fd(skel->maps.htab_3));
	}

	skel->bss->pid = getpid();

	err = htab_dynkey_test_success__attach(skel);
	if (!ASSERT_OK(err, "attach()"))
		goto out;

	usleep(1);

	ASSERT_EQ(skel->bss->test_err, 0, "test");
out:
	htab_dynkey_test_success__destroy(skel);
}

void test_htab_dynkey_test(void)
{
	if (test__start_subtest("pure_dynptr_key"))
		test_htab_dynptr_key(true, false);
	if (test__start_subtest("mixed_dynptr_key"))
		test_htab_dynptr_key(false, false);
	if (test__start_subtest("multiple_dynptr_key"))
		test_htab_dynptr_key(false, true);

	RUN_TESTS(htab_dynkey_test_failure);
}
