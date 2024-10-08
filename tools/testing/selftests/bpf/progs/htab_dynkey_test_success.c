// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2024. Huawei Technologies Co., Ltd */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct pure_dynptr_key {
	struct bpf_dynptr name;
};

struct mixed_dynptr_key {
	int id;
	struct bpf_dynptr name;
};

struct multiple_dynptr_key {
	struct pure_dynptr_key f_1;
	unsigned long f_2;
	struct mixed_dynptr_key f_3;
	unsigned long f_4;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_DYNPTR_IN_KEY);
	__type(key, struct bpf_dynptr);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_DYNPTR_IN_KEY);
	__type(key, struct pure_dynptr_key);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_DYNPTR_IN_KEY);
	__type(key, struct mixed_dynptr_key);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_DYNPTR_IN_KEY);
	__type(key, struct multiple_dynptr_key);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

int pid = 0;
int test_err = 0;
char dynptr_buf[2][32] = {{}, {}};

static const char systemd_name[] = "systemd";
static const char udevd_name[] = "udevd";
static const char rcu_sched_name[] = "[rcu_sched]";

struct bpf_map;

static int test_pure_dynptr_key_htab(struct bpf_map *htab)
{
	unsigned long new_value, *value;
	struct bpf_dynptr key;
	int err = 0;

	/* Lookup a existent key */
	__builtin_memcpy(dynptr_buf[0], systemd_name, sizeof(systemd_name));
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(systemd_name), 0, &key);
	value = bpf_map_lookup_elem(htab, &key);
	if (!value) {
		err = 1;
		goto out;
	}
	if (*value != 100) {
		err = 2;
		goto out;
	}

	/* Look up a non-existent key */
	__builtin_memcpy(dynptr_buf[0], udevd_name, sizeof(udevd_name));
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(udevd_name), 0, &key);
	value = bpf_map_lookup_elem(htab, &key);
	if (value) {
		err = 3;
		goto out;
	}

	/* Insert a new key */
	new_value = 42;
	err = bpf_map_update_elem(htab, &key, &new_value, BPF_NOEXIST);
	if (err) {
		err = 4;
		goto out;
	}

	/* Insert an existent key */
	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(udevd_name), 0, &key);
	err = bpf_dynptr_write(&key, 0, (void *)udevd_name, sizeof(udevd_name), 0);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key, 0);
		err = 5;
		goto out;
	}

	err = bpf_map_update_elem(htab, &key, &new_value, BPF_NOEXIST);
	bpf_ringbuf_discard_dynptr(&key, 0);
	if (err != -EEXIST) {
		err = 6;
		goto out;
	}

	/* Lookup it again */
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(udevd_name), 0, &key);
	value = bpf_map_lookup_elem(htab, &key);
	if (!value) {
		err = 7;
		goto out;
	}
	if (*value != 42) {
		err = 8;
		goto out;
	}

	/* Delete then lookup it */
	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(udevd_name), 0, &key);
	err = bpf_dynptr_write(&key, 0, (void *)udevd_name, sizeof(udevd_name), 0);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key, 0);
		err = 9;
		goto out;
	}
	err = bpf_map_delete_elem(htab, &key);
	bpf_ringbuf_discard_dynptr(&key, 0);
	if (err) {
		err = 10;
		goto out;
	}

	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(udevd_name), 0, &key);
	value = bpf_map_lookup_elem(htab, &key);
	if (value) {
		err = 10;
		goto out;
	}
out:
	return err;
}

static int test_mixed_dynptr_key_htab(struct bpf_map *htab)
{
	unsigned long new_value, *value;
	char udevd_name[] = "udevd";
	struct mixed_dynptr_key key;
	int err = 0;

	__builtin_memset(&key, 0, sizeof(key));
	key.id = 1000;

	/* Lookup a existent key */
	__builtin_memcpy(dynptr_buf[0], systemd_name, sizeof(systemd_name));
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(systemd_name), 0, &key.name);
	value = bpf_map_lookup_elem(htab, &key);
	if (!value) {
		err = 1;
		goto out;
	}
	if (*value != 100) {
		err = 2;
		goto out;
	}

	/* Look up a non-existent key */
	__builtin_memcpy(dynptr_buf[0], udevd_name, sizeof(udevd_name));
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(udevd_name), 0, &key.name);
	value = bpf_map_lookup_elem(htab, &key);
	if (value) {
		err = 3;
		goto out;
	}

	/* Insert a new key */
	new_value = 42;
	err = bpf_map_update_elem(htab, &key, &new_value, BPF_NOEXIST);
	if (err) {
		err = 4;
		goto out;
	}

	/* Insert an existent key */
	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(udevd_name), 0, &key.name);
	err = bpf_dynptr_write(&key.name, 0, (void *)udevd_name, sizeof(udevd_name), 0);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key.name, 0);
		err = 5;
		goto out;
	}

	err = bpf_map_update_elem(htab, &key, &new_value, BPF_NOEXIST);
	bpf_ringbuf_discard_dynptr(&key.name, 0);
	if (err != -EEXIST) {
		err = 6;
		goto out;
	}

	/* Lookup it again */
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(udevd_name), 0, &key.name);
	value = bpf_map_lookup_elem(htab, &key);
	if (!value) {
		err = 7;
		goto out;
	}
	if (*value != 42) {
		err = 8;
		goto out;
	}

	/* Delete then lookup it */
	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(udevd_name), 0, &key.name);
	err = bpf_dynptr_write(&key.name, 0, (void *)udevd_name, sizeof(udevd_name), 0);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key.name, 0);
		err = 9;
		goto out;
	}
	err = bpf_map_delete_elem(htab, &key);
	bpf_ringbuf_discard_dynptr(&key.name, 0);
	if (err) {
		err = 10;
		goto out;
	}

	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(udevd_name), 0, &key.name);
	value = bpf_map_lookup_elem(htab, &key);
	if (value) {
		err = 10;
		goto out;
	}
out:
	return err;
}

static int test_multiple_dynptr_key_htab(struct bpf_map *htab)
{
	unsigned long new_value, *value;
	struct multiple_dynptr_key key;
	int err = 0;

	__builtin_memset(&key, 0, sizeof(key));
	key.f_2 = 2;
	key.f_3.id = 3;
	key.f_4 = 4;

	/* Lookup a existent key */
	__builtin_memcpy(dynptr_buf[0], systemd_name, sizeof(systemd_name));
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(systemd_name), 0, &key.f_1.name);
	__builtin_memcpy(dynptr_buf[1], rcu_sched_name, sizeof(rcu_sched_name));
	bpf_dynptr_from_mem(dynptr_buf[1], sizeof(rcu_sched_name), 0, &key.f_3.name);
	value = bpf_map_lookup_elem(htab, &key);
	if (!value) {
		err = 1;
		goto out;
	}
	if (*value != 100) {
		err = 2;
		goto out;
	}

	/* Look up a non-existent key */
	bpf_dynptr_from_mem(dynptr_buf[1], sizeof(rcu_sched_name), 0, &key.f_1.name);
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(systemd_name), 0, &key.f_3.name);
	value = bpf_map_lookup_elem(htab, &key);
	if (value) {
		err = 3;
		goto out;
	}

	/* Insert a new key */
	new_value = 42;
	err = bpf_map_update_elem(htab, &key, &new_value, BPF_NOEXIST);
	if (err) {
		err = 4;
		goto out;
	}

	/* Insert an existent key */
	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(rcu_sched_name), 0, &key.f_1.name);
	err = bpf_dynptr_write(&key.f_1.name, 0, (void *)rcu_sched_name, sizeof(rcu_sched_name), 0);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key.f_1.name, 0);
		err = 5;
		goto out;
	}
	err = bpf_map_update_elem(htab, &key, &new_value, BPF_NOEXIST);
	bpf_ringbuf_discard_dynptr(&key.f_1.name, 0);
	if (err != -EEXIST) {
		err = 6;
		goto out;
	}

	/* Lookup a non-existent key */
	bpf_dynptr_from_mem(dynptr_buf[1], sizeof(rcu_sched_name), 0, &key.f_1.name);
	key.f_4 = 0;
	value = bpf_map_lookup_elem(htab, &key);
	if (value) {
		err = 7;
		goto out;
	}

	/* Lookup an existent key */
	key.f_4 = 4;
	value = bpf_map_lookup_elem(htab, &key);
	if (!value) {
		err = 8;
		goto out;
	}
	if (*value != 42) {
		err = 9;
		goto out;
	}

	/* Delete the newly-inserted key */
	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(systemd_name), 0, &key.f_3.name);
	err = bpf_dynptr_write(&key.f_3.name, 0, (void *)systemd_name, sizeof(systemd_name), 0);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key.f_3.name, 0);
		err = 10;
		goto out;
	}
	err = bpf_map_delete_elem(htab, &key);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key.f_3.name, 0);
		err = 11;
		goto out;
	}

	/* Lookup it again */
	value = bpf_map_lookup_elem(htab, &key);
	bpf_ringbuf_discard_dynptr(&key.f_3.name, 0);
	if (value) {
		err = 12;
		goto out;
	}
out:
	return err;
}

SEC("?fentry/" SYS_PREFIX "sys_nanosleep")
int BPF_PROG(pure_dynptr_key)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	test_err = test_pure_dynptr_key_htab((struct bpf_map *)&htab_1);
	test_err |= test_pure_dynptr_key_htab((struct bpf_map *)&htab_2) << 8;

	return 0;
}

SEC("?fentry/" SYS_PREFIX "sys_nanosleep")
int BPF_PROG(mixed_dynptr_key)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	test_err = test_mixed_dynptr_key_htab((struct bpf_map *)&htab_3);

	return 0;
}

SEC("?fentry/" SYS_PREFIX "sys_nanosleep")
int BPF_PROG(multiple_dynptr_key)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return 0;

	test_err = test_multiple_dynptr_key_htab((struct bpf_map *)&htab_4);

	return 0;
}
