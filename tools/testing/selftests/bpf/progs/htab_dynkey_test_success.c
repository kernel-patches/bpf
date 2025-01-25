// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */
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

struct nested_dynptr_key {
	unsigned long f_1;
	struct mixed_dynptr_key f_2;
	unsigned long f_3;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct bpf_dynptr);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct pure_dynptr_key);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct mixed_dynptr_key);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct nested_dynptr_key);
	__type(value, unsigned long);
	__uint(map_extra, 1024);
} htab_4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

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

static int test_nested_dynptr_key_htab(struct bpf_map *htab)
{
	unsigned long new_value, *value;
	struct nested_dynptr_key key;
	int err = 0;

	__builtin_memset(&key, 0, sizeof(key));
	key.f_1 = 1;
	key.f_2.id = 2;
	key.f_3 = 3;

	/* Lookup a existent key */
	__builtin_memcpy(dynptr_buf[0], systemd_name, sizeof(systemd_name));
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(systemd_name), 0, &key.f_2.name);
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
	__builtin_memcpy(dynptr_buf[0], rcu_sched_name, sizeof(rcu_sched_name));
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(rcu_sched_name), 0, &key.f_2.name);
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
	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(rcu_sched_name), 0, &key.f_2.name);
	err = bpf_dynptr_write(&key.f_2.name, 0, (void *)rcu_sched_name, sizeof(rcu_sched_name), 0);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key.f_2.name, 0);
		err = 5;
		goto out;
	}
	err = bpf_map_update_elem(htab, &key, &new_value, BPF_NOEXIST);
	bpf_ringbuf_discard_dynptr(&key.f_2.name, 0);
	if (err != -EEXIST) {
		err = 6;
		goto out;
	}

	/* Lookup a non-existent key */
	bpf_dynptr_from_mem(dynptr_buf[0], sizeof(rcu_sched_name), 0, &key.f_2.name);
	key.f_3 = 0;
	value = bpf_map_lookup_elem(htab, &key);
	if (value) {
		err = 7;
		goto out;
	}

	/* Lookup an existent key */
	key.f_3 = 3;
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
	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(systemd_name), 0, &key.f_2.name);
	err = bpf_dynptr_write(&key.f_2.name, 0, (void *)systemd_name, sizeof(systemd_name), 0);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key.f_2.name, 0);
		err = 10;
		goto out;
	}
	err = bpf_map_delete_elem(htab, &key);
	if (err) {
		bpf_ringbuf_discard_dynptr(&key.f_2.name, 0);
		err = 11;
		goto out;
	}

	/* Lookup it again */
	value = bpf_map_lookup_elem(htab, &key);
	bpf_ringbuf_discard_dynptr(&key.f_2.name, 0);
	if (value) {
		err = 12;
		goto out;
	}
out:
	return err;
}

SEC("?raw_tp")
int BPF_PROG(pure_dynptr_key)
{
	int err;

	err = test_pure_dynptr_key_htab((struct bpf_map *)&htab_1);
	err |= test_pure_dynptr_key_htab((struct bpf_map *)&htab_2) << 8;

	return err;
}

SEC("?raw_tp")
int BPF_PROG(mixed_dynptr_key)
{
	return test_mixed_dynptr_key_htab((struct bpf_map *)&htab_3);
}

SEC("?raw_tp")
int BPF_PROG(nested_dynptr_key)
{
	return test_nested_dynptr_key_htab((struct bpf_map *)&htab_4);
}
