.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2021 Red Hat, Inc.

================================================
BPF_MAP_TYPE_ARRAY and BPF_MAP_TYPE_PERCPU_ARRAY
================================================

.. note:: ``BPF_MAP_TYPE_ARRAY`` was introduced in Kernel version 3.19 and
   ``BPF_MAP_TYPE_PERCPU_ARRAY`` in version 4.6

``BPF_MAP_TYPE_ARRAY`` and ``BPF_MAP_TYPE_PERCPU_ARRAY`` provide generic array
storage.  The key type is an unsigned 32-bit integer (4 bytes) and the map is of
constant size. All array elements are pre-allocated and zero initialized when
created. ``BPF_MAP_TYPE_PERCPU_ARRAY`` uses a different memory region for each
CPU whereas ``BPF_MAP_TYPE_ARRAY`` uses the same memory region. The maximum
size of an array, defined in max_entries, is limited to 2^32. The value stored
can be of any size, however, small values will be rounded up to 8 bytes.

Since Kernel 5.4, memory mapping may be enabled for ``BPF_MAP_TYPE_ARRAY`` by
setting the flag ``BPF_F_MMAPABLE``.  The map definition is page-aligned and
starts on the first page.  Sufficient page-sized and page-aligned blocks of
memory are allocated to store all array values, starting on the second page,
which in some cases will result in over-allocation of memory. The benefit of
using this is increased performance and ease of use since userspace programs
would not be required to use helper functions to access and mutate data.

Usage
=====

Array elements can be retrieved using the ``bpf_map_lookup_elem()`` helper.
This helper returns a pointer into the array element, so to avoid data races
with userspace reading the value, the user must use primitives like
``__sync_fetch_and_add()`` when updating the value in-place.  Access from
userspace uses the libbpf API of the same name.

Array elements can also be added using the ``bpf_map_update_elem()`` helper or
libbpf API.

Since the array is of constant size, ``bpf_map_delete_elem()`` is not supported.
To clear an array element, you may use ``bpf_map_update_eleme()`` to insert a
zero value to that index.

Values stored in ``BPF_MAP_TYPE_ARRAY`` can be accessed by multiple programs
across different CPUs.  To restrict storage to a single CPU, you may use a
``BPF_MAP_TYPE_PERCPU_ARRAY``.  Since Kernel version 5.1, the BPF infrastructure
provides ``struct bpf_spin_lock`` to synchronize access.

``bpf_map_get_next_key()`` can be used to iterate over array values.

Examples
========

Please see the `tools/testing/selftests/bpf`_ directory for functional examples.
This sample code simply demonstrates the API.

.. section links
.. _tools/testing/selftests/bpf:
   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf

Kernel
------

.. code-block:: c

    struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, u32);
        __type(value, long);
        __uint(max_entries, 256);
    } my_map SEC(".maps");

    int bpf_prog(struct __sk_buff *skb)
    {
        int index = load_byte(skb,
                              ETH_HLEN + offsetof(struct iphdr, protocol));
        long *value;

        if (skb->pkt_type != PACKET_OUTGOING)
            return 0;

        value = bpf_map_lookup_elem(&my_map, &index);
        if (value)
            __sync_fetch_and_add(value, skb->len);

        return 0;
    }

Userspace
---------

BPF_MAP_TYPE_ARRAY
~~~~~~~~~~~~~~~~~~

.. code-block:: c

    #include <assert.h>
    #include <bpf/libbpf.h>
    #include <bpf/bpf.h>

    int main(int argc, char **argv)
    {
        int fd;
        int ret = 0;
        __u32 i, j;
        __u32 index = 42;
        long v, value;

        fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(long),
                            256, 0);
        if (fd < 0)
            return fd;

        /* fill the map with values from 0-255 */
        for (i = 0; i < 256 ; i++) {
            ret = bpf_map_update_elem(fd, &i, &v, BPF_ANY);
            if (ret < 0)
                return ret;
        }

        ret = bpf_map_lookup_elem(fd, &index, &value);
        if (ret < 0)
            return ret;

        assert(value == 42);

        return ret;
    }

BPF_MAP_TYPE_PERCPU_ARRAY
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: c

    #include <assert.h>
    #include <bpf/libbpf.h>
    #include <bpf/bpf.h>

    int main(int argc, char **argv)
    {
        int ncpus = libbpf_num_possible_cpus();
        if (ncpus < 0)
            return ncpus;

        int fd;
        int ret = 0;
        __u32 i, j;
        __u32 index = 42;
        long v[ncpus], value[ncpus];


        fd = bpf_create_map(BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(__u32),
                            sizeof(long), 256, 0);
        if (fd < 0)
            return -1;

        /* fill the map with values from 0-255 for each cpu */
        for (i = 0; i < 256 ; i++) {
            for (j = 0; j < ncpus; j++)
                v[j] = i;
            ret = bpf_map_update_elem(fd, &i, &v, BPF_ANY);
            if (ret < 0)
                return ret;
        }

        ret = bpf_map_lookup_elem(fd, &index, &value);
        if (ret < 0)
            return ret;

        for (j = 0; j < ncpus; j++)
            assert(value[j] == 42);

        return ret;
    }

Semantics
=========

As illustrated in the example above, when using a ``BPF_MAP_TYPE_PERCPU_ARRAY``
in userspace, the values are an array with ``ncpus`` elements.

When calling ``bpf_map_update_elem()`` the flags ``BPF_NOEXIST`` can not be used
for these maps.

