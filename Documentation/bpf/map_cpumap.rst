.. SPDX-License-Identifier: GPL-2.0-only
.. Copyright (C) 2022 Red Hat, Inc.

===================
BPF_MAP_TYPE_CPUMAP
===================

.. note::
   - ``BPF_MAP_TYPE_CPUMAP`` was introduced in kernel version 4.15

``BPF_MAP_TYPE_CPUMAP`` is primarily used as a backend map for the XDP BPF helpers
``bpf_redirect_map()`` and ``XDP_REDIRECT`` action. This map type redirects raw
XDP frames to another CPU.

A CPUMAP is a scalability and isolation mechanism, that allows separating the driver
network XDP layer, from the rest of the network stack, and assigning dedicated
CPUs for this stage. An example use case for this map type is software based Receive
Side Scaling (RSS) at the XDP layer.

The CPUMAP represents the CPUs in the system indexed as the map-key, and the
map-value is the config setting (per CPUMAP entry). Each CPUMAP entry has a dedicated
kernel thread bound to the given CPU to represent the remote CPU execution unit.

The CPUMAP entry represents a multi-producer single-consumer (MPSC) queue
(implemented via ``ptr_ring`` in the kernel). The single consumer is the CPUMAP
``kthread`` that can access the ``ptr_ring`` queue without taking any lock. It also
tries to bulk dequeue eight xdp_frame objects, as they represent one cache line.
The multi-producers can be RX IRQ line CPUs queuing up packets simultaneously for
the remote CPU. To avoid queue lock contention for each producer CPU, there is a
small eight-object queue to generate bulk enqueueing into the cross-CPU queue.
This careful queue usage means that each cache line transfers eight frames across
the CPUs.

.. note::

    XDP packets getting XDP redirected to another CPU, will maximum be stored/queued
    for one ``driver ->poll()`` call. Queueing the frame and the flush operation
    are guaranteed to happen on same CPU. Thus, ``cpu_map_flush`` operation can deduce
    via ``this_cpu_ptr()`` which queue in bpf_cpu_map_entry contains packets.

Usage
=====

.. c:function::
   long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)

 CPU entries can be added or updated using the ``bpf_map_update_elem()``
 helper. This helper replaces existing elements atomically. The ``value`` parameter
 can be ``struct bpf_cpumap_val``.

 .. note::
    The maps can only be updated from user space and not from a BPF program.

 .. code-block:: c

    struct bpf_cpumap_val {
        __u32 qsize;  /* queue size to remote target CPU */
        union {
            int   fd; /* prog fd on map write */
            __u32 id; /* prog id on map read */
        } bpf_prog;
    };

 Starting from Linux kernel version 5.9 the CPUMAP can run a second XDP program
 on the remote CPU. This helps with scalability as the receive CPU should spend
 as few cycles as possible processing packets. The remote CPU (to which the packet is
 directed) can afford to spend more cycles processing the frame. For example, packets
 are received on a CPU to which the IRQ of the NIC RX queue is steered. This CPU
 is the one that initially sees the packets. This is where the XDP redirect program
 is executed. Because the objective is to scale the CPU usage across multiple CPUs,
 the eBPF program should use as few cycles as possible on this initial CPU; just
 enough to determine which remote CPU to send the packet to, and then move the
 packet to a remote CPU for continued processing. The remote CPUMAP ``kthread``
 receives raw XDP frame (``xdp_frame``) objects. If the frames are to be passed
 to the networking stack, the SKB objects are allocated by the remote CPU, and
 the SKBs are passed to the networking stack.

.. c:function::
   void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)

 CPU entries can be retrieved using the ``bpf_map_lookup_elem()``
 helper.

.. c:function::
   long bpf_map_delete_elem(struct bpf_map *map, const void *key)

 CPU entries can be deleted using the ``bpf_map_delete_elem()``
 helper. This helper will return 0 on success, or negative error in case of
 failure.

.. c:function::
     long bpf_redirect_map(struct bpf_map *map, u32 key, u64 flags)

 Redirect the packet to the endpoint referenced by ``map`` at index ``key``.
 For ``BPF_MAP_TYPE_CPUMAP`` this map contains references to CPUs.

 The lower two bits of *flags* are used as the return code if the map lookup
 fails. This is so that the return value can be one of the XDP program return
 codes up to ``XDP_TX``, as chosen by the caller.

Examples
========
Kernel
------

The following code snippet shows how to declare a BPF_MAP_TYPE_CPUMAP called cpu_map.

.. code-block:: c

   struct {
        __uint(type, BPF_MAP_TYPE_CPUMAP);
        __type(key, u32);
        __type(value, struct bpf_cpumap_val);
    } cpu_map SEC(".maps");

The following code snippet shows how to redirect packets to a remote CPU.

.. code-block:: c

    struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, u32);
        __type(value, u32);
    } cpus_available SEC(".maps"); /* Map populated by user space program as selectable redirect CPUs*/

    SEC("xdp")
    int  xdp_redir_cpu(struct xdp_md *ctx)
    {
        u32 key = bpf_get_smp_processor_id();
        u32 *cpu_selected;
        u32 cpu_dest = 0;

        cpu_selected = bpf_map_lookup_elem(&cpus_available, &key);
        if (!cpu_selected)
            return XDP_ABORTED;
        cpu_dest = *cpu_selected;

        if (cpu_dest >= bpf_num_possible_cpus()) {
            return XDP_ABORTED;
        }
        return bpf_redirect_map(&cpu_map, cpu_dest, 0);
    }

User Space
----------

The following code snippet shows how to update a CPUMAP called cpumap.

.. code-block:: c

    static int create_cpu_entry(__u32 cpu, struct bpf_cpumap_val *value)
    {
        int ret;

        ret = bpf_map_update_elem(bpf_map__fd(cpu_map), &cpu, value, 0);
        if (ret < 0)
            fprintf(stderr, "Create CPU entry failed: %s\n", strerror(errno));

        return ret;
    }

References
===========

- https://elixir.bootlin.com/linux/v6.0.1/source/kernel/bpf/cpumap.c
- https://developers.redhat.com/blog/2021/05/13/receive-side-scaling-rss-with-ebpf-and-cpumap#redirecting_into_a_cpumap
