.. SPDX-License-Identifier: GPL-2.0-only

Vhost dirty-log regression test
==============================

``vhost_log_test`` exercises used-ring logging through the existing
``/dev/vhost-test`` interface. It requires a test kernel with vhost support
and the ``vhost_test`` module built from ``tools/virtio/vhost_test`` for that
same kernel. Run it in a disposable VM, with permission to open the device.

Build the userspace executable from the kernel source root::

  make -C tools/virtio vhost_log_test

For a static initramfs executable, use ``LDFLAGS="-static -pthread"`` on a
clean build. Load ``vhost``, its dependencies, and ``vhost_test`` in the
guest, then run::

  ./vhost_log_test /mnt/vhost-log-scratch

The path is a disposable scratch file: the test truncates and removes it.
Use a disk-backed filesystem such as ext4 to exercise file writeback.
Omitting the path uses ``/tmp/vhost-log-test``. The test uses the vhost UAPI's
fixed 4 KiB ``VHOST_PAGE_SIZE`` and assumes the native little-endian legacy
vring layout; runtime coverage is intended for x86.

Keep this as a separate tool from ``virtio_test`` and ``vhost_net_test``.
It targets used-ring dirty logging through the dedicated ``/dev/vhost-test``
interface, which those tests do not configure or verify. Folding it into
either tool would add a separate module/device prerequisite without sharing
their test setup.

The suite covers every bit within a byte, repeated sets, neighboring-byte
preservation, unaligned byte addresses, a guarded page end, a used ring
write that spans two log pages (within one bitmap byte and across two),
first touch, inaccessible mappings and recovery, private COW, shared-file
sync/reread, eight workers sharing a byte, and concurrent userspace atomic
collection.
The collector checks each of 1000 independent rounds. Another 1000 rounds
use two aliases of a shared file page and discard one alias's PTEs before
each round, exercising resident and faulting accesses to the same bitmap.

Used-ring logging currently discards ``log_used()`` errors. Consequently,
the inaccessible-mapping cases check survival, absence of a successful
write and recovery; they do not verify userspace-visible ``-EFAULT``.
The collector verifies that all eight bits were observed in each round,
not that every repeated dirty event was counted. Alias tests exercise
fault fallback but do not establish a deterministic instruction ordering.
These tests do not replace MM race analysis or live migration testing.

Run the benchmark separately::

  taskset -c 0 ./vhost_log_test --bench

Each logging-disabled/enabled measurement warms up with 100 batches,
then times 10000 batches of 128 descriptors. The result includes queue
submission, worker execution and completion notification. It measures
nanoseconds per descriptor, not isolated ``set_bit_to_user()`` latency,
network throughput or migration time. Keep the kernel configuration and
VM setup identical, alternate baseline/optimized runs, and report multiple
samples. Affinity applies to the guest CPU; host CPU placement is separate.
