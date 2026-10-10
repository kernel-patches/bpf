.. SPDX-License-Identifier: GPL-2.0-only

==================
BPF_MAP_TYPE_ARENA
==================

A BPF arena provides shared memory that BPF programs and userspace can
access directly. Create the map with zero key and value sizes and
``BPF_F_MMAPABLE``. ``max_entries`` specifies its capacity in pages, up to
4 GiB. The canonical BPF address range must not cross a 4 GiB boundary.

Pinned arena files
==================

An arena created with ``BPF_F_ARENA_EXPORT`` can be pinned in bpffs and
opened as a sized file. Its size is ``max_entries * PAGE_SIZE``. Export
requires ``BPF_F_ARENA_NO_FREE`` so BPF programs cannot release backing
pages while external consumers may still use them. Creating an arena with
``BPF_F_ARENA_EXPORT`` alone fails with ``EINVAL``. Arenas without the
export flag retain their existing bpffs behavior and cannot be opened
this way, including arenas created with ``BPF_F_ARENA_NO_FREE`` alone.

Establish the canonical BPF address range before mapping the pinned file:

* Set ``map_extra`` to a nonzero, page-aligned address at map creation.
  The canonical range then covers the full map capacity, even if the map
  FD has not been mmaped.
* Alternatively, leave ``map_extra`` zero and mmap the map FD first. This
  mapping establishes the canonical address and must cover the full map
  capacity. Shorter canonical mappings fail with ``EINVAL``.

A canonical map FD mapping may start at address zero if the system's
low-address mapping policy permits it.

Mapping the pinned file before either step fails with ``EINVAL``. Exported
mappings do not establish or change the canonical BPF address range.

Once the canonical range is established, it covers the entire capacity
reported by ``fstat()``. Consumers can map the full file or smaller slices.
Establishing the full canonical mapping reserves virtual address space;
it does not populate every arena page. Arenas without
``BPF_F_ARENA_EXPORT`` can still establish shorter canonical mappings.

Open the pin with ``O_RDONLY`` for read-only access or ``O_RDWR`` for
writable access, and mmap it with ``MAP_SHARED``. An exported
mapping may use a different virtual address from the canonical mapping.
Its offset must be page-aligned, and its offset and length must fit within
both the map capacity and the established canonical range. Consumers can
map disjoint slices of one arena. Oversized or out-of-range mappings fail
with ``EINVAL``. ``MAP_PRIVATE`` mappings are unsupported.

Exported mappings share the bytes of the arena without relocating pointers
stored in those bytes. Arena pointers produced by a BPF program use that
arena's canonical address representation, based on ``user_vm_start``.
A consumer mapping a slice at another address must translate such pointers
before dereferencing them. A guest BPF arena has its own canonical range;
sharing the backing pages does not make host arena pointers valid in the
guest arena, or vice versa. Communication structures can use offsets
relative to the shared slice, with each side validating the offsets and
translating them to addresses in its own mapping or arena.

A pin opened with ``O_RDONLY`` supports read-only shared mappings, which
observe updates made by BPF programs and other writable mappings. Requests
for ``PROT_WRITE`` through that FD fail with ``EACCES``. A mapping made
without ``PROT_WRITE`` cannot subsequently acquire write permission with
``mprotect()``, even when the pin was opened with ``O_RDWR``.

Pin permissions can grant readers access independently of writers. For
example, mode ``0640`` permits the owner to open the pin for writable
access and the group to open it for read-only access, subject to the
applicable LSM checks. Changing permissions does not revoke access through
existing FDs or mappings.

The file has a fixed size. ``truncate()``, ``ftruncate()``, and ``O_TRUNC``
cannot change it. A truncate request that leaves the size unchanged is
allowed. Permission and ownership changes remain available.
Consumers can discover the capacity with ``fstat()`` or
``lseek(fd, 0, SEEK_END)``. Seeking supports ``SEEK_SET``, ``SEEK_CUR``, and
``SEEK_END`` within the file bounds; it does not enable ``read()`` or
``write()`` access to the memory.

``fsync()``, ``fdatasync()``, and ``msync(..., MS_SYNC)`` succeed without
performing writeback: arena memory is volatile and has no persistent
backing. These calls do not synchronize access between consumers or BPF
programs; shared-memory protocols still need appropriate memory ordering.

Exported mappings inherit the arena's mapping lifecycle restrictions.
They are not inherited across ``fork()``, and ``MADV_DOFORK`` cannot enable
inheritance. Consumers must create their own mappings in a child process.
Mappings cannot be split, expanded, or relocated with ``mremap()``.
Partial unmapping and protection changes that require splitting a mapping
fail with ``EINVAL``. Unmapping an entire mapping remains supported, as do
protection changes that do not require a split and satisfy the access
restrictions above. Consumers needing independently managed regions
should create separate slice mappings.

Access control and lifetime
===========================

Opening the pin uses ordinary filesystem permissions and file LSM checks,
as well as ``security_bpf_map()`` for the requested access mode. Mapping it
also passes the ordinary mmap LSM checks. Writable mappings remain subject
to the BPF map's frozen state and program-read-only restrictions.

Consumers use ``open()`` and ``mmap()`` rather than ``bpf(BPF_OBJ_GET)``.
Consequently, seccomp rules and LSM policies specific to the ``bpf()``
syscall do not govern this file interface. Grant access through the pin's
permissions and the applicable file, mmap, and BPF map LSM policies.
A process prohibited from calling ``bpf()`` can still access the arena
through this interface if those permissions and checks allow it.
``unprivileged_bpf_disabled`` restricts unprivileged map and program
creation; it does not generally prohibit access to existing maps.

``BPF_F_ARENA_NO_FREE`` makes ``bpf_arena_free_pages()`` a no-op in both
sleepable and non-sleepable BPF programs. The free operation returns no
indication that pages were retained. Programs using this flag must not
rely on freeing pages to restore arena allocation capacity. Arena pages
are retained until the map is destroyed. Open map and pin FDs, mappings,
and other map references retain the arena, including after the pin is
unlinked. Removing the pin therefore does not revoke existing mappings or
free their pages.

The retention flag does not itself expose the pin as a sized file.
``BPF_F_ARENA_EXPORT`` opts into that interface and must be combined with
``BPF_F_ARENA_NO_FREE``. Retention-only arenas can still share memory
through ordinary map FD mappings and manage reusable objects within
their retained pages.

For example, a consumer such as QEMU can use an exported slice as a shared
file-backed guest RAM backend. The file interface provides shared memory;
consumers must supply their own allocation and communication protocol.
