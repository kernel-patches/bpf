/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * Common BPF ELF operations.
 *
 * Copyright (C) 2013-2015 Alexei Starovoitov <ast@kernel.org>
 * Copyright (C) 2015 Wang Nan <wangnan0@huawei.com>
 * Copyright (C) 2015 Huawei Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 */
#ifndef __LIBBPF_BPF_H
#define __LIBBPF_BPF_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbpf_common.h"
#include "libbpf_legacy.h"

#ifdef __cplusplus
extern "C" {
#endif

LIBBPF_API int libbpf_set_memlock_rlim(size_t memlock_bytes);

struct bpf_map_create_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	__u32 btf_fd;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 btf_vmlinux_value_type_id;

	__u32 inner_map_fd;
	__u32 map_flags;
	__u64 map_extra;

	__u32 numa_node;
	__u32 map_ifindex;
	__s32 value_type_btf_obj_fd;

	__u32 token_fd;

	const void *excl_prog_hash;
	__u32 excl_prog_hash_size;
	size_t :0;
};
#define bpf_map_create_opts__last_field excl_prog_hash_size

/**
 * @brief Create a new BPF map.
 *
 * This helper wraps the kernel's BPF_MAP_CREATE command and returns a file
 * descriptor referring to the newly created map. The map's behavior (e.g.
 * key/value semantics, lookup/update constraints) is determined by its
 * type and various size parameters.
 *
 * @param map_type
 *        Map type (enum bpf_map_type) selecting the kernel map implementation
 *        (e.g. BPF_MAP_TYPE_HASH, ARRAY, LRU_HASH, PERCPU_ARRAY, etc.).
 *
 * @param map_name
 *        Optional human-readable name (null-terminated). May appear in
 *        bpftool output and used for pinning; can be NULL for unnamed maps.
 *        Must not exceed the kernel's NAME_MAX for BPF objects.
 *
 * @param key_size
 *        Size (in bytes) of a single key. For some map types this must match
 *        kernel expectations (e.g. prog array uses sizeof(int)). Must be > 0.
 *
 * @param value_size
 *        Size (in bytes) of a single value. Some map types have specific or
 *        implicit value sizes (e.g. perf event array); still pass the
 *        required size. Must be > 0 unless the map type defines otherwise.
 *
 * @param max_entries
 *        Maximum number of key/value pairs (capacity). For certain map types
 *        (e.g. ring buffer, stack, queue) semantics differ but this field is
 *        still used. Must be > 0 except for types that ignore it.
 *
 * @param opts
 *        Optional pointer to bpf_map_create_opts providing extended creation
 *        parameters. Pass NULL for defaults. Common fields include:
 *          - .map_flags: Additional BPF map flags (e.g. BPF_F_NO_PREALLOC).
 *          - .numa_node: Prefer allocation on specified NUMA node.
 *          - .btf_fd / .btf_key_type_id / .btf_value_type_id: Associate BTF
 *            types for verification and introspection.
 *          - .inner_map_fd: For map-in-map types (array_of_maps / hash_of_maps).
 *          - .map_ifindex: Bind map to a network interface when supported.
 *          - .map_extra: Reserved/experimental extensions (depends on kernel).
 *        Not all fields may be available in older libbpf versions; zero-init
 *        the struct and set only known fields.
 *
 * @return
 *        >= 0: File descriptor of the created map (caller owns it and should
 *              close() when no longer needed).
 *        < 0 : Negative error code (libbpf style, typically -errno). Detailed
 *              reason can be inferred from -ret or examined via errno (if
 *              converted) / libbpf logging.
 */
LIBBPF_API int bpf_map_create(enum bpf_map_type map_type,
			      const char *map_name,
			      __u32 key_size,
			      __u32 value_size,
			      __u32 max_entries,
			      const struct bpf_map_create_opts *opts);

struct bpf_prog_load_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	/* libbpf can retry BPF_PROG_LOAD command if bpf() syscall returns
	 * -EAGAIN. This field determines how many attempts libbpf has to
	 *  make. If not specified, libbpf will use default value of 5.
	 */
	int attempts;

	enum bpf_attach_type expected_attach_type;
	__u32 prog_btf_fd;
	__u32 prog_flags;
	__u32 prog_ifindex;
	__u32 kern_version;

	__u32 attach_btf_id;
	__u32 attach_prog_fd;
	__u32 attach_btf_obj_fd;

	const int *fd_array;

	/* .BTF.ext func info data */
	const void *func_info;
	__u32 func_info_cnt;
	__u32 func_info_rec_size;

	/* .BTF.ext line info data */
	const void *line_info;
	__u32 line_info_cnt;
	__u32 line_info_rec_size;

	/* verifier log options */
	__u32 log_level;
	__u32 log_size;
	char *log_buf;
	/* output: actual total log contents size (including terminating zero).
	 * It could be both larger than original log_size (if log was
	 * truncated), or smaller (if log buffer wasn't filled completely).
	 * If kernel doesn't support this feature, log_size is left unchanged.
	 */
	__u32 log_true_size;
	__u32 token_fd;

	/* if set, provides the length of fd_array */
	__u32 fd_array_cnt;
	size_t :0;
};
#define bpf_prog_load_opts__last_field fd_array_cnt
/**
 * @brief Load (verify and register) a BPF program into the kernel.
 *
 * This is a high-level libbpf wrapper around the BPF_PROG_LOAD command of the
 * bpf(2) syscall. It submits an array of eBPF instructions to the kernel
 * verifier, optionally provides BTF metadata and attachment context, and
 * returns a file descriptor referring to the newly loaded (but not yet
 * attached) BPF program.
 *
 * Core flow:
 *   1. The kernel verifier validates instruction safety, helper usage,
 *      stack bounds, pointer arithmetic, and (if provided) BTF type
 *      consistency.
 *   2. If verification succeeds, a program FD is returned (>= 0).
 *   3. If verification fails, a negative libbpf-style error is returned
 *      (< 0). If logging was requested via @c opts->log_* fields, a textual
 *      verifier log may be captured for debugging.
 *
 * @param prog_type
 *        Enumerated BPF program type (enum bpf_prog_type) selecting verifier
 *        expectations and permissible helpers (e.g. BPF_PROG_TYPE_SOCKET_FILTER,
 *        BPF_PROG_TYPE_KPROBE, BPF_PROG_TYPE_TRACING, BPF_PROG_TYPE_XDP, etc.).
 *
 * @param prog_name
 *        Optional, null-terminated human-readable name. Visible via bpftool
 *        and in kernel introspection APIs. Can be NULL. If longer than the
 *        kernel's max BPF object name length (typically BPF_OBJ_NAME_LEN),
 *        it will be truncated. Use concise alphanumeric/underscore names.
 *
 * @param license
 *        Null-terminated license string (e.g. "GPL", "Dual BSD/GPL"). Determines
 *        eligibility for GPL-only helpers. Must not be NULL. Passing a license
 *        incompatible with required GPL-only helpers yields -EACCES/-EPERM.
 *
 * @param insns
 *        Pointer to an array of eBPF instructions (struct bpf_insn). Must be
 *        non-NULL and executable by the verifier (no out-of-bounds jumps, etc.).
 *        The kernel copies this array; caller can free/modify it after return.
 *
 * @param insn_cnt
 *        Number of instructions in @p insns. Must be > 0 and within kernel
 *        limits (historically <= ~1M instructions; exact cap is kernel-specific).
 *        A too large value results in -E2BIG or -EINVAL.
 *
 * @param opts
 *        Optional pointer to a zero-initialized struct bpf_prog_load_opts
 *        providing extended parameters. Pass NULL for defaults. Only set
 *        fields you understand; leaving others zero ensures fwd/back compat.
 *
 *        Notable fields:
 *          - sz: Must be set to sizeof(struct bpf_prog_load_opts) for libbpf
 *            to validate structure layout.
 *          - attempts: Number of automatic retries if bpf() returns -EAGAIN
 *            (transient verifier/resource contention). Default is 5 if zero.
 *          - expected_attach_type: For some program types (tracing, LSM, etc.)
 *            the verifier requires an attach type hint.
 *          - prog_btf_fd: BTF describing function prototypes / types referenced
 *            by the program (enables CO-RE relocations, enhanced validation).
 *          - prog_flags: Bitmask of program load flags (e.g. BPF_F_STRICT_ALIGNMENT,
 *            BPF_F_SLEEPABLE for sleepable programs; availability is kernel-dependent).
 *          - prog_ifindex: Network interface index for certain net-specific types
 *            (e.g., tc or XDP offload scenarios).
 *          - kern_version: Legacy field (mostly for old kernels / cBPF migration).
 *          - attach_btf_id / attach_btf_obj_fd: Identify kernel BTF target (e.g.
 *            function or struct) for fentry/fexit/tracing program types.
 *          - attach_prog_fd: Attach to an existing BPF program (e.g. for extension).
 *          - fd_array / fd_array_cnt: Supply an array of FDs (maps, progs) when the
 *            kernel expects auxiliary references (advanced use cases).
 *          - func_info / line_info (+ *_cnt, *_rec_size): Raw .BTF.ext sections
 *            used for richer debugging and introspection (normally handled by
 *            libbpf when loading from object files; rarely set manually).
 *          - log_level / log_size / log_buf: Request verifier output. Set
 *            log_level > 0, allocate log_buf of at least log_size bytes. After
 *            return, log_true_size (if kernel supports) reflects actual length
 *            (may exceed provided size if truncated).
 *          - token_fd: BPF token for delegated permissions (non-root controlled
 *            environments).
 *
 *        Unrecognized (future) fields should remain zeroed. Always update sz.
 *
 * @return
 *        >= 0 : File descriptor of loaded BPF program; caller owns it and must
 *                close() when no longer needed.
 *        < 0  : Negative libbpf-style error code (typically -errno). Common:
 *                  - -EINVAL: Malformed instructions, bad prog_type/flags, struct
 *                             size mismatch, missing required attach hints.
 *                  - -EACCES / -EPERM: Disallowed helpers (license/capability),
 *                                        missing CAP_BPF/CAP_SYS_ADMIN or blocked
 *                                        by LSM/lockdown.
 *                  - -E2BIG: Instruction count or log size too large.
 *                  - -ENOMEM: Kernel memory/resource exhaustion.
 *                  - -EFAULT: Bad user pointers (insns/log_buf).
 *                  - -EOPNOTSUPP: Unsupported program type or flag on this kernel.
 *                  - -ENOSPC: Program too complex (e.g. verifier limits exceeded).
 *                  - -EAGAIN: Transient verifier failure; libbpf may retry until
 *                              attempts exhausted.
 *
 */
LIBBPF_API int bpf_prog_load(enum bpf_prog_type prog_type,
			     const char *prog_name, const char *license,
			     const struct bpf_insn *insns, size_t insn_cnt,
			     struct bpf_prog_load_opts *opts);

/* Flags to direct loading requirements */
#define MAPS_RELAX_COMPAT	0x01

/* Recommended log buffer size */
#define BPF_LOG_BUF_SIZE (UINT32_MAX >> 8) /* verifier maximum in kernels <= 5.1 */

struct bpf_btf_load_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	/* kernel log options */
	char *log_buf;
	__u32 log_level;
	__u32 log_size;
	/* output: actual total log contents size (including terminating zero).
	 * It could be both larger than original log_size (if log was
	 * truncated), or smaller (if log buffer wasn't filled completely).
	 * If kernel doesn't support this feature, log_size is left unchanged.
	 */
	__u32 log_true_size;

	__u32 btf_flags;
	__u32 token_fd;
	size_t :0;
};
#define bpf_btf_load_opts__last_field token_fd

LIBBPF_API int bpf_btf_load(const void *btf_data, size_t btf_size,
			    struct bpf_btf_load_opts *opts);

/**
 * @brief Update or insert an element in a BPF map.
 *
 * Attempts to store the value referenced by @p value into the BPF map
 * identified by @p fd under the key referenced by @p key. The semantics
 * of the operation are controlled by @p flags:
 *
 *   - BPF_ANY:     Create a new element or update an existing one.
 *   - BPF_NOEXIST: Create a new element only; fail if the key already exists (errno = EEXIST).
 *   - BPF_EXIST:   Update an existing element only; fail if the key does not exist (errno = ENOENT).
 *   - (Optional) BPF_F_LOCK: If supported by the map type, perform a lock-based update
 *                            (mainly for certain per-cpu map types).
 *
 * The memory pointed to by @p key and @p value must be at least the size of the map's
 * key and value definitions respectively, and properly aligned for the target architecture.
 * Callers typically place key/value objects on the stack or in static storage; the kernel
 * copies their contents during the call, so they need not remain valid after the function
 * returns.
 *
 * Concurrency: For most map types, updates are atomic with respect to lookups and other
 * updates. For per-CPU maps, the update affects the current CPU's copy (unless a flag
 * or map type enforces different behavior). Locking flags (e.g., BPF_F_LOCK) may be
 * required for certain map types to ensure consistent read-modify-write sequences.
 *
 * Privileges: Some map updates may require CAP_SYS_ADMIN or CAP_BPF depending on the
 * map type and system configuration (e.g., locked down environments or LSM policies).
 *
 * @param fd     File descriptor referring to the opened BPF map.
 * @param key    Pointer to the key data to be inserted/updated.
 * @param value  Pointer to the value data to be stored for the key.
 * @param flags  Operation control flags (see above).
 *
 * @return 0 on success; negative error code, otherwise (errno is also set to
 * the error code).
 *
 * Possible errno values include (not exhaustive):
 *   - E2BIG:      Key or value size exceeds map definition.
 *   - EINVAL:     Invalid map fd, flags, or unsupported operation for map type.
 *   - EBADF:      @p fd is not a valid BPF map descriptor.
 *   - ENOENT:     Key does not exist (with BPF_EXIST).
 *   - EEXIST:     Key already exists (with BPF_NOEXIST).
 *   - ENOMEM:     Kernel memory allocation failure.
 *   - EPERM/EACCES: Insufficient privileges or rejected by security policy.
 *   - ENOSPC:     Map at capacity (for maps with a max entries limit).
 *
 */
LIBBPF_API int bpf_map_update_elem(int fd, const void *key, const void *value,
				   __u64 flags);

/**
 * @brief Look up an element in a BPF map by key.
 *
 * Retrieves the value associated with the specified key from a BPF map
 * identified by its file descriptor. The caller must supply a pointer to
 * a key of the map's key size, and a writable buffer large enough to hold
 * the map's value size. On success, the value buffer is filled with the
 * data stored in the map.
 *
 * This is a blocking system call that wraps the BPF_MAP_LOOKUP_ELEM
 * command. It may incur a context switch and can fail for a variety of
 * reasons, including transient kernel conditions.
 *
 * @param fd   File descriptor of an open BPF map (obtained via bpf_obj_get(),
 *             bpf_map_create(), or via loading an object file).
 * @param key  Pointer to a buffer containing the key to look up. The buffer
 *             must be exactly the size of the map's key type.
 * @param value Pointer to a buffer where the map's value will be copied on
 *             success. Must be at least the size of the map's value type.
 *
 * @return 0 on success (value populated); negative error code, otherwise
 * (errno is also set to the error code):
 *         - ENOENT: The key does not exist in the map.
 *         - EINVAL: Invalid parameters (e.g., wrong sizes or bad map type).
 *         - EPERM / EACCES: Insufficient privileges (e.g., missing CAP_BPF or
 *           related capability).
 *         - EBADF: Invalid map file descriptor.
 *         - ENOMEM: Kernel could not allocate required memory.
 *         - EFAULT: key or value points to invalid user memory.
 *
 */
LIBBPF_API int bpf_map_lookup_elem(int fd, const void *key, void *value);

/**
 * @brief Look up (read) a value stored in a BPF map.
 *
 * This is a thin libbpf wrapper around the BPF_MAP_LOOKUP_ELEM command of the
 * bpf(2) system call. It retrieves the value associated with the provided key
 * from the map referred to by fd.
 *
 * The caller must supply storage for both the key and the value. On success
 * the memory pointed to by value is filled with the map element's data.
 *
 * Concurrency semantics depend on the map type. For maps whose values contain
 * a bpf_spin_lock (e.g. certain HASH or ARRAY-like map types), you may pass
 * the BPF_F_LOCK flag in flags to request that the kernel return the value
 * while holding the spin lock, guaranteeing a consistent snapshot for complex
 * composite data. The lock is released immediately after copying the value
 * out to user space. Pass 0 for default (unlocked) lookup semantics.
 *
 * Note: Only flags supported by the running kernel (currently BPF_F_LOCK) are
 * valid; unsupported flags will cause the lookup to fail with EINVAL.
 *
 * Key requirements:
 *  - For array-like maps (e.g., BPF_MAP_TYPE_ARRAY, PERCPU_ARRAY), key points
 *    to an integer index.
 *  - For hash-like maps, key points to a full key of the map's declared key
 *    size.
 *
 * Value requirements:
 *  - value must point to a buffer at least as large as the map's value size
 *    (use bpf_obj_get_info_by_fd() or bpf_map__value_size() helpers to query
 *    this).
 *
 * @param fd     File descriptor of the BPF map obtained via bpf_create_map(),
 *               bpf_obj_get(), or a libbpf helper.
 * @param key    Pointer to the key (or index) identifying the element to read.
 *               Must not be nullptr.
 * @param value  Pointer to caller-allocated buffer that receives the value on
 *               success. Must not be nullptr.
 * @param flags  Bitmask of lookup flags. Use 0 for a normal lookup. Specify
 *               BPF_F_LOCK (if supported) to perform a locked read of values
 *               containing a bpf_spin_lock.
 *
 * @return 0 on success; negative error code, otherwise
 * (errno is also set to the error code):
 *         - ENOENT: No element with the specified key exists.
 *         - EINVAL: Invalid arguments (bad flags, key/value pointers, or map type).
 *         - EPERM / EACCES: Insufficient privileges (e.g., map access restrictions).
 *         - EBADF: Invalid map file descriptor.
 *         - EFAULT: key or value points to unreadable/writable memory.
 *         - E2BIG: Key size does not match the map's declared key size.
 *         - Other standard Linux errors depending on map type and kernel.
 *
 */
LIBBPF_API int bpf_map_lookup_elem_flags(int fd, const void *key, void *value,
					 __u64 flags);
/**
 * @brief Atomically look up and delete a single element from a BPF map.
 *
 * Performs a combined "lookup-and-delete" operation for the element
 * identified by the key pointed to by @p key in the map referred to by
 * @p fd. If the key exists, its value is copied into the user-provided
 * @p value buffer (if non-null) and the element is removed from the map
 * as one atomic kernel operation, preventing races between a separate
 * lookup and delete sequence.
 *
 * Supported map types are those for which the kernel implements
 * BPF_MAP_LOOKUP_AND_DELETE_ELEM (e.g., queue/stack-like maps and
 * certain hash variants). On unsupported map types the call fails.
 *
 * Concurrency:
 *  - The lookup and deletion are performed atomically with respect to
 *    other map operations on the same key, avoiding TOCTOU races.
 *  - For per-CPU maps (where applicable) the deletion affects only the
 *    current CPU's instance unless the map semantics dictate otherwise.
 *
 * Memory requirements:
 *  - @p key must point to a buffer exactly equal to the declared key
 *    size of the map.
 *  - @p value must point to a buffer at least as large as the map's
 *    value size. If @p value is NULL, no value is copied; the element
 *    is still deleted (kernel may return EFAULT on older kernels that
 *    require a non-null value pointer).
 *
 * Privileges:
 *  - May require CAP_BPF or CAP_SYS_ADMIN depending on kernel
 *    configuration, LSM policies, or lockdown state.
 *
 * @param fd     File descriptor of an open BPF map.
 * @param key    Pointer to the key identifying the element to remove.
 * @param value  Pointer to caller-allocated buffer that receives the
 *               value prior to deletion (can be NULL on kernels that
 *               allow skipping value copy).
 *
 * @return 0 on success (value copied and element deleted); negative error
 * code, otherwise (errno is also set to the error code):
 *         - ENOENT: Key not found in the map.
 *         - EINVAL: Invalid arguments (bad key pointer/size, unsupported map type).
 *         - EOPNOTSUPP: Operation not supported for this map type.
 *         - EBADF: @p fd is not a valid BPF map descriptor.
 *         - EFAULT: key/value points to inaccessible user memory.
 *         - EPERM / EACCES: Insufficient privileges.
 *         - ENOMEM: Kernel failed to allocate temporary resources.
 *
 */
LIBBPF_API int bpf_map_lookup_and_delete_elem(int fd, const void *key,
					      void *value);
/**
 * @brief Atomically look up and delete an element from a BPF map with extra flags.
 *
 * This is a flags-capable variant of bpf_map_lookup_and_delete_elem(). It performs
 * a single atomic kernel operation that (optionally) retrieves the value associated
 * with the specified key and then deletes the element from the map. The additional
 * @p flags parameter allows requesting special semantics if supported by the map
 * type and kernel (e.g., locked access with BPF_F_LOCK when the map value embeds
 * a bpf_spin_lock).
 *
 * Semantics:
 *   - If the key exists:
 *       * Its value is copied into the user-provided @p value buffer (if non-NULL).
 *       * The element is removed from the map.
 *   - If the key does not exist: fails with errno = ENOENT, no deletion performed.
 *
 * Atomicity:
 *   The lookup and deletion occur as one kernel operation, eliminating race
 *   windows that would exist if lookup and delete were performed separately.
 *
 * Flags (@p flags):
 *   - 0: Perform a normal atomic lookup-and-delete.
 *   - BPF_F_LOCK: If supported and the map value contains a bpf_spin_lock, the
 *                 kernel acquires the spin lock during value retrieval ensuring
 *                 a consistent snapshot, then releases it prior to returning.
 *   - Other bits: Must be zero unless future kernels introduce new semantics;
 *                 unsupported flags yield -1 with errno = EINVAL.
 *
 * Memory requirements:
 *   - @p key must point to a buffer exactly the size of the map's key.
 *   - @p value must point to a buffer at least the size of the map's value if
 *     non-NULL. Passing NULL skips value copy (if supported by the running kernel).
 *
 * Supported map types:
 *   Only those implementing BPF_MAP_LOOKUP_AND_DELETE_ELEM (e.g., queue, stack,
 *   certain hash variants). Unsupported types fail with errno = EOPNOTSUPP.
 *
 * Privileges:
 *   May require CAP_BPF or CAP_SYS_ADMIN depending on kernel configuration,
 *   lockdown mode, or LSM policies.
 *
 * Concurrency:
 *   - The operation is atomic with respect to other concurrent updates,
 *     lookups, or deletions of the same key.
 *   - For per-CPU maps, semantics follow the underlying map implementation
 *     (typically deleting from the calling CPU's instance).
 *
 * @param fd     File descriptor of an open BPF map.
 * @param key    Pointer to the key identifying the element to consume.
 * @param value  Optional pointer to a buffer receiving the element's value prior
 *               to deletion. Can be NULL to skip retrieval (subject to kernel support).
 * @param flags  Bitmask controlling lookup/delete behavior (see above).
 *
 * @return 0 on success; negative error code, otherwise
 * (errno is also set to the error code):
 *         - ENOENT: Key not found.
 *         - EINVAL: Bad arguments, unsupported flags, or mismatched key size.
 *         - EOPNOTSUPP: Operation not supported for this map type.
 *         - EBADF: Invalid map file descriptor.
 *         - EFAULT: key/value points to inaccessible user memory.
 *         - EPERM / EACCES: Insufficient privileges / denied by security policy.
 *         - ENOMEM: Temporary kernel allocation failure.
 *
 */
LIBBPF_API int bpf_map_lookup_and_delete_elem_flags(int fd, const void *key,
						    void *value, __u64 flags);
/**
 * @brief Delete (remove) a single element from a BPF map.
 *
 * Issues the BPF_MAP_DELETE_ELEM command for the map referenced by @p fd,
 * removing the element identified by the key pointed to by @p key. This
 * helper is the simplest deletion API and does not support any additional
 * deletion or locking flags. For flag-capable deletion semantics (e.g.,
 * locked delete of spin_lock-embedded values) use bpf_map_delete_elem_flags().
 *
 * Semantics:
 *   - If an element with the specified key exists, it is atomically removed.
 *   - If the key is absent, the call fails with errno = ENOENT.
 *   - No value is returned; if you need to retrieve and consume an element,
 *     use bpf_map_lookup_and_delete_elem() (or its flags variant).
 *
 * Concurrency:
 *   - Deletion is atomic with respect to concurrent lookups and updates of
 *     the same key.
 *   - Ordering relative to other operations is map-type dependent; no
 *     global ordering guarantees are provided beyond atomicity for the key.
 *
 * Key requirements:
 *   - @p key must point to a buffer exactly equal in size to the map's
 *     declared key size. Supplying a buffer of incorrect size or alignment
 *     can lead to EINVAL or EFAULT.
 *
 * Privileges:
 *   - May require CAP_BPF, CAP_SYS_ADMIN, or be restricted by LSM or
 *     lockdown policies depending on system configuration and map type.
 *
 * Error handling (errno set on failure):
 *   - ENOENT: Key not found in the map.
 *   - EINVAL: Invalid map fd, bad key size, or operation unsupported for map type.
 *   - EBADF:  @p fd is not a valid (open) BPF map descriptor.
 *   - EFAULT: @p key points to unreadable user memory.
 *   - EPERM / EACCES: Insufficient privileges or blocked by security policy.
 *   - ENOMEM: Transient kernel memory/resource exhaustion (rare).
 *
 * @param fd  File descriptor of an open BPF map.
 * @param key Pointer to a buffer containing the key to delete; must not be NULL.
 *
 * @return 0 on success; negative error code, otherwise
 * (errno is also set to the error code).
 *
 */
LIBBPF_API int bpf_map_delete_elem(int fd, const void *key);
/**
 * @brief Delete an element from a BPF map with optional flags.
 *
 * This is a flags-capable variant of bpf_map_delete_elem(). It issues the
 * BPF_MAP_DELETE_ELEM command to remove the element identified by the key
 * pointed to by @p key from the map referenced by @p fd. Unlike the plain
 * variant, this helper allows passing lookup/delete control flags in @p flags.
 *
 * Typical usage mirrors bpf_map_delete_elem(), but if the map's value type
 * embeds a bpf_spin_lock (and the kernel supports locked delete semantics),
 * you may specify BPF_F_LOCK in @p flags to request the kernel to take the
 * spin lock while performing the deletion, ensuring consistent removal for
 * composite values that might otherwise require user space synchronization.
 *
 * Semantics:
 *   - If the key exists, the element is removed.
 *   - If the key does not exist, the call fails with errno = ENOENT.
 *   - No value is returned; for consume-and-retrieve use
 *     bpf_map_lookup_and_delete_elem() or
 *     bpf_map_lookup_and_delete_elem_flags().
 *
 * Flags (@p flags):
 *   - 0: Perform a normal deletion.
 *   - BPF_F_LOCK: (If supported) acquire/release map value's spin lock around
 *     delete operation. Ignored or rejected if unsupported for the map type.
 *   - Unsupported bits cause failure with errno = EINVAL.
 *
 * Concurrency:
 *   - Deletion is atomic with respect to concurrent lookups/updates of the
 *     same key.
 *   - For per-CPU map types, semantics follow underlying implementation
 *     (only current CPU's instance is affected where applicable).
 *
 * Privileges:
 *   - May require CAP_BPF or CAP_SYS_ADMIN depending on kernel configuration,
 *     system lockdown mode, or LSM policies.
 *
 * @param fd     File descriptor of an open BPF map.
 * @param key    Pointer to a buffer containing the key to delete. Must be
 *               exactly the size of the map's key type.
 * @param flags  Deletion control flags (see above). Use 0 for default behavior.
 *
 * @return 0 on success; negative error code, otherwise
 * (errno is also set to the error code):
 *         - ENOENT: Key not found.
 *         - EINVAL: Invalid arguments, unsupported flags, or wrong key size.
 *         - EBADF:  @p fd is not a valid BPF map descriptor.
 *         - EFAULT: @p key points to inaccessible user memory.
 *         - EPERM / EACCES: Insufficient privileges or denied by security policy.
 *         - ENOMEM: Temporary kernel resource allocation failure.
 *
 */
LIBBPF_API int bpf_map_delete_elem_flags(int fd, const void *key, __u64 flags);
/**
 * @brief Iterate over keys in a BPF map by retrieving the key that follows a given key.
 *
 * This helper wraps the BPF_MAP_GET_NEXT_KEY command. It copies into @p next_key
 * the key that lexicographically (or implementation-defined order) follows @p key
 * in the map referenced by @p fd. It is typically used to enumerate all keys in
 * a map from user space.
 *
 * Iteration pattern:
 *   1. Pass NULL as @p key to retrieve the first key in the map.
 *   2. On each successful call, use the returned @p next_key as the @p key input
 *      for the subsequent call to advance the iteration.
 *   3. When there are no more keys, the call fails with errno = ENOENT and
 *      iteration is complete.
 *
 * Concurrency:
 *   - The order of enumeration is not guaranteed to be stable across concurrent
 *     inserts/deletes. Keys added or removed during iteration may or may not be
 *     observed.
 *   - For hash-like maps, ordering is implementation-dependent (hash bucket
 *     traversal). For array-like maps (ARRAY/PERCPU_ARRAY), "next" corresponds
 *     to the next valid index.
 *
 * Memory requirements:
 *   - @p key (if non-NULL) must point to a buffer exactly the size of the map's
 *     key type.
 *   - @p next_key must point to a writable buffer at least the size of the map's
 *     key type.
 *
 * Privileges:
 *   - Access may require CAP_BPF or CAP_SYS_ADMIN depending on system lockdown
 *     mode, LSM policy, or map type.
 *
 * @param fd       File descriptor of an open BPF map.
 * @param key      Pointer to the current key; NULL to start iteration from the first key.
 * @param next_key Pointer to a buffer that receives the next key on success.
 *
 * @return 0 on success (next key stored in @p next_key); negative error code, otherwise
 * (errno is also set to the error code):
 *           - ENOENT: No further keys (end of iteration) or map is empty (when @p key is NULL).
 *           - EINVAL: Invalid arguments (bad fd, wrong key size, unsupported map type).
 *           - EBADF:  @p fd is not a valid BPF map descriptor.
 *           - EFAULT: @p key or @p next_key points to inaccessible user memory.
 *           - EPERM / EACCES: Insufficient privileges or access denied by security policy.
 *
 */
LIBBPF_API int bpf_map_get_next_key(int fd, const void *key, void *next_key);
/**
 * @brief Mark a BPF map as frozen (read-only for any future user space modifications).
 *
 * Invokes the kernel's BPF_MAP_FREEZE command on the map referred to by @p fd.
 * Once a map is successfully frozen:
 *   - User space can still perform lookups (bpf_map_lookup_elem*(), batch lookups, etc.).
 *   - All further update, delete, and batch mutation operations from user space
 *     will fail (typically with EPERM).
 *   - Freezing is irreversible for the lifetime of the map.
 *
 * Typical use cases:
 *   - Finalizing initialization data (e.g., config arrays or constant maps)
 *     before exposing the map to untrusted code or other processes.
 *   - Enforcing write-once semantics to ensure stronger safety guarantees.
 *   - Preventing accidental or malicious runtime mutation of maps that should
 *     remain constant after setup.
 *
 * Semantics & scope:
 *   - The freeze applies system-wide to the map object, not just to the calling
 *     process.
 *   - BPF programs' ability to modify the map after freezing depends on kernel
 *     semantics: for most map types, freezing blocks user space mutations only.
 *     (Do not rely on program write restrictions unless explicitly documented
 *     for a specific kernel/map type.)
 *   - Re-freezing an already frozen map succeeds (idempotent) or may return
 *     an error depending on kernel version; treat a second freeze as a no-op.
 *
 * Privileges:
 *   - Typically requires CAP_BPF or CAP_SYS_ADMIN (depending on kernel
 *     configuration, LSM, and lockdown state).
 *
 * @param fd File descriptor of an open BPF map to freeze.
 *
 * @return 0 on success; negative libbpf-style error code (< 0) on failure.
 *
 * Possible errors (returned as -errno style negatives):
 *   - -EBADF: @p fd is not a valid file descriptor.
 *   - -EINVAL: @p fd is not a BPF map, or map type is not freezable.
 *   - -EPERM / -EACCES: Insufficient privileges or blocked by security policy.
 *   - -EOPNOTSUPP: Kernel doesn't support BPF_MAP_FREEZE.
 *   - -ENOMEM: Temporary resource allocation failure inside the kernel.
 *
 * Thread safety:
 *   - Safe to call concurrently; only the first successful call transitions
 *     the map into the frozen state.
 *
 * After freezing:
 *   - Continue using lookup APIs to read data.
 *   - Avoid calling mutation APIs (update/delete) unless prepared to handle
 *     expected failures.
 *
 */
LIBBPF_API int bpf_map_freeze(int fd);

struct bpf_map_batch_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u64 elem_flags;
	__u64 flags;
};
#define bpf_map_batch_opts__last_field flags


/**
 * @brief **bpf_map_delete_batch()** allows for batch deletion of multiple
 * elements in a BPF map.
 *
 * @param fd BPF map file descriptor
 * @param keys pointer to an array of *count* keys
 * @param count input and output parameter; on input **count** represents the
 * number of  elements in the map to delete in batch;
 * on output if a non-EFAULT error is returned, **count** represents the number of deleted
 * elements if the output **count** value is not equal to the input **count** value
 * If EFAULT is returned, **count** should not be trusted to be correct.
 * @param opts options for configuring the way the batch deletion works
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_map_delete_batch(int fd, const void *keys,
				    __u32 *count,
				    const struct bpf_map_batch_opts *opts);

/**
 * @brief **bpf_map_lookup_batch()** allows for batch lookup of BPF map elements.
 *
 * The parameter *in_batch* is the address of the first element in the batch to
 * read. *out_batch* is an output parameter that should be passed as *in_batch*
 * to subsequent calls to **bpf_map_lookup_batch()**. NULL can be passed for
 * *in_batch* to indicate that the batched lookup starts from the beginning of
 * the map. Both *in_batch* and *out_batch* must point to memory large enough to
 * hold a single key, except for maps of type **BPF_MAP_TYPE_{HASH, PERCPU_HASH,
 * LRU_HASH, LRU_PERCPU_HASH}**, for which the memory size must be at
 * least 4 bytes wide regardless of key size.
 *
 * The *keys* and *values* are output parameters which must point to memory large enough to
 * hold *count* items based on the key and value size of the map *map_fd*. The *keys*
 * buffer must be of *key_size* * *count*. The *values* buffer must be of
 * *value_size* * *count*.
 *
 * @param fd BPF map file descriptor
 * @param in_batch address of the first element in batch to read, can pass NULL to
 * indicate that the batched lookup starts from the beginning of the map.
 * @param out_batch output parameter that should be passed to next call as *in_batch*
 * @param keys pointer to an array large enough for *count* keys
 * @param values pointer to an array large enough for *count* values
 * @param count input and output parameter; on input it's the number of elements
 * in the map to read in batch; on output it's the number of elements that were
 * successfully read.
 * If a non-EFAULT error is returned, count will be set as the number of elements
 * that were read before the error occurred.
 * If EFAULT is returned, **count** should not be trusted to be correct.
 * @param opts options for configuring the way the batch lookup works
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_map_lookup_batch(int fd, void *in_batch, void *out_batch,
				    void *keys, void *values, __u32 *count,
				    const struct bpf_map_batch_opts *opts);

/**
 * @brief **bpf_map_lookup_and_delete_batch()** allows for batch lookup and deletion
 * of BPF map elements where each element is deleted after being retrieved.
 *
 * @param fd BPF map file descriptor
 * @param in_batch address of the first element in batch to read, can pass NULL to
 * get address of the first element in *out_batch*. If not NULL, must be large
 * enough to hold a key. For **BPF_MAP_TYPE_{HASH, PERCPU_HASH, LRU_HASH,
 * LRU_PERCPU_HASH}**, the memory size must be at least 4 bytes wide regardless
 * of key size.
 * @param out_batch output parameter that should be passed to next call as *in_batch*
 * @param keys pointer to an array of *count* keys
 * @param values pointer to an array large enough for *count* values
 * @param count input and output parameter; on input it's the number of elements
 * in the map to read and delete in batch; on output it represents the number of
 * elements that were successfully read and deleted
 * If a non-**EFAULT** error code is returned and if the output **count** value
 * is not equal to the input **count** value, up to **count** elements may
 * have been deleted.
 * if **EFAULT** is returned up to *count* elements may have been deleted without
 * being returned via the *keys* and *values* output parameters.
 * @param opts options for configuring the way the batch lookup and delete works
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_map_lookup_and_delete_batch(int fd, void *in_batch,
					void *out_batch, void *keys,
					void *values, __u32 *count,
					const struct bpf_map_batch_opts *opts);

/**
 * @brief **bpf_map_update_batch()** updates multiple elements in a map
 * by specifying keys and their corresponding values.
 *
 * The *keys* and *values* parameters must point to memory large enough
 * to hold *count* items based on the key and value size of the map.
 *
 * The *opts* parameter can be used to control how *bpf_map_update_batch()*
 * should handle keys that either do or do not already exist in the map.
 * In particular the *flags* parameter of *bpf_map_batch_opts* can be
 * one of the following:
 *
 * Note that *count* is an input and output parameter, where on output it
 * represents how many elements were successfully updated. Also note that if
 * **EFAULT** then *count* should not be trusted to be correct.
 *
 * **BPF_ANY**
 *    Create new elements or update existing.
 *
 * **BPF_NOEXIST**
 *    Create new elements only if they do not exist.
 *
 * **BPF_EXIST**
 *    Update existing elements.
 *
 * **BPF_F_LOCK**
 *    Update spin_lock-ed map elements. This must be
 *    specified if the map value contains a spinlock.
 *
 * @param fd BPF map file descriptor
 * @param keys pointer to an array of *count* keys
 * @param values pointer to an array of *count* values
 * @param count input and output parameter; on input it's the number of elements
 * in the map to update in batch; on output if a non-EFAULT error is returned,
 * **count** represents the number of updated elements if the output **count**
 * value is not equal to the input **count** value.
 * If EFAULT is returned, **count** should not be trusted to be correct.
 * @param opts options for configuring the way the batch update works
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_map_update_batch(int fd, const void *keys, const void *values,
				    __u32 *count,
				    const struct bpf_map_batch_opts *opts);

struct bpf_obj_pin_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	__u32 file_flags;
	int path_fd;

	size_t :0;
};
#define bpf_obj_pin_opts__last_field path_fd

LIBBPF_API int bpf_obj_pin(int fd, const char *pathname);
LIBBPF_API int bpf_obj_pin_opts(int fd, const char *pathname,
				const struct bpf_obj_pin_opts *opts);

struct bpf_obj_get_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	__u32 file_flags;
	int path_fd;

	size_t :0;
};
#define bpf_obj_get_opts__last_field path_fd

LIBBPF_API int bpf_obj_get(const char *pathname);
LIBBPF_API int bpf_obj_get_opts(const char *pathname,
				const struct bpf_obj_get_opts *opts);
/**
 * @brief Attach a loaded BPF program to a kernel hook or attach point.
 *
 * This is a low-level libbpf helper that wraps the bpf(BPF_PROG_ATTACH)
 * syscall command. It establishes a relationship between an already loaded
 * BPF program (@p prog_fd) and an attachable kernel entity represented by
 * @p attachable_fd (or, for certain attach types, a pseudo file descriptor).
 *
 * Common attach targets include:
 *   - cgroup FDs (for CGroup-related program types like BPF_PROG_TYPE_CGROUP_SKB,
 *     BPF_PROG_TYPE_CGROUP_SOCK_ADDR, etc.).
 *   - perf event FDs (for certain tracing or profiling program types).
 *   - socket or socket-like FDs (for SK_MSG, SK_SKB, SOCK_OPS, etc.).
 *   - BPF prog array FDs (when chaining programs).
 *
 * Prefer using newer link-based APIs (e.g., bpf_link_create()) when available,
 * as they provide a stable lifetime model and automatic cleanup when the link
 * FD is closed. This legacy API is still useful on older kernels or for
 * attach types not yet covered by link abstractions.
 *
 * @param prog_fd
 *        File descriptor of an already loaded BPF program obtained via
 *        bpf_prog_load() or similar. Must be a valid BPF program FD.
 *
 * @param attachable_fd
 *        File descriptor of the target attach point (e.g., cgroup FD, perf
 *        event FD, target program array FD). For some attach types this might
 *        be a special or pseudo FD whose semantics depend on @p type.
 *
 * @param type
 *        Enumerated BPF attach type (enum bpf_attach_type) specifying how the
 *        kernel should link the program to the target. The allowable set
 *        depends on both the program's BPF program type and the nature of
 *        @p attachable_fd. A mismatch typically yields -EINVAL.
 *
 * @param flags
 *        Additional attach flags controlling behavior. Most attach types
 *        require this to be 0. Some program families (e.g., cgroup) permit
 *        flag combinations (such as replacing existing attachments) subject
 *        to kernel version support. Unsupported flags result in -EINVAL.
 *
 * @return 0 on success; negative error code (< 0) on failure.
 *
 * Example (attaching a cgroup program):
 *   int prog_fd = bpf_prog_load(...);
 *   int cg_fd   = open("/sys/fs/cgroup/mygroup", O_RDONLY);
 *   if (bpf_prog_attach(prog_fd, cg_fd, BPF_CGROUP_INET_INGRESS, 0) < 0)
 *       perror("bpf_prog_attach");
 *
 */
LIBBPF_API int bpf_prog_attach(int prog_fd, int attachable_fd,
			       enum bpf_attach_type type, unsigned int flags);
/**
 * @brief Detach (unlink) BPF program(s) from an attach point.
 *
 * bpf_prog_detach() is a legacy convenience wrapper around the
 * BPF_PROG_DETACH command of the bpf(2) syscall. It removes the BPF
 * program currently attached to the kernel object represented by
 * attachable_fd for the specified attach @p type. This API only works
 * for attach types that historically supported a single attached
 * program (e.g., older cgroup program types before multi-attach was
 * introduced).
 *
 * For modern multi-program attach points (e.g., cgroup with multiple
 * programs of the same attach type), prefer bpf_prog_detach2(), which
 * allows specifying the exact program FD to be detached. Calling
 * bpf_prog_detach() on a multi-attach capable target typically fails
 * with -EINVAL or -EPERM, or detaches only the "base"/single program
 * depending on kernel version, so it should be avoided in new code.
 *
 * Lifetime semantics:
 *   - On success, the link between the program and the attach point is
 *     removed; any subsequent events at that hook will no longer invoke
 *     the detached program.
 *   - The program itself remains loaded; its FD is still valid and
 *     should be closed separately when no longer needed.
 *
 * Concurrency & races:
 *   - Detach operations compete with parallel attach/detach attempts.
 *     If another program is attached between inspection and detach,
 *     the result may differ from expectations; always check return
 *     codes.
 *
 * Typical usage (legacy cgroup case):
 *   int cg_fd = open("/sys/fs/cgroup/mygroup", O_RDONLY);
 *   if (cg_fd < 0) { perror("open cgroup"); return -1; }
 *   if (bpf_prog_detach(cg_fd, BPF_CGROUP_INET_INGRESS) < 0)
 *       perror("bpf_prog_detach");
 *
 * @param attachable_fd
 *        File descriptor of the attach target (e.g., cgroup FD, perf event FD,
 *        etc.). Must refer to an object supporting the given attach type.
 * @param type
 *        Enumerated BPF attach type (enum bpf_attach_type) corresponding to
 *        the hook from which to detach. Must match the original attach type
 *        used when the program was attached.
 *
 * @return 0 on success;
 *         < 0 negative libbpf-style error code (typically -errno) on failure:
 *           - -EBADF: attachable_fd is not a valid descriptor.
 *           - -EINVAL: Unsupported attach type for this target, no program
 *                     of that type attached, or legacy detach disallowed
 *                     (multi-attach scenario).
 *           - -ENOENT: No program currently attached for the given type.
 *           - -EPERM / -EACCES: Insufficient privileges (missing CAP_BPF /
 *                     CAP_SYS_ADMIN) or blocked by security policy.
 *           - -EOPNOTSUPP: Kernel lacks support for detaching this type.
 *           - Other negative codes: Propagated syscall failures (e.g., -ENOMEM).
 *
 */
LIBBPF_API int bpf_prog_detach(int attachable_fd, enum bpf_attach_type type);
/**
 * @brief Detach a specific BPF program from an attach point that may support multiple
 *        simultaneously attached programs.
 *
 * bpf_prog_detach2() is an enhanced variant of bpf_prog_detach(). While
 * bpf_prog_detach() detaches "the" program of a given @p type from @p attachable_fd
 * (and therefore only works reliably for legacy single-attach hooks), this function
 * targets and detaches the exact BPF program referenced by @p prog_fd from the
 * attach point referenced by @p attachable_fd.
 *
 * Typical use cases:
 *   - Cgroup multi-attach program types (e.g., CGROUP_SKB, CGROUP_SOCK, CGROUP_SYSCTL,
 *     CGROUP_INET_INGRESS/EGRESS, etc.), where multiple programs of the same attach
 *     type can coexist.
 *   - Hooks that allow program stacking/chaining and require precise removal of a
 *     single program without disturbing others.
 *
 * Preferred alternatives:
 *   - For new code that establishes long-lived attachments, consider using link-based
 *     APIs (bpf_link_create() + bpf_link_detach()/close(link_fd)), which provide
 *     clearer lifetime semantics. bpf_prog_detach2() is still necessary on older
 *     kernels or when working directly with legacy cgroup/perf event style attachments.
 *
 * Concurrency & races:
 *   - If another thread/process detaches the same program (or destroys either FD)
 *     concurrently, this call can fail with -ENOENT or -EBADF.
 *   - Immediately check the return value; success means the specified program
 *     was detached at the time of the call. The program remains loaded and its
 *     @p prog_fd is still valid; close() it separately when done.
 *
 * Privileges:
 *   - Typically requires CAP_BPF and/or CAP_SYS_ADMIN depending on kernel
 *     configuration, LSM policies, and lockdown mode.
 *
 * Error handling (negative return codes, libbpf style == -errno):
 *   - -EBADF: @p prog_fd or @p attachable_fd is not a valid file descriptor, or
 *             @p prog_fd does not reference a loaded BPF program.
 *   - -EINVAL: Unsupported @p type for the given attachable_fd, mismatch between
 *              program's type/expected attach type and @p type, or kernel doesn't
 *              support detach2 for this combination.
 *   - -ENOENT: The specified program is not currently attached at the given hook
 *              (it may have been detached already or never attached there).
 *   - -EACCES / -EPERM: Insufficient privileges or blocked by security policy.
 *   - -EOPNOTSUPP: Kernel lacks support for multi-program detachment for this
 *                  attach type.
 *   - Other negative codes: Propagated from underlying syscall (e.g., -ENOMEM
 *     for transient resource issues).
 *
 * Example (detaching a cgroup eBPF program):
 *   int prog_fd = bpf_prog_load(...);
 *   int cg_fd   = open("/sys/fs/cgroup/mygroup", O_RDONLY);
 *   // (Assume program was previously attached via bpf_prog_attach or link API)
 *   if (bpf_prog_detach2(prog_fd, cg_fd, BPF_CGROUP_INET_INGRESS) < 0) {
 *       perror("bpf_prog_detach2");
 *   }
 *
 * @param prog_fd        File descriptor of the loaded BPF program to be detached.
 * @param attachable_fd  File descriptor of the attach point (e.g., cgroup FD, perf
 *                       event FD, socket-like FD, prog array FD).
 * @param type           BPF attach type (enum bpf_attach_type) identifying the hook
 *                       from which to detach this program. Must match the original
 *                       attach type used when the program was attached.
 *
 * @return 0 on success; < 0 on failure (negative error code as described above).
 */
LIBBPF_API int bpf_prog_detach2(int prog_fd, int attachable_fd,
				enum bpf_attach_type type);

struct bpf_prog_attach_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;
	union {
		int replace_prog_fd;
		int replace_fd;
	};
	int relative_fd;
	__u32 relative_id;
	__u64 expected_revision;
	size_t :0;
};
#define bpf_prog_attach_opts__last_field expected_revision

struct bpf_prog_detach_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;
	int relative_fd;
	__u32 relative_id;
	__u64 expected_revision;
	size_t :0;
};
#define bpf_prog_detach_opts__last_field expected_revision

/**
 * @brief **bpf_prog_attach_opts()** attaches the BPF program corresponding to
 * *prog_fd* to a *target* which can represent a file descriptor or netdevice
 * ifindex.
 *
 * @param prog_fd BPF program file descriptor
 * @param target attach location file descriptor or ifindex
 * @param type attach type for the BPF program
 * @param opts options for configuring the attachment
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_prog_attach_opts(int prog_fd, int target,
				    enum bpf_attach_type type,
				    const struct bpf_prog_attach_opts *opts);

/**
 * @brief **bpf_prog_detach_opts()** detaches the BPF program corresponding to
 * *prog_fd* from a *target* which can represent a file descriptor or netdevice
 * ifindex.
 *
 * @param prog_fd BPF program file descriptor
 * @param target detach location file descriptor or ifindex
 * @param type detach type for the BPF program
 * @param opts options for configuring the detachment
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_prog_detach_opts(int prog_fd, int target,
				    enum bpf_attach_type type,
				    const struct bpf_prog_detach_opts *opts);

union bpf_iter_link_info; /* defined in up-to-date linux/bpf.h */
struct bpf_link_create_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;
	union bpf_iter_link_info *iter_info;
	__u32 iter_info_len;
	__u32 target_btf_id;
	union {
		struct {
			__u64 bpf_cookie;
		} perf_event;
		struct {
			__u32 flags;
			__u32 cnt;
			const char **syms;
			const unsigned long *addrs;
			const __u64 *cookies;
		} kprobe_multi;
		struct {
			__u32 flags;
			__u32 cnt;
			const char *path;
			const unsigned long *offsets;
			const unsigned long *ref_ctr_offsets;
			const __u64 *cookies;
			__u32 pid;
		} uprobe_multi;
		struct {
			__u64 cookie;
		} tracing;
		struct {
			__u32 pf;
			__u32 hooknum;
			__s32 priority;
			__u32 flags;
		} netfilter;
		struct {
			__u32 relative_fd;
			__u32 relative_id;
			__u64 expected_revision;
		} tcx;
		struct {
			__u32 relative_fd;
			__u32 relative_id;
			__u64 expected_revision;
		} netkit;
		struct {
			__u32 relative_fd;
			__u32 relative_id;
			__u64 expected_revision;
		} cgroup;
	};
	size_t :0;
};
#define bpf_link_create_opts__last_field uprobe_multi.pid
/**
 * @brief Create a persistent BPF link that attaches a loaded BPF program to a
 *        kernel hook or target object.
 *
 * bpf_link_create() wraps the BPF_LINK_CREATE syscall command and establishes
 * a first-class in-kernel "link" object representing the attachment of
 * @p prog_fd to @p target_fd (or to a kernel entity implied by @p attach_type).
 * The returned FD (>= 0) owns the lifetime of that attachment: closing it
 * cleanly detaches the program without requiring a separate detach syscall.
 *
 * Compared to legacy bpf_prog_attach()/bpf_raw_tracepoint_open(), link-based
 * attachment:
 *   - Provides explicit lifetime control (close(link_fd) == detach).
 *   - Enables richer introspection via bpf_link_get_info_by_fd().
 *   - Avoids ambiguous detach semantics and races inherent in "implicit detach
 *     on last program FD close" patterns.
 *
 * Typical usage:
 *   struct bpf_link_create_opts opts = {
 *       .sz = sizeof(opts),
 *       .flags = 0,
 *   };
 *   int link_fd = bpf_link_create(prog_fd, target_fd, BPF_TRACE_FENTRY, &opts);
 *   if (link_fd < 0) {
 *       // handle error
 *   }
 *   // ... use link_fd; close(link_fd) to detach later.
 *
 * @param prog_fd
 *        File descriptor of a previously loaded BPF program (from bpf_prog_load()
 *        or libbpf higher-level loader). Must be valid and compatible with
 *        @p attach_type.
 *
 * @param target_fd
 *        File descriptor of the attach target, when required by @p attach_type
 *        (e.g. a cgroup FD, perf event FD, network interface, or another BPF
 *        object). For some attach types (e.g. certain tracing variants) this may
 *        be -1 or ignored; passing an inappropriate FD yields -EINVAL.
 *
 * @param attach_type
 *        Enumeration value (enum bpf_attach_type) describing the hook/context
 *        at which the program should be executed (e.g. BPF_CGROUP_INET_INGRESS,
 *        BPF_TRACE_FENTRY, BPF_PERF_EVENT, BPF_NETFILTER, etc.). The program's
 *        bpf_prog_type and expected_attach_type must be compatible; otherwise
 *        verification will fail or the syscall returns -EINVAL/-EOPNOTSUPP.
 *
 * @param opts
 *        Optional pointer to a zero-initialized struct bpf_link_create_opts
 *        extended options; may be NULL for defaults. Must set opts->sz to
 *        sizeof(struct bpf_link_create_opts) when non-NULL.
 *
 *        Common fields:
 *          - .flags: Link creation flags (most callers set 0; future kernels
 *            may define bits for pinning behaviors, exclusivity, etc.).
 *          - .target_btf_id: For BTF-enabled tracing/fentry/fexit/kprobe multi
 *            scenarios, identifies a BTF entity (function/type) this link
 *            targets.
 *          - .iter_info / .iter_info_len: Provide iterator-specific metadata
 *            for BPF iter programs.
 *
 *        Attach-type specific nested unions:
 *          - .perf_event.bpf_cookie: User-defined cookie visible to program via
 *            bpf_get_attach_cookie() for PERF_EVENT and some tracing types.
 *          - .kprobe_multi: Batch (multi) kprobe attachment:
 *                * flags: KPROBE_MULTI_* flags controlling semantics.
 *                * cnt: Number of symbols/addresses.
 *                * syms / addrs: Symbol names or raw addresses (one of them
 *                  used depending on kernel capabilities).
 *                * cookies: Optional per-probe cookies.
 *          - .uprobe_multi: Batch uprobes:
 *                * path: Target binary path.
 *                * offsets / ref_ctr_offsets: Instruction/file offsets and
 *                  optional reference counter offsets.
 *                * pid: Target PID (0 for any or to let kernel decide).
 *                * cookies: Per-uprobe cookies.
 *          - .tracing.cookie: Generic tracing cookie for newer tracing types.
 *          - .netfilter: Attaching to Netfilter with:
 *                * pf (protocol family), hooknum, priority, flags.
 *          - .tcx / .netkit / .cgroup: Relative attachment variants allowing
 *            multi-attach ordering and revision consistency:
 *                * relative_fd / relative_id: Anchor or neighbor link/program.
 *                * expected_revision: Revision check to avoid races (fail with
 *                  -ESTALE if mismatch).
 *
 *        Zero any fields you do not explicitly use for forward compatibility.
 *
 * @return
 *   >= 0 : Link file descriptor (attachment active).
 *   < 0  : Negative error code (attachment failed; program not attached).
 *
 * Error Handling (negative libbpf-style codes; errno also set):
 *   - -EINVAL: Invalid prog_fd/target_fd/attach_type combination, malformed
 *              opts, bad sizes, unsupported flags, or missing required union
 *              fields.
 *   - -EOPNOTSUPP / -ENOTSUP: Attach type or creation mode unsupported by
 *              running kernel.
 *   - -EPERM / -EACCES: Insufficient privileges (CAP_BPF/CAP_SYS_ADMIN) or
 *              blocked by LSM/lockdown.
 *   - -ENOENT: Target object no longer exists (race) or unresolved symbol for
 *              kprobe/uprobes multi-attach.
 *   - -EBADF: Invalid file descriptor(s).
 *   - -ENOMEM: Kernel memory/resource exhaustion.
 *   - -ESTALE: Revision mismatch when using expected_revision (atomicity guard).
 *   - Other negative codes: Propagated from underlying bpf() syscall failures.
 *
 * Lifetime & Ownership:
 *   - Success returns a link FD. Caller must close() it to detach.
 *   - Closing the original program FD does NOT detach the link; only closing
 *     the link FD (or explicit bpf_link_detach()) does.
 *   - Link FDs can be pinned to bpffs via bpf_obj_pin() for persistence.
 *
 * Concurrency & Races:
 *   - Linking can fail if another concurrent operation changes target's state
 *     (revision checks can mitigate using expected_revision).
 *   - Multi-attach environments may reorder relative attachments if not using
 *     relative_* fields; always inspect returned link state if ordering matters.
 *
 * Introspection:
 *   - Use bpf_link_get_info_by_fd(link_fd, ...) to query link metadata
 *     (program ID, attach type, target, cookies, multi-probe details).
 *   - Enumerate existing links via bpf_link_get_next_id() then open with
 *     bpf_link_get_fd_by_id().
 *
 */
LIBBPF_API int bpf_link_create(int prog_fd, int target_fd,
			       enum bpf_attach_type attach_type,
			       const struct bpf_link_create_opts *opts);
/**
 * @brief Detach (tear down) an existing BPF link represented by a link file descriptor.
 *
 * bpf_link_detach() issues the BPF_LINK_DETACH command to the kernel, breaking
 * the association between a previously created BPF link (see bpf_link_create())
 * and its target (cgroup, tracing hook, perf event, netfilter hook, etc.). After
 * a successful call the program will no longer be invoked at that attach point.
 *
 * In most cases you do not need to call bpf_link_detach() explicitly; simply
 * closing the link FD (close(link_fd)) also detaches the link. This helper is
 * useful when you want to explicitly detach early while keeping the FD open for
 * introspection (e.g., querying link info after detachment) or when building
 * higher-level lifecycle abstractions.
 *
 * Semantics:
 *   - Success makes the in-kernel link inactive; subsequent events at the hook
 *     no longer trigger the program.
 *   - The link FD itself does NOT automatically close; you are still responsible
 *     for close(link_fd) to release user space resources.
 *   - Repeated calls after a successful detach will fail (idempotency: only the
 *     first detach succeeds).
 *
 * Typical usage:
 *   int link_fd = bpf_link_create(prog_fd, target_fd, attach_type, &opts);
 *   ...
 *   if (bpf_link_detach(link_fd) < 0)
 *       perror("bpf_link_detach");
 *   close(link_fd); // optional: now just releases the FD
 *
 * Concurrency & races:
 *   - Detaching can race with another thread closing or detaching the same link.
 *     In such cases you may observe -EBADF or -ENOENT.
 *   - Once detached, the program can be safely re-attached elsewhere if desired
 *     (requires a new link via bpf_link_create()).
 *
 * Privileges:
 *   - Usually requires CAP_BPF and/or CAP_SYS_ADMIN depending on kernel
 *     configuration, LSM, and lockdown mode. Lack of privileges yields -EPERM
 *     or -EACCES.
 *
 * Post-detach:
 *   - The program object remains loaded; its own FD is still valid and can be
 *     attached again.
 *   - Maps referenced by the program are unaffected.
 *
 * @param link_fd File descriptor of the active BPF link to detach; must have
 *                been obtained via bpf_link_create() or equivalent.
 *
 * @return 0 on success; < 0 on failure (negative error code as described above).
 *
 * Error handling (negative libbpf-style return codes, errno also set):
 *   - -EBADF: link_fd is not a valid open file descriptor.
 *   - -EINVAL: link_fd does not refer to a BPF link, or the kernel does not
 *              support BPF_LINK_DETACH for this link type.
 *   - -ENOENT: Link already detached or no longer exists (race with close()).
 *   - -EPERM / -EACCES: Insufficient privileges or denied by security policy.
 *   - -EOPNOTSUPP / -ENOTSUP: Kernel lacks support for link detachment of this
 *                             specific attach type.
 *   - -ENOMEM: Transient kernel resource exhaustion (rare in this path).
 *   - Other negative codes may be propagated from the underlying bpf() syscall.
 *
 */
LIBBPF_API int bpf_link_detach(int link_fd);

struct bpf_link_update_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;	   /* extra flags */
	__u32 old_prog_fd; /* expected old program FD */
	__u32 old_map_fd;  /* expected old map FD */
};
#define bpf_link_update_opts__last_field old_map_fd
/**
 * @brief Atomically replace (update) the BPF program or map referenced by an
 *        existing link with a new program.
 *
 * bpf_link_update() wraps the BPF_LINK_UPDATE command of the bpf(2) syscall.
 * It allows retargeting an already established BPF link (identified by
 * link_fd) to point at a different loaded BPF program (new_prog_fd) without
 * having to tear the link down (detach) and recreate it. This is typically
 * used for hot-swapping a program while preserving:
 *   - Link pinning (bpffs path remains valid).
 *   - Relative ordering in multi-attach contexts (TC/XDP/cgroup revisions).
 *   - Existing references held by other processes.
 *
 * Consistency & safety:
 *   - The update is performed atomically: events arriving at the hook will
 *     either see the old program before the call, or the new one after the
 *     call; no window exists with an unattached link.
 *   - Optional expectations can be enforced via @p opts to avoid races:
 *       * old_prog_fd: Fail with -ESTALE if the link does not currently
 *         reference that program.
 *       * old_map_fd:  (Kernel dependent) Can be used when links encapsulate
 *         a map association; if set and mismatched, update fails.
 *       * flags: Future extension bits (must be 0 on current kernels).
 *
 * Typical usage:
 *   struct bpf_link_update_opts u = {
 *       .sz = sizeof(u),
 *       .flags = 0,
 *       .old_prog_fd = old_fd, // set to 0 to skip validation
 *   };
 *   if (bpf_link_update(link_fd, new_prog_fd, &u) < 0)
 *       perror("bpf_link_update");
 *
 * Preconditions:
 *   - link_fd must refer to a valid, updatable BPF link. Not all link types
 *     support in-place program replacement; unsupported types return -EOPNOTSUPP.
 *   - new_prog_fd must be a loaded BPF program whose type and expected attach
 *     type are compatible with the link's attach context.
 *   - If @p opts is non-NULL, opts->sz MUST be set to sizeof(*opts).
 *
 * @param link_fd
 *        File descriptor of the existing BPF link to be updated.
 * @param new_prog_fd
 *        File descriptor of the newly loaded BPF program that should replace
 *        the currently attached program.
 * @param opts
 *        Optional pointer to bpf_link_update_opts controlling validation:
 *          - sz: Structure size for forward/backward compatibility.
 *          - flags: Reserved; must be 0 (unsupported bits yield -EINVAL).
 *          - old_prog_fd: Expected current program FD (0 to skip check).
 *          - old_map_fd:  Expected current map FD (0 to skip; kernel-specific).
 *        Pass NULL for default (no expectation checks).
 *
 * @return
 *   0        on success (link now points to new_prog_fd).
 *  <0        negative libbpf-style error code (typically -errno):
 *              - -EBADF: Invalid link_fd or new_prog_fd.
 *              - -EINVAL: Malformed opts (bad sz/flags) or incompatible program type.
 *              - -EOPNOTSUPP: Link type does not support updates.
 *              - -EPERM / -EACCES: Insufficient privileges (CAP_BPF/CAP_SYS_ADMIN) or blocked by LSM.
 *              - -ENOENT: Link no longer exists (race) or old_prog_fd refers to a non-existent program.
 *              - -ESTALE: Expectation mismatch (old_prog_fd / old_map_fd differs).
 *              - -ENOMEM: Kernel resource allocation failure.
 *              - Other -errno codes propagated from the bpf() syscall.
 *
 * Postconditions:
 *   - On success, the old program remains loaded; caller should close its FD
 *     if no longer needed.
 *   - Pinning status and link ID are preserved.
 *   - Maps referenced by the new program must be valid; no automatic rebinding
 *     occurs beyond program substitution.
 *
 * Caveats:
 *   - If verifier features differ (e.g., CO-RE relocations) ensure the new
 *     program was loaded with compatible expectations for the same hook.
 *   - Updating to a program of a strictly different attach semantics (e.g.,
 *     sleepable vs non-sleepable) is rejected if the link type disallows it.
 *
 * Thread safety:
 *   - Safe to call concurrently with other update attempts; only one succeeds.
 *   - Consumers of the link see either old or new program; intermediate states
 *     are not observable.
 */
LIBBPF_API int bpf_link_update(int link_fd, int new_prog_fd,
			       const struct bpf_link_update_opts *opts);

LIBBPF_API int bpf_iter_create(int link_fd);

struct bpf_prog_test_run_attr {
	int prog_fd;
	int repeat;
	const void *data_in;
	__u32 data_size_in;
	void *data_out;      /* optional */
	__u32 data_size_out; /* in: max length of data_out
			      * out: length of data_out */
	__u32 retval;        /* out: return code of the BPF program */
	__u32 duration;      /* out: average per repetition in ns */
	const void *ctx_in; /* optional */
	__u32 ctx_size_in;
	void *ctx_out;      /* optional */
	__u32 ctx_size_out; /* in: max length of ctx_out
			     * out: length of cxt_out */
};
/**
 * @brief Retrieve the next existing BPF program ID after a given starting ID.
 *
 * This helper wraps the kernel's BPF_PROG_GET_NEXT_ID command and enumerates
 * system-wide BPF program IDs in strictly ascending order. It is typically used
 * to iterate over all currently loaded BPF programs from user space.
 *
 * Enumeration pattern:
 *   1. Initialize start_id to 0 to obtain the first (lowest) existing program ID.
 *   2. On success, *next_id is set to the next valid ID greater than start_id.
 *   3. Use the returned *next_id as the new start_id for the subsequent call.
 *   4. Repeat until the function returns -ENOENT, indicating there is no program
 *      with ID greater than start_id (end of enumeration).
 *
 * Concurrency & races:
 *   - Program creation/destruction can race with enumeration. A program whose
 *     ID you just retrieved might disappear (be unloaded) before you convert
 *     it to a file descriptor (e.g., via bpf_prog_get_fd_by_id()). Always
 *     handle failures when opening by ID.
 *   - Enumeration does not provide a consistent snapshot; newly created
 *     programs may appear after you pass their would-be predecessor ID.
 *
 * Lifetime considerations:
 *   - IDs are monotonically increasing and not reused until wraparound (which
 *     is practically unreachable in normal operation).
 *   - Successfully retrieving an ID does not pin or otherwise prevent program
 *     unloading; obtain an FD immediately if you need to interact with it.
 *
 *
 * @param start_id
 *        Starting point for the search. The helper finds the first program ID
 *        strictly greater than start_id. Use 0 to begin enumeration.
 * @param next_id
 *        Pointer to a __u32 that receives the next program ID on success.
 *        Must not be NULL.
 *
 * @return
 *        0        on success (next_id populated);
 *        -ENOENT  if there is no program ID greater than start_id (end of iteration);
 *        -EINVAL  if next_id is NULL or invalid arguments were supplied;
 *        -EPERM / -EACCES if denied by security policy or lacking required privileges;
 *        Other negative libbpf-style errors (-errno) on transient or system failures.
 *
 */
LIBBPF_API int bpf_prog_get_next_id(__u32 start_id, __u32 *next_id);
/**
 * @brief Retrieve the next existing BPF map ID after a given starting ID.
 *
 * This helper enumerates system-wide BPF map IDs in ascending order. It wraps
 * the kernel's BPF_OBJ_GET_NEXT_ID command restricted to BPF maps.
 *
 * Enumeration pattern:
 *   1. Initialize start_id to 0 to obtain the first (lowest) existing map ID.
 *   2. On success, *next_id is set. Use that returned value as the new start_id
 *      for the subsequent call to advance the iteration.
 *   3. Repeat until the function returns -ENOENT, which indicates there is no
 *      map with ID greater than start_id (end of enumeration).
 *
 * Concurrency & races:
 *   - Map creation/deletion can race with enumeration; a retrieved ID might
 *     become invalid by the time you act on it (e.g., when calling
 *     bpf_map_get_fd_by_id()).
 *   - To safely interact with a map after enumeration, immediately convert the
 *     ID to a file descriptor with bpf_map_get_fd_by_id() and handle possible
 *     failures (e.g., -ENOENT if the map was removed).
 *
 * Typical usage example:
 *   __u32 id = 0, next;
 *   while (!bpf_map_get_next_id(id, &next)) {
 *       int map_fd = bpf_map_get_fd_by_id(next);
 *       if (map_fd >= 0) {
 *           // process map_fd
 *           close(map_fd);
 *       }
 *       id = next;
 *   }
 *   // Loop terminates when -ENOENT is returned (no more IDs).
 *
 * @param start_id
 *        Starting point for the search; the function looks for a map ID
 *        strictly greater than start_id. Use 0 to get the first existing ID.
 * @param next_id
 *        Pointer to a __u32 that receives the next map ID on success.
 *        Must not be NULL.
 *
 * @return
 *        0 on success (next_id populated);
 *        -ENOENT if there is no map ID greater than start_id (end of iteration);
 *        -EINVAL on invalid arguments (e.g., next_id == NULL);
 *        -EPERM / -EACCES if denied by security policy or lacking privileges;
 *        Other negative libbpf-style errors for transient or system failures.
 */
LIBBPF_API int bpf_map_get_next_id(__u32 start_id, __u32 *next_id);
LIBBPF_API int bpf_btf_get_next_id(__u32 start_id, __u32 *next_id);
/**
 * @brief Retrieve the next existing BPF link ID after a given starting ID.
 *
 * This helper wraps the kernel's BPF_LINK_GET_NEXT_ID command and enumerates
 * system-wide BPF link objects (each representing a persistent attachment of
 * a BPF program) in strictly ascending order of their kernel-assigned IDs.
 * It is typically used to iterate over all currently existing BPF links from
 * user space.
 *
 * Enumeration pattern:
 *   1. Initialize start_id to 0 to obtain the first (lowest) existing link ID.
 *   2. On success, *next_id is set to the first link ID strictly greater than start_id.
 *   3. Use the returned *next_id as the new start_id for the subsequent call.
 *   4. Repeat until the function returns -ENOENT, indicating there is no link
 *      with ID greater than start_id (end of enumeration).
 *
 * Concurrency & races:
 *   - Links can be created or detached concurrently with enumeration. A link ID
 *     you just retrieved might become invalid before you convert it to an FD
 *     (via bpf_link_get_fd_by_id()). Always handle failures when opening by ID.
 *   - Enumeration does not provide a consistent snapshot; links created after
 *     you pass their predecessor ID may appear in later iterations.
 *
 * Lifetime considerations:
 *   - Link IDs are monotonically increasing and not reused until wraparound
 *     (effectively unreachable in normal operation).
 *   - Successfully retrieving an ID does not pin or otherwise prevent link
 *     detachment; obtain an FD immediately if you need to interact with the link.
 *
 * Usage example:
 *   __u32 id = 0, next;
 *   while (bpf_link_get_next_id(id, &next) == 0) {
 *       int link_fd = bpf_link_get_fd_by_id(next);
 *       if (link_fd >= 0) {
 *           // Inspect link (e.g., bpf_link_get_info_by_fd(link_fd))
 *           close(link_fd);
 *       }
 *       id = next;
 *   }
 *   // Loop terminates when -ENOENT is returned.
 *
 * @param start_id
 *        Starting point for the search. The helper finds the first link ID
 *        strictly greater than start_id. Use 0 to begin enumeration.
 * @param next_id
 *        Pointer to a __u32 that receives the next link ID on success.
 *        Must not be NULL.
 *
 * @return
 *        0        on success (next_id populated);
 *        -ENOENT  if there is no link ID greater than start_id (end of iteration);
 *        -EINVAL  if next_id is NULL or invalid arguments were supplied;
 *        -EPERM / -EACCES if denied by security policy or lacking required privileges;
 *        Other negative libbpf-style errors (-errno) on transient or system failures.
 *
 * Error handling notes:
 *   - Treat -ENOENT as normal termination (not an error condition).
 *   - For other negative returns, errno will also be set to the underlying cause.
 *
 * After enumeration:
 *   - Convert retrieved IDs to FDs with bpf_link_get_fd_by_id() for introspection
 *     or detachment (via bpf_link_detach()).
 *   - Closing the FD does not destroy the link if other references remain (e.g.,
 *     pinned in bpffs); the link persists until explicitly detached or all
 *     references are released.
 */
LIBBPF_API int bpf_link_get_next_id(__u32 start_id, __u32 *next_id);

struct bpf_get_fd_by_id_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 open_flags; /* permissions requested for the operation on fd */
	__u32 token_fd;
	size_t :0;
};
#define bpf_get_fd_by_id_opts__last_field token_fd
/**
 * @brief Convert a kernel-assigned BPF program ID into a process-local file descriptor.
 *
 * bpf_prog_get_fd_by_id() wraps the BPF_PROG_GET_FD_BY_ID command of the
 * bpf(2) syscall. Given a stable, monotonically increasing program ID, it
 * returns a new file descriptor referring to that loaded BPF program, allowing
 * user space to inspect or further manage the program (e.g. query info, attach,
 * pin, update links).
 *
 * Typical enumeration + open pattern:
 *   __u32 id = 0, next;
 *   while (!bpf_prog_get_next_id(id, &next)) {
 *       int prog_fd = bpf_prog_get_fd_by_id(next);
 *       if (prog_fd >= 0) {
 *           // Use prog_fd (e.g. bpf_prog_get_info_by_fd(), attach, pin, etc.)
 *           close(prog_fd);
 *       }
 *       id = next;
 *   }
 *   // Loop ends when bpf_prog_get_next_id() returns -ENOENT.
 *
 *
 * @param id Kernel-assigned unique (non-zero) BPF program ID.
 *
 * @return
 *   >= 0 : File descriptor referring to the BPF program (caller must close()).
 *   < 0  : Negative error code (libbpf-style, see list above).
 */
LIBBPF_API int bpf_prog_get_fd_by_id(__u32 id);
/**
 * @brief Obtain a file descriptor for an existing BPF program by its kernel-assigned ID,
 *        with extended open options.
 *
 * This function is an extended variant of bpf_prog_get_fd_by_id(). It wraps the
 * BPF_PROG_GET_FD_BY_ID command of the bpf(2) syscall and converts a stable BPF
 * program ID into a process-local file descriptor, honoring optional attributes
 * supplied via @p opts.
 *
 * Typical usage pattern:
 *   1. Enumerate program IDs with bpf_prog_get_next_id().
 *   2. For each ID, call bpf_prog_get_fd_by_id_opts() to obtain a program FD.
 *   3. Use the FD (e.g., bpf_prog_get_info_by_fd(), attach, pin, link operations).
 *   4. close() the FD when no longer needed.
 *
 * Example:
 *   __u32 id = ...; // obtained via bpf_prog_get_next_id()
 *   struct bpf_get_fd_by_id_opts o = {
 *       .sz = sizeof(o),
 *       .open_flags = 0,
 *   };
 *   int prog_fd = bpf_prog_get_fd_by_id_opts(id, &o);
 *   if (prog_fd < 0) {
 *       // handle error
 *   } else {
 *       // use prog_fd
 *       close(prog_fd);
 *   }
 *
 * @param id
 *        Kernel-assigned unique (non-zero) BPF program ID, typically obtained via
 *        bpf_prog_get_next_id() or from a prior info query. Must be > 0.
 * @param opts
 *        Optional pointer to a zero-initialized struct bpf_get_fd_by_id_opts controlling
 *        open behavior. May be NULL for defaults. Fields:
 *          - sz: Must be set to sizeof(struct bpf_get_fd_by_id_opts) for forward/backward
 *                compatibility if @p opts is non-NULL.
 *          - open_flags: Requested open/access flags (kernel-specific; pass 0 unless a
 *                documented flag is needed). Unsupported flags yield -EINVAL.
 *          - token_fd: FD of a BPF token providing delegated permissions (set to -1 or 0
 *                if unused). If provided, enables restricted environments to open the
 *                program without elevated global capabilities.
 *
 * @return
 *   >= 0 : File descriptor referring to the BPF program (caller must close()).
 *   < 0  : Negative libbpf-style error code (typically -errno):
 *            - -ENOENT  : No program with @p id (unloaded or never existed).
 *            - -EPERM / -EACCES : Insufficient privileges / denied by policy.
 *            - -EINVAL  : Bad @p id, malformed @p opts, or unsupported flags.
 *            - -ENOMEM  : Transient kernel resource exhaustion.
 *            - Other negative codes: Propagated bpf() syscall errors.
 *
 */
LIBBPF_API int bpf_prog_get_fd_by_id_opts(__u32 id,
				const struct bpf_get_fd_by_id_opts *opts);
/**
 * @brief Get a file descriptor for an existing BPF map given its kernel-assigned ID.
 *
 * This helper wraps the BPF_MAP_GET_FD_BY_ID command of the bpf(2) syscall and
 * converts a stable (monotonically increasing) map ID into a process-local
 * file descriptor referring to that map object. The returned descriptor grants
 * the caller access consistent with system security policy (LSM, cgroup,
 * namespace, capabilities) at the time of the call.
 *
 * Typical enumeration pattern:
 *   __u32 id = 0, next;
 *   while (!bpf_map_get_next_id(id, &next)) {
 *       int map_fd = bpf_map_get_fd_by_id(next);
 *       if (map_fd >= 0) {
 *           // Use map_fd (query info, perform lookups, etc.)
 *           close(map_fd);
 *       }
 *       id = next;
 *   }
 *   // Loop ends when bpf_map_get_next_id() returns -ENOENT.
 *
 * Concurrency & races:
 *   - A map may be deleted between obtaining its ID (e.g., via
 *     bpf_map_get_next_id()) and calling this function; in that case the call
 *     fails with -ENOENT.
 *   - Immediately act on (and, when done, close) the returned file descriptor
 *     to minimize race windows.
 *
 * Lifetime & ownership:
 *   - On success the caller owns the returned file descriptor and must close()
 *     it when no longer needed.
 *   - The underlying map persists system-wide until all references (FDs and
 *     in-kernel attachments) are gone; closing this FD alone does not destroy
 *     the map.
 *
 * Privileges / access control:
 *   - May require CAP_BPF, CAP_SYS_ADMIN, or be denied by LSM / lockdown
 *     policies depending on system configuration.
 *   - A successful return does not guarantee unrestricted operations on the
 *     map; specific actions (updates, pinning, freezing) may still be gated.
 *
 * Error handling (negative libbpf-style return codes):
 *   - -ENOENT: No map with the specified ID (deleted or never existed).
 *   - -EACCES / -EPERM: Access denied by security policy or insufficient
 *     privilege.
 *   - -EINVAL: Invalid attributes passed to the kernel (rare; typically
 *     indicates an out-of-date kernel/libbpf mismatch).
 *   - -ENOMEM: Transient kernel memory/resource exhaustion.
 *   - Other negative values: Propagated -errno from the bpf() syscall.
 *
 * @param id
 *        Kernel-assigned unique ID of the target BPF map (obtained via
 *        bpf_map_get_next_id() or from info queries). Must be > 0.
 *
 * @return
 *        >= 0: File descriptor referring to the BPF map (caller must close()).
 *        < 0 : Negative error code (libbpf-style, e.g., -ENOENT, -EPERM).
 *
 */
LIBBPF_API int bpf_map_get_fd_by_id(__u32 id);
/**
 * @brief Obtain a file descriptor for an existing BPF map by its kernel-assigned ID,
 *        with extended options.
 *
 * This is an extended variant of bpf_map_get_fd_by_id() that allows the caller
 * to specify additional attributes (via @p opts) affecting how the kernel opens
 * the map. It wraps the BPF_MAP_GET_FD_BY_ID command of the bpf(2) syscall.
 *
 * Typical usage pattern:
 *   - Enumerate map IDs with bpf_map_get_next_id().
 *   - For each ID, call bpf_map_get_fd_by_id_opts() to convert the ID into a
 *     process-local file descriptor.
 *   - Use the returned FD to query info (bpf_map_get_info_by_fd()), perform
 *     lookups/updates, or pin the map.
 *   - close() the FD when finished.
 *
 * Concurrency & races:
 *   A map can be deleted between discovering its ID and calling this function.
 *   In that case the call fails with -ENOENT. Always check the return value and
 *   handle transient failures.
 *
 * Lifetime & ownership:
 *   On success the caller owns the returned FD. Closing it decrements a
 *   reference on the underlying map object but does not destroy the map if
 *   other references (FDs or in-kernel links/programs) remain.
 *
 * Security / privileges:
 *   Access can be denied by capabilities (CAP_BPF, CAP_SYS_ADMIN), LSM policies,
 *   or lockdown mode, yielding -EPERM/-EACCES. Supplying certain @p opts values
 *   (e.g., restrictive @c open_flags) does not bypass system security policy.
 *
 * @param id
 *        Kernel-assigned unique ID of the target map (must be > 0). Typically
 *        obtained via bpf_map_get_next_id() or from a prior info query.
 * @param opts
 *        Optional pointer to bpf_get_fd_by_id_opts controlling open behavior:
 *          - .open_flags: Requested access/open semantics (kernel-specific;
 *            pass 0 for default). Unsupported flags produce -EINVAL.
 *          - .token_fd: FD of a BPF token (if using delegated permissions).
 *        May be NULL for default behavior. Unrecognized or unsupported fields
 *        should be zero-initialized for forward/backward compatibility.
 *
 * @return
 *        >= 0 : File descriptor referring to the BPF map (caller must close()).
 *        < 0  : Negative libbpf-style error code (typically -errno):
 *                - -ENOENT  : No map with @p id (deleted or never existed).
 *                - -EPERM / -EACCES : Insufficient privileges / denied by policy.
 *                - -EINVAL  : Invalid @p id, malformed @p opts, or bad flags.
 *                - -ENOMEM  : Transient kernel resource exhaustion.
 *                - Other negative codes propagated from bpf() syscall.
 *
 */
LIBBPF_API int bpf_map_get_fd_by_id_opts(__u32 id,
				const struct bpf_get_fd_by_id_opts *opts);
LIBBPF_API int bpf_btf_get_fd_by_id(__u32 id);
LIBBPF_API int bpf_btf_get_fd_by_id_opts(__u32 id,
				const struct bpf_get_fd_by_id_opts *opts);
/**
 * @brief Obtain a file descriptor for an existing BPF link given its kernel-assigned ID.
 *
 * bpf_link_get_fd_by_id() wraps the BPF_LINK_GET_FD_BY_ID command of the bpf(2)
 * syscall. A BPF "link" is a persistent in-kernel object representing an
 * attachment of a BPF program to some hook (cgroup, tracing point, perf event,
 * netfilter hook, tc/xdp chain, etc.). Each link has a unique, monotonically
 * increasing ID. This helper converts such an ID into a process-local file
 * descriptor, allowing user space to inspect, pin, update, or detach the link.
 *
 * Typical enumeration + open pattern:
 *   __u32 id = 0, next;
 *   while (bpf_link_get_next_id(id, &next) == 0) {
 *       int link_fd = bpf_link_get_fd_by_id(next);
 *       if (link_fd >= 0) {
 *           // Use link_fd (e.g. bpf_link_get_info_by_fd(), bpf_link_detach(), pin)
 *           close(link_fd);
 *       }
 *       id = next;
 *   }
 *   // Loop terminates when bpf_link_get_next_id() returns -ENOENT.
 *
 * Concurrency & races:
 *   - A link may be detached (or otherwise invalidated) between discovering its ID
 *     and calling this function. In that case the call fails with -ENOENT.
 *   - Successfully retrieving a file descriptor does not prevent later detachment
 *     by other processes; always handle subsequent operation failures gracefully.
 *
 * Lifetime & ownership:
 *   - On success, the caller owns the returned FD and must close() it when done.
 *   - Closing the FD decreases the user space reference count; the underlying link
 *     persists while any references (FDs or pinned bpffs path) remain.
 *   - Detaching the link (via bpf_link_detach() or closing the last active FD)
 *     invalidates future operations on that FD.
 *
 * Privileges / access control:
 *   - May require CAP_BPF and/or CAP_SYS_ADMIN depending on kernel configuration,
 *     LSM policy, or lockdown mode. Lack of privileges yields -EPERM / -EACCES.
 *   - Security policies can deny access even if the link ID exists.
 *
 * Error handling (negative libbpf-style codes; errno is also set):
 *   - -ENOENT: No link with the specified ID (never existed or already detached).
 *   - -EPERM / -EACCES: Insufficient privilege or blocked by security policy.
 *   - -EINVAL: Invalid ID (e.g., 0) or kernel rejected the request (rare).
 *   - -ENOMEM: Transient kernel resource exhaustion while creating the FD.
 *   - -EBADF, -EFAULT, or other -errno values: Propagated from the underlying syscall.
 *
 * Usage notes:
 *   - Immediately call bpf_link_get_info_by_fd() after acquiring the FD if you need
 *     metadata (program ID, attach type, target, cookie, etc.).
 *   - To keep a link across process restarts, pin it to bpffs via bpf_obj_pin().
 *   - Prefer using bpf_link_get_fd_by_id_opts() if you need extended open semantics
 *     (e.g., token-based delegated permissions) on newer kernels.
 *
 * @param id
 *        Kernel-assigned unique ID of the target BPF link (must be > 0). Usually
 *        obtained via bpf_link_get_next_id() or from a prior info query.
 *
 * @return
 *        >= 0 : File descriptor referring to the BPF link (caller must close()).
 *        < 0  : Negative error code (libbpf-style, typically -errno) on failure.
 */
LIBBPF_API int bpf_link_get_fd_by_id(__u32 id);
/**
 * @brief Obtain a file descriptor for an existing BPF link by kernel-assigned link ID
 *        with extended open options.
 *
 * bpf_link_get_fd_by_id_opts() is an extended variant of bpf_link_get_fd_by_id().
 * It wraps the BPF_LINK_GET_FD_BY_ID command of the bpf(2) syscall and converts a
 * stable, monotonically increasing BPF link ID into a process-local file descriptor
 * while honoring optional attributes supplied via @p opts.
 *
 * A BPF "link" represents a persistent attachment of a BPF program to some kernel
 * hook (cgroup, tracing point, perf event, netfilter, tc/xdp chain, etc.). Links can
 * be enumerated system-wide by first calling bpf_link_get_next_id().
 *
 * Typical enumeration + open pattern:
 *   __u32 id = 0, next;
 *   while (bpf_link_get_next_id(id, &next) == 0) {
 *       struct bpf_get_fd_by_id_opts o = {
 *           .sz = sizeof(o),
 *           .open_flags = 0,
 *           .token_fd = 0,
 *       };
 *       int link_fd = bpf_link_get_fd_by_id_opts(next, &o);
 *       if (link_fd >= 0) {
 *           // inspect link (e.g. bpf_link_get_info_by_fd(link_fd))
 *           close(link_fd);
 *       }
 *       id = next;
 *   }
 *   // Loop ends when bpf_link_get_next_id() returns -ENOENT (no more links).
 *
 * Concurrency & races:
 *   - A link may detach between enumeration and opening; handle -ENOENT gracefully.
 *   - Successfully obtaining a FD does not prevent future detachment by other processes;
 *     subsequent operations (e.g., bpf_link_get_info_by_fd()) can still fail.
 *
 * Lifetime & ownership:
 *   - The returned FD holds a user-space reference; close() decrements it.
 *   - The underlying link persists while any references remain (FDs or bpffs pin).
 *   - Use bpf_obj_pin() to make the link persistent across process lifetimes.
 *
 * Security:
 *   - CAP_BPF and/or CAP_SYS_ADMIN may be required depending on kernel configuration.
 *   - Token-based access (token_fd) can allow operations in sandboxed environments.
 *
 * Follow-up introspection:
 *   - Call bpf_link_get_info_by_fd(link_fd, ...) to retrieve program ID, attach type,
 *     target info, cookies, and other metadata.
 *   - Detach via bpf_link_detach(link_fd) or simply close(link_fd).
 *
 * Recommended usage notes:
 *   - Always zero-initialize the opts struct before setting fields.
 *   - Treat -ENOENT after enumeration as normal termination, not an error condition.
 *   - Avoid relying on stable ordering beyond ascending ID sequence; links created
 *     during enumeration may appear after you pass their predecessor ID.
 *
 * @param id
 *   Kernel-assigned unique (non-zero) BPF link ID. Usually obtained from
 *   bpf_link_get_next_id() or from a prior info query. Must be > 0.
 *
 * @param opts
 *   Optional pointer to a zero-initialized struct bpf_get_fd_by_id_opts:
 *     - sz: MUST be set to sizeof(struct bpf_get_fd_by_id_opts) if @p opts
 *           is non-NULL (enables fwd/backward compatibility).
 *     - open_flags: Additional open/access flags (currently most callers set 0;
 *                   unsupported bits yield -EINVAL; semantics are kernel-specific).
 *     - token_fd: File descriptor of a BPF token granting delegated permissions
 *                 (set 0 or -1 if unused). Allows restricted environments to
 *                 open the link without elevated global capabilities.
 *   Pass NULL for defaults (equivalent to open_flags=0, no token).
 *
 * @return
 *   >= 0 : File descriptor referencing the BPF link (caller owns it; close() when done).
 *   < 0  : Negative libbpf-style error code (typically -errno):
 *            - -ENOENT  : Link with @p id does not exist (detached or never created).
 *            - -EPERM / -EACCES : Insufficient privilege or blocked by LSM/lockdown.
 *            - -EINVAL  : Invalid @p id (0), malformed @p opts (bad sz / flags), or
 *                         unsupported open_flags.
 *            - -ENOMEM  : Transient kernel memory/resource exhaustion.
 *            - Other negative codes: Propagated from underlying bpf() syscall.
 *
 */
LIBBPF_API int bpf_link_get_fd_by_id_opts(__u32 id,
				const struct bpf_get_fd_by_id_opts *opts);

LIBBPF_API int bpf_obj_get_info_by_fd(int bpf_fd, void *info, __u32 *info_len);

/**
 * @brief **bpf_prog_get_info_by_fd()** obtains information about the BPF
 * program corresponding to *prog_fd*.
 *
 * Populates up to *info_len* bytes of *info* and updates *info_len* with the
 * actual number of bytes written to *info*. Note that *info* should be
 * zero-initialized or initialized as expected by the requested *info*
 * type. Failing to (zero-)initialize *info* under certain circumstances can
 * result in this helper returning an error.
 *
 * @param prog_fd BPF program file descriptor
 * @param info pointer to **struct bpf_prog_info** that will be populated with
 * BPF program information
 * @param info_len pointer to the size of *info*; on success updated with the
 * number of bytes written to *info*
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_prog_get_info_by_fd(int prog_fd, struct bpf_prog_info *info, __u32 *info_len);

/**
 * @brief **bpf_map_get_info_by_fd()** obtains information about the BPF
 * map corresponding to *map_fd*.
 *
 * Populates up to *info_len* bytes of *info* and updates *info_len* with the
 * actual number of bytes written to *info*. Note that *info* should be
 * zero-initialized or initialized as expected by the requested *info*
 * type. Failing to (zero-)initialize *info* under certain circumstances can
 * result in this helper returning an error.
 *
 * @param map_fd BPF map file descriptor
 * @param info pointer to **struct bpf_map_info** that will be populated with
 * BPF map information
 * @param info_len pointer to the size of *info*; on success updated with the
 * number of bytes written to *info*
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_map_get_info_by_fd(int map_fd, struct bpf_map_info *info, __u32 *info_len);

/**
 * @brief **bpf_btf_get_info_by_fd()** obtains information about the
 * BTF object corresponding to *btf_fd*.
 *
 * Populates up to *info_len* bytes of *info* and updates *info_len* with the
 * actual number of bytes written to *info*. Note that *info* should be
 * zero-initialized or initialized as expected by the requested *info*
 * type. Failing to (zero-)initialize *info* under certain circumstances can
 * result in this helper returning an error.
 *
 * @param btf_fd BTF object file descriptor
 * @param info pointer to **struct bpf_btf_info** that will be populated with
 * BTF object information
 * @param info_len pointer to the size of *info*; on success updated with the
 * number of bytes written to *info*
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_btf_get_info_by_fd(int btf_fd, struct bpf_btf_info *info, __u32 *info_len);

/**
 * @brief **bpf_btf_get_info_by_fd()** obtains information about the BPF
 * link corresponding to *link_fd*.
 *
 * Populates up to *info_len* bytes of *info* and updates *info_len* with the
 * actual number of bytes written to *info*. Note that *info* should be
 * zero-initialized or initialized as expected by the requested *info*
 * type. Failing to (zero-)initialize *info* under certain circumstances can
 * result in this helper returning an error.
 *
 * @param link_fd BPF link file descriptor
 * @param info pointer to **struct bpf_link_info** that will be populated with
 * BPF link information
 * @param info_len pointer to the size of *info*; on success updated with the
 * number of bytes written to *info*
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_link_get_info_by_fd(int link_fd, struct bpf_link_info *info, __u32 *info_len);

struct bpf_prog_query_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 query_flags;
	__u32 attach_flags; /* output argument */
	__u32 *prog_ids;
	union {
		/* input+output argument */
		__u32 prog_cnt;
		__u32 count;
	};
	__u32 *prog_attach_flags;
	__u32 *link_ids;
	__u32 *link_attach_flags;
	__u64 revision;
	size_t :0;
};
#define bpf_prog_query_opts__last_field revision

/**
 * @brief **bpf_prog_query_opts()** queries the BPF programs and BPF links
 * which are attached to *target* which can represent a file descriptor or
 * netdevice ifindex.
 *
 * @param target query location file descriptor or ifindex
 * @param type attach type for the BPF program
 * @param opts options for configuring the query
 * @return 0, on success; negative error code, otherwise (errno is also set to
 * the error code)
 */
LIBBPF_API int bpf_prog_query_opts(int target, enum bpf_attach_type type,
				   struct bpf_prog_query_opts *opts);
/**
 * @brief Query BPF programs attached to a given target (legacy/simple interface).
 *
 * bpf_prog_query() wraps the BPF_PROG_QUERY command of the bpf(2) syscall and
 * retrieves information about one or more BPF programs attached to an attach
 * point represented by @p target_fd for a specific attach @p type. For richer
 * queries (including link IDs and per-program attach flags) use
 * bpf_prog_query_opts(), which supersedes this API.
 *
 * Typical usage pattern:
 *   1. Set *prog_cnt to the capacity (number of elements) of the @p prog_ids
 *      buffer.
 *   2. Call bpf_prog_query().
 *   3. On success:
 *        - If @p attach_flags is non-NULL, *attach_flags contains global
 *          attach flags for the hook (e.g., multi-attach, replace semantics).
 *        - *prog_cnt is updated with the number of program IDs actually written.
 *        - prog_ids[0 .. *prog_cnt-1] holds the program IDs (ascending order
 *          is typical but not guaranteed).
 *
 * Concurrency & races:
 *   - Programs may be attached or detached concurrently. The returned list is
 *     a snapshot at the moment of the query; programs might disappear before
 *     you turn their IDs into FDs (via bpf_prog_get_fd_by_id()).
 *   - Always check subsequent opens for -ENOENT.
 *
 * Buffer management:
 *   - On input, *prog_cnt must reflect the capacity of @p prog_ids.
 *   - On output, *prog_cnt is set to the number of IDs returned (0 is valid).
 *   - If @p prog_ids is NULL, the call can still populate @p attach_flags (if
 *     provided) and report whether any programs are attached by returning
 *     *prog_cnt == 0 (legacy kernels may return -EINVAL in this case).
 *
 * @param target_fd
 *        File descriptor of the attach point (e.g., a cgroup FD, perf event FD,
 *        or other object that supports @p type).
 * @param type
 *        BPF attach type (enum bpf_attach_type) describing which hook to query
 *        (must match how programs were attached).
 * @param query_flags
 *        Optional refinement flags (must be 0 unless specific flags are
 *        supported by the running kernel; unsupported flags yield -EINVAL).
 * @param attach_flags
 *        Optional output pointer to receive aggregate attach flags describing
 *        the state/behavior of the attach point. Pass NULL to ignore.
 * @param prog_ids
 *        Caller-provided array to receive program IDs; may be NULL only if
 *        *prog_cnt == 0 or when only @p attach_flags is of interest (kernel
 *        version dependent).
 * @param prog_cnt
 *        In: capacity (number of elements) in @p prog_ids.
 *        Out: number of program IDs actually written. Must not be NULL.
 *
 * @return
 *        0 on success (results populated as described);
 *        < 0 a negative libbpf-style error code (typically -errno):
 *          - -EINVAL: Bad arguments (NULL prog_cnt, unsupported query/type,
 *                     invalid flags, insufficient buffer) or target_fd not a
 *                     valid attach point for @p type.
 *          - -ENOENT: No program(s) of this @p type attached (older kernels may
 *                     use 0 + *prog_cnt == 0 instead).
 *          - -EPERM / -EACCES: Insufficient privileges (CAP_BPF/CAP_SYS_ADMIN)
 *                              or blocked by security policy.
 *          - -EBADF: target_fd is not a valid file descriptor.
 *          - -EFAULT: User memory (prog_ids / attach_flags / prog_cnt) is
 *                    unreadable or unwritable.
 *          - -ENOMEM: Transient kernel memory/resource exhaustion.
 *          - Other negative codes: Propagated syscall failures.
 *
 * Post-processing:
 *   - Convert each returned program ID to an FD with bpf_prog_get_fd_by_id()
 *     for further introspection or management.
 *
 * Recommended alternative:
 *   - Prefer bpf_prog_query_opts() for new code; it supports link enumeration,
 *     per-program attach flags, revision checks, and future extensions.
 */
LIBBPF_API int bpf_prog_query(int target_fd, enum bpf_attach_type type,
			      __u32 query_flags, __u32 *attach_flags,
			      __u32 *prog_ids, __u32 *prog_cnt);

struct bpf_raw_tp_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	const char *tp_name;
	__u64 cookie;
	size_t :0;
};
#define bpf_raw_tp_opts__last_field cookie

LIBBPF_API int bpf_raw_tracepoint_open_opts(int prog_fd, struct bpf_raw_tp_opts *opts);
LIBBPF_API int bpf_raw_tracepoint_open(const char *name, int prog_fd);
LIBBPF_API int bpf_task_fd_query(int pid, int fd, __u32 flags, char *buf,
				 __u32 *buf_len, __u32 *prog_id, __u32 *fd_type,
				 __u64 *probe_offset, __u64 *probe_addr);

#ifdef __cplusplus
/* forward-declaring enums in C++ isn't compatible with pure C enums, so
 * instead define bpf_enable_stats() as accepting int as an input
 */
LIBBPF_API int bpf_enable_stats(int type);
#else
enum bpf_stats_type; /* defined in up-to-date linux/bpf.h */
LIBBPF_API int bpf_enable_stats(enum bpf_stats_type type);
#endif

struct bpf_prog_bind_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;
};
#define bpf_prog_bind_opts__last_field flags
/**
 * @brief Bind (associate) an already loaded BPF program with an existing BPF map.
 *
 * bpf_prog_bind_map() is a low-level libbpf helper wrapping the
 * BPF_PROG_BIND_MAP kernel command. It establishes (or updates) an
 * association between a loaded BPF program (prog_fd) and a map (map_fd)
 * that the program is expected to reference at run time. This allows
 * certain late binding or rebinding scenarios (e.g., providing a map that
 * could not be created or located at initial program load time, or
 * updating a program's backing/global data map after load). The exact
 * semantics and which map types are supported are kernel-version dependent;
 * unsupported combinations will fail with an error.
 *
 * Typical use cases:
 *   - Late injection of a data/config map into a program that was loaded
 *     without direct access to that map.
 *   - Rebinding a program to a replacement map (e.g., upgraded layout),
 *     where the kernel permits such updates without reloading the program.
 *   - Establishing program <-> map relationship needed for specific kernel
 *     features (e.g., global data sections, special helper expectations,
 *     or JIT/runtime adjustments).
 *
 *
 * Recommended pattern:
 *   struct bpf_prog_bind_opts opts = {
 *       .sz = sizeof(opts),
 *       .flags = 0,
 *   };
 *   if (bpf_prog_bind_map(prog_fd, map_fd, &opts) < 0) {
 *       perror("bpf_prog_bind_map");
 *       // handle failure
 *   }
 *
 * @param prog_fd File descriptor of an already loaded BPF program.
 * @param map_fd  File descriptor of the BPF map to bind to the program.
 * @param opts    Optional pointer to bpf_prog_bind_opts (may be NULL for defaults).
 *                Must have opts->sz set when non-NULL. opts->flags must be 0 unless
 *                documented otherwise.
 *
 * @return 0 on success; negative error code (< 0) on failure.
 *
 * Error handling (negative libbpf-style return codes; errno set):
 *   - -EBADF: prog_fd or map_fd is not a valid descriptor.
 *   - -EINVAL: Invalid arguments, unsupported map/program type combination,
 *              malformed opts, bad flags, or kernel does not support binding.
 *   - -EPERM / -EACCES: Insufficient privileges (CAP_BPF/CAP_SYS_ADMIN) or
 *                       blocked by LSM / lockdown policy.
 *   - -ENOENT: The referenced program or map no longer exists (race).
 *   - -ENOMEM: Transient kernel resource exhaustion.
 *   - Other negative codes: Propagated from underlying bpf() syscall.
 */
LIBBPF_API int bpf_prog_bind_map(int prog_fd, int map_fd,
				 const struct bpf_prog_bind_opts *opts);

struct bpf_test_run_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	const void *data_in; /* optional */
	void *data_out;      /* optional */
	__u32 data_size_in;
	__u32 data_size_out; /* in: max length of data_out
			      * out: length of data_out
			      */
	const void *ctx_in; /* optional */
	void *ctx_out;      /* optional */
	__u32 ctx_size_in;
	__u32 ctx_size_out; /* in: max length of ctx_out
			     * out: length of cxt_out
			     */
	__u32 retval;        /* out: return code of the BPF program */
	int repeat;
	__u32 duration;      /* out: average per repetition in ns */
	__u32 flags;
	__u32 cpu;
	__u32 batch_size;
};
#define bpf_test_run_opts__last_field batch_size
/**
 * @brief Execute a loaded BPF program in a controlled (synthetic) context and
 *        collect its return code, output data, and timing statistics.
 *
 * bpf_prog_test_run_opts() is a high-level wrapper around the kernel's
 * BPF_PROG_TEST_RUN command. It allows user space to "test run" a program
 * without attaching it to a live hook, supplying optional input data
 * (data_in), optional execution context (ctx_in), and retrieving any
 * transformed output data (data_out), context (ctx_out), program return
 * value, and average per-run duration in nanoseconds.
 *
 * Typical purposes:
 *   - Unit-style testing of program logic (e.g., XDP, TC, SK_MSG) before
 *     deployment.
 *   - Verifying correctness of packet mangling or map access patterns.
 *   - Microbenchmarking via repeat execution (repeat > 1).
 *   - Exercising program behavior under different synthetic contexts.
 *
 * Usage pattern (minimal):
 *   struct bpf_test_run_opts opts = {};
 *   opts.sz           = sizeof(opts);
 *   opts.data_in      = pkt;
 *   opts.data_size_in = pkt_len;
 *   opts.data_out     = out_buf;
 *   opts.data_size_out = out_buf_cap;
 *   opts.repeat       = 1000;
 *   if (bpf_prog_test_run_opts(prog_fd, &opts) == 0) {
 *       printf("prog retval=%u avg_ns=%u out_len=%u\n",
 *              opts.retval, opts.duration, opts.data_size_out);
 *   } else {
 *       perror("bpf_prog_test_run_opts");
 *   }
 *
 * Structure initialization notes:
 *   - opts.sz MUST be set to sizeof(struct bpf_test_run_opts) for
 *     forward/backward compatibility.
 *   - All unused fields should be zeroed (memset(&opts, 0, sizeof(opts))).
 *   - Omit (leave NULL/zero) optional buffers you don't need (e.g., ctx_out).
 *
 * Input fields (set by caller):
 *   - data_in / data_size_in:
 *       Optional raw input buffer fed to the program. For packet-oriented
 *       types (e.g., XDP) this simulates an ingress frame. If data_in is
 *       NULL, data_size_in must be 0.
 *   - data_out / data_size_out:
 *       Optional buffer receiving (potentially) modified data. On success
 *       data_size_out is updated with actual bytes written. If data_out
 *       is NULL, set data_size_out = 0 (no output capture).
 *   - ctx_in / ctx_size_in:
 *       Optional synthetic context (e.g., struct xdp_md) passed to the
 *       program. Only meaningful for program types expecting a context
 *       argument. If unused, leave NULL/0.
 *   - ctx_out / ctx_size_out:
 *       Optional buffer to retrieve (possibly altered) context. Provide
 *       initial max size in ctx_size_out. Set ctx_out NULL if not needed.
 *   - repeat:
 *       Number of times to run the program back-to-back. If > 1 the kernel
 *       accumulates total time and returns averaged per-run duration in
 *       opts.duration. Use for stable timing. If 0 or 1, program executes
 *       exactly once.
 *   - flags:
 *       Feature/control flags (must be 0 unless a supported kernel extension
 *       is documented; unknown bits yield errors).
 *   - cpu:
 *       Optional CPU index hint for program types allowing per-CPU execution
 *       binding during test runs (e.g., for percpu data semantics). If 0 and
 *       not meaningful for the program type, ignored. If unsupported, call
 *       may fail with -EINVAL.
 *   - batch_size:
 *       For program types that support batched test execution (kernel-
 *       dependent). Each test iteration may process up to batch_size items
 *       internally. Leave 0 unless specifically targeting a batched mode.
 *
 * Output fields (populated on success):
 *   - data_size_out:
 *       Actual number of bytes written to data_out (may be <= original
 *       capacity; unchanged if no output).
 *   - ctx_size_out:
 *       Actual number of bytes written to ctx_out (if provided).
 *   - retval:
 *       Program's return value (semantics depend on program type; e.g.,
 *       XDP_* action code for XDP programs).
 *   - duration:
 *       Average per run execution time in nanoseconds (only meaningful
 *       when repeat > 0; may be 0 if kernel cannot measure).
 *
 * Concurrency & isolation:
 *   - Test runs occur in isolation from live attachment points; no real
 *     packets, sockets, or kernel events are consumed.
 *   - Map interactions are real: the program can read/update maps during
 *     test runs. Ensure maps are in a suitable state.
 *
 * Data & context lifetime:
 *   - Kernel copies input data/context before executing; caller can reuse
 *     buffers after return.
 *   - Output buffers must be writable and sufficiently sized; truncation
 *     occurs if too small (reported via size_out fields).
 *
 * Performance measurement guidance:
 *   - Use a sufficiently large repeat count (hundreds/thousands) to
 *     smooth timing variance.
 *   - Avoid measuring with data_out/ctx_out unless necessary; copying
 *     increases overhead.
 *
 *
 * @param prog_fd
 *        File descriptor of the loaded BPF program to test.
 * @param opts
 *        Pointer to an initialized bpf_test_run_opts describing input,
 *        output, and execution parameters. Must not be NULL.
 *
 * @return 0 on success; negative error code (< 0) on failure (errno is also set).
 *
 * Error handling (return value < 0, errno set):
 *   - -EINVAL: Malformed opts (missing sz), unsupported flags, invalid
 *              buffer sizes, or program type mismatch.
 *   - -EPERM / -EACCES: Insufficient privileges (CAP_BPF / CAP_SYS_ADMIN)
 *                       or restricted by LSM/lockdown.
 *   - -EFAULT: Bad user pointers (data_in/out or ctx_in/out).
 *   - -ENOMEM: Kernel resource allocation failure.
 *   - -ENOTSUP / -EOPNOTSUPP: Test run unsupported for this program type
 *                             or kernel version.
 *   - Other negative codes: Propagated from underlying bpf() syscall.
 *
 */
LIBBPF_API int bpf_prog_test_run_opts(int prog_fd,
				      struct bpf_test_run_opts *opts);

struct bpf_token_create_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;
	size_t :0;
};
#define bpf_token_create_opts__last_field flags

/**
 * @brief **bpf_token_create()** creates a new instance of BPF token derived
 * from specified BPF FS mount point.
 *
 * BPF token created with this API can be passed to bpf() syscall for
 * commands like BPF_PROG_LOAD, BPF_MAP_CREATE, etc.
 *
 * @param bpffs_fd FD for BPF FS instance from which to derive a BPF token
 * instance.
 * @param opts optional BPF token creation options, can be NULL
 *
 * @return BPF token FD > 0, on success; negative error code, otherwise (errno
 * is also set to the error code)
 */
LIBBPF_API int bpf_token_create(int bpffs_fd,
				struct bpf_token_create_opts *opts);

struct bpf_prog_stream_read_opts {
	size_t sz;
	size_t :0;
};
#define bpf_prog_stream_read_opts__last_field sz
/**
 * @brief **bpf_prog_stream_read** reads data from the BPF stream of a given BPF
 * program.
 *
 * @param prog_fd FD for the BPF program whose BPF stream is to be read.
 * @param stream_id ID of the BPF stream to be read.
 * @param buf Buffer to read data into from the BPF stream.
 * @param buf_len Maximum number of bytes to read from the BPF stream.
 * @param opts optional options, can be NULL
 *
 * @return The number of bytes read, on success; negative error code, otherwise
 * (errno is also set to the error code)
 */
LIBBPF_API int bpf_prog_stream_read(int prog_fd, __u32 stream_id, void *buf, __u32 buf_len,
				    struct bpf_prog_stream_read_opts *opts);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __LIBBPF_BPF_H */
