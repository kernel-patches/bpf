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

LIBBPF_API int bpf_prog_attach(int prog_fd, int attachable_fd,
			       enum bpf_attach_type type, unsigned int flags);
LIBBPF_API int bpf_prog_detach(int attachable_fd, enum bpf_attach_type type);
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

LIBBPF_API int bpf_link_create(int prog_fd, int target_fd,
			       enum bpf_attach_type attach_type,
			       const struct bpf_link_create_opts *opts);

LIBBPF_API int bpf_link_detach(int link_fd);

struct bpf_link_update_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;	   /* extra flags */
	__u32 old_prog_fd; /* expected old program FD */
	__u32 old_map_fd;  /* expected old map FD */
};
#define bpf_link_update_opts__last_field old_map_fd

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
LIBBPF_API int bpf_link_get_next_id(__u32 start_id, __u32 *next_id);

struct bpf_get_fd_by_id_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 open_flags; /* permissions requested for the operation on fd */
	__u32 token_fd;
	size_t :0;
};
#define bpf_get_fd_by_id_opts__last_field token_fd

LIBBPF_API int bpf_prog_get_fd_by_id(__u32 id);
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
LIBBPF_API int bpf_link_get_fd_by_id(__u32 id);
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
