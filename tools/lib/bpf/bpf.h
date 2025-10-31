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
/**
 * @brief Adjust process RLIMIT_MEMLOCK to facilitate loading BPF objects.
 *
 * libbpf_set_memlock_rlim() raises (or lowers) the calling process's
 * RLIMIT_MEMLOCK soft and hard limits to at least the number of bytes
 * specified by memlock_bytes. BPF map and program creation can require
 * locking kernel/user pages; if RLIMIT_MEMLOCK is too low the kernel
 * will fail operations with EPERM/ENOMEM. This helper provides a
 * convenient way to pre-allocate sufficient memlock quota.
 *
 * Semantics:
 *   - If current (soft or hard) RLIMIT_MEMLOCK is already >= memlock_bytes,
 *     the limit is left unchanged and the function succeeds.
 *   - Otherwise, the function attempts to set both soft and hard limits
 *     to memlock_bytes using setrlimit(RLIMIT_MEMLOCK, ...).
 *   - On systems enforcing privilege constraints, increasing the hard
 *     limit may require CAP_SYS_RESOURCE; lack of privilege yields failure.
 *
 * Typical usage (before loading large maps/programs):
 *   size_t needed = 128ul * 1024 * 1024; // 128 MB
 *   if (libbpf_set_memlock_rlim(needed) < 0) {
 *       // handle error (e.g., fall back to smaller maps or abort)
 *   }
 *
 * Choosing a value:
 *   - Sum anticipated sizes of maps (key_size + value_size) * max_entries
 *     plus overhead. Add headroom for verifier, BTF, and future growth.
 *   - Large per-CPU maps multiply value storage by number of CPUs.
 *   - Overestimating is usually harmless (within administrative policy).
 *
 * Concurrency & scope:
 *   - Affects only the calling process's RLIMIT_MEMLOCK.
 *   - Child processes inherit the adjusted limits after fork/exec.
 *
 * Security / privileges:
 *   - Increasing the hard limit above the current maximum may require
 *     CAP_SYS_RESOURCE or appropriate PAM/ulimit configuration.
 *   - Without sufficient privilege, the call fails with -errno (often -EPERM).
 *
 * @param memlock_bytes Desired minimum RLIMIT_MEMLOCK (in bytes). If zero,
 *                      the function is a no-op (always succeeds).
 *
 * @return 0 on success;
 *         < 0 negative error code (libbpf style == -errno) on failure:
 *           - -EINVAL: Invalid argument (e.g., internal conversion issues).
 *           - -EPERM / -EACCES: Insufficient privilege to raise hard limit.
 *           - -ENOMEM: Rare failure allocating internal structures.
 *           - Other -errno codes propagated from setrlimit().
 *
 * Failure handling:
 *   - A failure means RLIMIT_MEMLOCK is unchanged; subsequent BPF map/program
 *     loads may still succeed if existing limit is adequate.
 *   - Check current limits manually (getrlimit) if precise sizing is critical.
 *
 */
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
/**
 * @brief Load a BTF (BPF Type Format) blob into the kernel and obtain a BTF object FD.
 *
 * bpf_btf_load() wraps the BPF_BTF_LOAD command of the bpf(2) syscall. It validates
 * and registers the BTF metadata described by @p btf_data so that subsequently loaded
 * BPF programs and maps can reference rich type information (for CO-RE relocations,
 * pretty printing, introspection, etc.).
 *
 * Typical usage:
 *   // Prepare optional verifier/logging buffer (only if you want kernel diagnostics)
 *   char log_buf[1 << 20] = {};
 *   struct bpf_btf_load_opts opts = {
 *       .sz        = sizeof(opts),
 *       .log_buf   = log_buf,
 *       .log_size  = sizeof(log_buf),
 *       .log_level = 1,              // >0 to request kernel parsing/validation log
 *   };
 *   int btf_fd = bpf_btf_load(btf_blob_ptr, btf_blob_size, &opts);
 *   if (btf_fd < 0) {
 *       // Inspect errno; if opts.log_buf was provided, it may contain details.
 *   } else {
 *       // Use btf_fd (e.g. pass to bpf_prog_load() via prog_btf_fd, or query info).
 *   }
 *
 * Input expectations:
 *   - @p btf_data must point to a complete, well-formed BTF buffer starting with
 *     struct btf_header followed by the type section and string section.
 *   - @p btf_size is the total size in bytes of that buffer.
 *   - Endianness must match the running kernel; cross-endian BTF is rejected.
 *   - Types must obey kernel constraints (e.g., no unsupported kinds, valid string
 *     offsets, canonical integer encodings, no dangling references).
 *
 * Logging (opts->log_*):
 *   - If @p opts is non-NULL and opts->log_level > 0, the kernel may emit a textual
 *     parse/validation log into opts->log_buf (up to opts->log_size - 1 bytes, with
 *     trailing '\0').
 *   - On supported kernels, opts->log_true_size is updated to reflect the full (untruncated)
 *     length of the internal log; if larger than log_size, the log was truncated.
 *   - If the kernel does not support returning true size, log_true_size remains equal
 *     to the original log_size value or zero.
 *
 * Privileges & security:
 *   - CAP_BPF and/or CAP_SYS_ADMIN may be required depending on kernel configuration,
 *     LSM policy, and lockdown mode. Lack of privilege yields -EPERM / -EACCES.
 *   - In delegated environments, opts->token_fd (if available and supported) can grant
 *     scoped permission to load BTF without full global capabilities.
 *
 * Memory and lifetime:
 *   - On success a file descriptor (>= 0) referencing the in-kernel BTF object is returned.
 *     Close it with close() when no longer needed.
 *   - The kernel makes its own copy of the supplied BTF blob; the caller can free or reuse
 *     @p btf_data immediately after the call returns.
 *   - BTF objects can be queried via bpf_btf_get_info_by_fd() and referenced by programs
 *     (prog_btf_fd) or maps for type information.
 *
 * Concurrency & races:
 *   - Loading is independent; multiple BTF objects may coexist.
 *   - There is no automatic deduplication across separate loads (except any internal
 *     kernel optimizations); user space manages uniqueness/pinning if desired.
 *
 * Validation tips:
 *   - Use bpftool btf dump to sanity-check a blob before loading.
 *   - Keep string table minimal; excessive strings inflate memory and may hit limits.
 *   - Ensure all referenced type IDs exist and form a closed, acyclic graph (except
 *     for permitted self-references in struct/union definitions).
 *
 * After loading:
 *   - Pass the returned FD as prog_btf_fd when loading programs that rely on CO-RE
 *     relocations or need BTF type validation.
 *   - Optionally pin the BTF object with bpf_obj_pin() for persistence across process
 *     lifetimes.
 *   - Query metadata (e.g., number of types, string section size) with bpf_btf_get_info_by_fd().
 *
 * @param btf_data Pointer to the raw in-memory BTF blob.
 * @param btf_size Size (in bytes) of the BTF blob pointed to by @p btf_data.
 * @param opts     Optional pointer to a bpf_btf_load_opts struct. May be NULL.
 *                 Must set opts->sz = sizeof(*opts) when non-NULL. Fields:
 *                   - log_buf / log_size / log_level: Request and store kernel
 *                     validation log (see Logging).
 *                   - log_true_size: Updated by kernel on success (if supported).
 *                   - btf_flags: Reserved for future extensions (must be 0 unless documented).
 *                   - token_fd: Delegated permission token (0 or -1 if unused).
 *
 * @return
 *   >= 0 : File descriptor referencing the loaded BTF object.
 *   < 0  : Negative error code (see Error handling).
 *
 * Error handling (negative return codes == -errno style):
 *   - -EINVAL: Malformed BTF (bad header, section sizes, invalid type graph, bad string
 *              offsets, unsupported features), opts->sz mismatch, bad flags.
 *   - -EFAULT: @p btf_data or opts->log_buf points to unreadable/writable memory.
 *   - -ENOMEM: Kernel failed to allocate memory for internal BTF representation.
 *   - -EPERM / -EACCES: Insufficient privileges or blocked by security policy.
 *   - -E2BIG: Exceeds kernel size/complexity limits (e.g., too many types or strings).
 *   - -ENOTSUP / -EOPNOTSUPP: Kernel lacks support for a feature used in the blob (rare).
 *   - Other negative codes may be propagated from the underlying syscall.
 *
 */
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
/**
 * @brief Pin a BPF object (map, program, BTF, link, etc.) to a persistent
 *        location in the BPF filesystem (bpffs).
 *
 * bpf_obj_pin() wraps the BPF_OBJ_PIN command and creates a bpffs file
 * at @p pathname that permanently references the in-kernel BPF object
 * associated with @p fd. Once pinned, the object survives process exit
 * and can later be reopened (referenced) by other processes via
 * bpf_obj_get()/bpf_obj_get_opts().
 *
 * Typical use cases:
 *  - Share maps or programs across processes (e.g., loader + consumer).
 *  - Preserve objects across service restarts.
 *  - Provide stable, discoverable paths for orchestration tooling.
 *
 * Requirements:
 *  - The BPF filesystem (usually mounted at /sys/fs/bpf) must be mounted.
 *  - All parent directories in @p pathname must already exist; this helper
 *    does NOT create intermediate directories.
 *  - @p fd must reference a pin-able BPF object (map, program, link, BTF, etc.).
 *
 * Idempotency & overwriting:
 *  - If a file already exists at @p pathname, the call fails (typically
 *    with -EEXIST). Remove or rename the existing entry before pinning
 *    a new object to that path.
 *
 * Lifetime semantics:
 *  - Pinning increments the in-kernel object's refcount. The object will
 *    remain alive until the pinned bpffs entry is removed and all other
 *    references (FDs, links, attachments) are closed.
 *  - Closing @p fd after pinning does NOT unpin the object.
 *
 * Security & permissions:
 *  - Usually requires write permission to the bpffs mount and appropriate
 *    capabilities (CAP_BPF and/or CAP_SYS_ADMIN depending on kernel/LSM).
 *  - Path components must not traverse outside bpffs (no ".." escapes).
 *
 * Example:
 *   int map_fd = bpf_map_create(...);
 *   if (map_fd < 0)
 *       return -1;
 *   if (bpf_obj_pin(map_fd, "/sys/fs/bpf/myapp/session_map") < 0) {
 *       perror("bpf_obj_pin");
 *       // handle error (e.g., create parent dir, adjust permissions)
 *   }
 *
 * Re-opening later:
 *   int pinned_fd = bpf_obj_get("/sys/fs/bpf/myapp/session_map");
 *   if (pinned_fd >= 0) {
 *       // use map
 *       close(pinned_fd);
 *   }
 *
 * @param fd        File descriptor of the loaded BPF object to pin.
 * @param pathname  Absolute or relative path inside bpffs where the object
 *                  should be pinned (e.g. "/sys/fs/bpf/my_map"). Must not be NULL.
 *
 * @return 0 on success; < 0 negative error code (libbpf style == -errno) on failure.
 *
 * Common errors (negative libbpf-style return codes == -errno):
 *  - -EBADF: @p fd is not a valid BPF object FD.
 *  - -EINVAL: @p fd refers to an object type that cannot be pinned, or
 *             pathname is invalid.
 *  - -EEXIST: A file already exists at @p pathname.
 *  - -ENOENT: One or more parent directories in the path do not exist.
 *  - -ENOTDIR: A path component expected to be a directory is not.
 *  - -EPERM / -EACCES: Insufficient privileges or denied by security policy.
 *  - -ENOMEM: Kernel failed to allocate internal metadata.
 *  - Other -errno codes may be propagated from the underlying syscall.
 *
 */
LIBBPF_API int bpf_obj_pin(int fd, const char *pathname);

/**
 * @brief Pin a BPF object (map, program, BTF, link, etc.) to bpffs with
 *        extended options controlling filesystem open semantics.
 *
 * This is an extended variant of bpf_obj_pin() that allows specifying
 * additional pinning attributes through @p opts. On success a new file
 * (bpffs inode) at @p pathname references the in-kernel BPF object
 * associated with @p fd, incrementing its refcount and making it
 * persist beyond the lifetime of the creating process.
 *
 * Differences vs bpf_obj_pin():
 *   - Supports optional struct bpf_obj_pin_opts for forward/backward
 *     compatibility without breaking older kernels.
 *   - Allows passing file creation flags (opts->file_flags) and a
 *     directory file descriptor (opts->path_fd) for path resolution
 *     using the underlying kernel support (e.g. enabling O_EXCL-style
 *     semantics if/when supported).
 *
 * Typical usage:
 *   struct bpf_obj_pin_opts popts = {
 *       .sz        = sizeof(popts),
 *       .file_flags = 0,          // reserved / must be 0 unless documented
 *       .path_fd    = -1,         // optional dir FD; -1 means unused
 *   };
 *   if (bpf_obj_pin_opts(obj_fd, "/sys/fs/bpf/myapp/session_map", &popts) < 0) {
 *       perror("bpf_obj_pin_opts");
 *       // handle error (inspect errno or negative return value)
 *   }
 *
 * Notes on @p pathname:
 *   - Must reside within a mounted BPF filesystem (bpffs), typically
 *     /sys/fs/bpf.
 *   - All parent directories must already exist; intermediate directories
 *     are not created automatically.
 *   - Existing path results in -EEXIST (no overwrite).
 *   - Avoid relative paths that could escape bpffs (no ".." traversal).
 *
 * opts initialization:
 *   - If @p opts is non-NULL, opts->sz MUST be set to sizeof(*opts).
 *   - Unused/unknown fields should be zeroed for forward compatibility.
 *   - opts->file_flags: Currently reserved; pass 0 unless a kernel
 *     extension explicitly documents valid bits (non-zero may yield
 *     -EINVAL on older kernels).
 *   - opts->path_fd: Optional directory file descriptor that serves as
 *     the base for relative @p pathname resolution (similar to *at()
 *     syscalls). Set to -1 or 0 to ignore and use normal absolute path
 *     semantics. If used, ensure it refers to bpffs.
 *
 * Concurrency:
 *   - Pinning is atomic with respect to path name; two simultaneous
 *     attempts to pin to the same pathname will result in one success
 *     and one -EEXIST failure.
 *   - After success, closing @p fd does NOT unpin; removal of the pinned
 *     bpffs file (unlink) plus closing all other references is required
 *     to allow object destruction.
 *
 * Security / Privileges:
 *   - May require CAP_BPF and/or CAP_SYS_ADMIN depending on kernel
 *     configuration, LSM policy, and lockdown mode.
 *   - Filesystem permissions on bpffs apply; lack of write/execute on
 *     parent directories yields -EACCES / -EPERM.
 *
 * After pinning:
 *   - Object can be reopened via bpf_obj_get()/bpf_obj_get_opts() using
 *     the same pathname.
 *   - Can be safely shared across processes and persists across
 *     restarts until explicitly unpinned (unlink).
 *
 * Best practices:
 *   - Zero-initialize opts: struct bpf_obj_pin_opts popts = {};
 *   - Always set popts.sz = sizeof(popts) when passing opts.
 *   - Validate that bpffs is mounted (e.g., stat("/sys/fs/bpf")) before
 *     attempting to pin.
 *   - Use distinct subdirectories (e.g., /sys/fs/bpf/<app>/...) to avoid
 *     naming collisions and facilitate cleanup.
 *
 * @param fd        File descriptor of the loaded BPF object to pin.
 * @param pathname  Absolute (recommended) or relative path inside bpffs
 *                  identifying where to create the pin entry. Must not be NULL.
 * @param opts      Optional pointer to a struct bpf_obj_pin_opts providing
 *                  extended pin options; may be NULL for defaults.
 *
 * @return 0 on success; < 0 negative error code (libbpf style == -errno) on failure.
 *
 * Error handling (negative libbpf-style return codes == -errno):
 *   - -EBADF: Invalid @p fd, or @p path_fd (if used) not a valid directory FD.
 *   - -EINVAL: opts->sz mismatch, unsupported file_flags, invalid pathname,
 *              or object type cannot be pinned.
 *   - -EEXIST: A file already exists at @p pathname.
 *   - -ENOENT: Parent directory component missing (or @p path_fd base invalid).
 *   - -ENOTDIR: A path component expected to be a directory is not.
 *   - -EPERM / -EACCES: Insufficient privileges or blocked by security policy.
 *   - -ENOMEM: Kernel failed to allocate internal metadata.
 *   - Other -errno codes may be propagated from the underlying bpf() syscall.
 *
 */
LIBBPF_API int bpf_obj_pin_opts(int fd, const char *pathname,
				const struct bpf_obj_pin_opts *opts);

struct bpf_obj_get_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */

	__u32 file_flags;
	int path_fd;

	size_t :0;
};
#define bpf_obj_get_opts__last_field path_fd
/**
 * @brief Open (re-reference) a pinned BPF object by its bpffs pathname.
 *
 * bpf_obj_get() wraps the BPF_OBJ_GET command of the bpf(2) syscall. It
 * converts a persistent BPF filesystem (bpffs) entry (previously created
 * with bpf_obj_pin()/bpf_obj_pin_opts()) back into a live file descriptor
 * that the caller owns and can use for further operations (e.g. map
 * lookups/updates, program introspection, link detachment, BTF queries).
 *
 * Supported object kinds (depending on kernel version):
 *   - Maps
 *   - Programs
 *   - BTF objects
 *   - Links
 *   - (Future kinds may also become accessible through the same API)
 *
 * Typical usage:
 *   int fd = bpf_obj_get("/sys/fs/bpf/myapp/session_map");
 *   if (fd < 0) {
 *       perror("bpf_obj_get");
 *       // handle error
 *   } else {
 *       // use fd
 *       close(fd);
 *   }
 *
 * Path requirements:
 *   - @p pathname must reside inside a mounted BPF filesystem (usually
 *     /sys/fs/bpf).
 *   - Intermediate directories must already exist.
 *   - The path must reference a previously pinned object; regular files
 *     or non-BPF entries yield errors.
 *
 * Lifetime semantics:
 *   - Success returns a new file descriptor referencing the existing
 *     in-kernel object; the object's lifetime is extended while this FD
 *     (and any others) remain open or while the bpffs entry stays pinned.
 *   - Closing the returned FD does not remove or unpin the object.
 *   - To permanently remove the object, unlink the bpffs path and close
 *     all remaining descriptors.
 *
 * Concurrency & races:
 *   - If the pinned entry is removed (unlink) between name resolution and
 *     the syscall, the call may fail with -ENOENT.
 *   - Multiple opens of the same pinned path are safe and return distinct
 *     FDs.
 *
 * Privileges & security:
 *   - May require CAP_BPF and/or CAP_SYS_ADMIN depending on kernel config,
 *     LSM policies, and lockdown mode.
 *   - Filesystem permission checks apply (read/search on parent dirs).
 *
 * Thread safety:
 *   - The function itself is thread-safe; distinct threads can open the
 *     same pinned path concurrently.
 *
 * Performance considerations:
 *   - Operation cost is dominated by path lookup and a single bpf()
 *     syscall; typically negligible compared to subsequent map/program
 *     usage.
 *
 * @param pathname Absolute (recommended) or relative bpffs path of the
 *                 pinned BPF object; must not be NULL.
 *
 * @return >= 0 : File descriptor referencing the object (caller must close()).
 *         < 0  : Negative error code (libbpf style, see list above).
 *
 *
 * Error handling (negative libbpf-style return codes == -errno):
 *   - -ENOENT: Path does not exist or was unpinned.
 *   - -ENOTDIR: A path component expected to be a directory is not.
 *   - -EACCES / -EPERM: Insufficient privileges or denied by security policy.
 *   - -EINVAL: Path does not refer to a valid pinned BPF object (type mismatch,
 *              corrupted entry, or unsupported kernel feature).
 *   - -ENOMEM: Kernel could not allocate internal resources.
 *   - -EBADF: Rare: internal descriptor handling failed.
 *   - Other negative codes propagated from the underlying syscall.
 *
 */
LIBBPF_API int bpf_obj_get(const char *pathname);

/**
 * @brief Open (re-reference) a pinned BPF object with extended options.
 *
 * bpf_obj_get_opts() is an extended variant of bpf_obj_get() that wraps the
 * BPF_OBJ_GET command of the bpf(2) syscall. It converts a bpffs pathname
 * (previously created via bpf_obj_pin()/bpf_obj_pin_opts()) into a process-local
 * file descriptor referencing the underlying in-kernel BPF object (map, program,
 * BTF object, link, etc.), honoring additional lookup/open semantics supplied
 * through @p opts.
 *
 * Extended capabilities vs bpf_obj_get():
 *   - Structured forward/backward compatibility via @p opts->sz.
 *   - Optional directory FD-relative path resolution (opts->path_fd),
 *     similar to *at() family syscalls (openat, fstatat, etc.).
 *   - Future room for file/open semantic modifiers (opts->file_flags).
 *
 * Requirements:
 *   - The target pathname must reside inside a mounted BPF filesystem
 *     (usually /sys/fs/bpf). Relative paths are resolved either against
 *     the current working directory (if opts->path_fd is -1 or 0) or
 *     against the directory represented by opts->path_fd.
 *   - All parent directories must already exist; intermediate components
 *     are not created automatically.
 *   - The bpffs entry at @p pathname must refer to a pinned BPF object.
 *
 * Lifetime semantics:
 *   - Success returns a new file descriptor owning a user space reference
 *     to the object. Closing this FD does NOT unpin or destroy the object
 *     if other references (FDs or pinned entries) remain.
 *   - To remove the persistent reference, unlink(2) the bpffs path and
 *     close all remaining FDs.
 *
 * Concurrency & races:
 *   - If the pinned entry is unlinked concurrently, the call may fail
 *     with -ENOENT.
 *   - Multiple successful opens of the same path yield distinct FDs.
 *
 * Security / privileges:
 *   - May require CAP_BPF and/or CAP_SYS_ADMIN depending on kernel config,
 *     LSM policies, or lockdown mode.
 *   - Filesystem permission checks apply to path traversal and directory
 *     components (execute/search permissions).
 *
 * @param pathname
 *        Absolute or relative bpffs path of the pinned BPF object. Must
 *        not be NULL. If relative and opts->path_fd is a valid directory
 *        FD, resolution is performed relative to that directory; otherwise
 *        relative to the process's current working directory.
 * @param opts
 *        Optional pointer to a zero-initialized bpf_obj_get_opts structure.
 *        May be NULL for default behavior. Fields:
 *          - sz: MUST be set to sizeof(struct bpf_obj_get_opts) when @p opts
 *                is non-NULL; mismatch causes -EINVAL.
 *          - file_flags: Reserved for future extensions; MUST be 0 on
 *                current kernels or the call may fail with -EINVAL.
 *          - path_fd: Directory file descriptor for *at()-style relative
 *                path resolution. Set to -1 (or 0) to ignore and use normal
 *                pathname semantics. Must reference a directory within bpffs
 *                if used with relative @p pathname.
 *
 * @return
 *   >= 0 : File descriptor referencing the pinned BPF object (caller must close()).
 *   < 0  : Negative libbpf-style error code (== -errno):
 *            - -ENOENT: Path does not exist or was unpinned.
 *            - -ENOTDIR: A path component is not a directory; or opts->path_fd
 *                       is not a directory when required.
 *            - -EACCES / -EPERM: Insufficient privileges or denied by security policy.
 *            - -EBADF: Invalid opts->path_fd (not an open FD) or internal FD misuse.
 *            - -EINVAL: opts->sz mismatch, unsupported file_flags, invalid pathname,
 *                       or path does not refer to a valid pinned BPF object.
 *            - -ENOMEM: Kernel failed to allocate internal metadata/resources.
 *            - Other -errno codes may be propagated from the underlying syscall.
 *
 * Usage example:
 *   struct bpf_obj_get_opts gopts = {
 *       .sz = sizeof(gopts),
 *       .file_flags = 0,
 *       .path_fd = -1,
 *   };
 *   int fd = bpf_obj_get_opts("/sys/fs/bpf/myapp/session_map", &gopts);
 *   if (fd < 0) {
 *       // handle error (inspect -fd or errno)
 *   } else {
 *       // use fd
 *       close(fd);
 *   }
 *
 * Best practices:
 *   - Always zero-initialize the opts struct before setting recognized fields.
 *   - Verify bpffs is mounted (e.g., stat("/sys/fs/bpf")) before calling.
 *   - Avoid passing non-zero file_flags until documented by newer kernels.
 *   - Treat -ENOENT as a normal condition if the object might have been
 *     cleaned up asynchronously.
 *
 * Thread safety:
 *   - Safe to call concurrently from multiple threads; each successful call
 *     yields its own FD.
 *
 * Forward compatibility:
 *   - Unrecognized future fields must remain zeroed to avoid -EINVAL.
 *   - Ensure opts->sz matches the libbpf version's struct size to enable
 *     kernel-side bounds checking and extension handling.
 */
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
/**
 * @brief Create a user space iterator stream FD from an existing BPF iterator link.
 *
 * bpf_iter_create() wraps the kernel's BPF_ITER_CREATE command. Given a BPF
 * link FD (@p link_fd) that represents an attached BPF iterator program
 * (i.e., a program of type BPF_PROG_TYPE_TRACING with an iterator attach
 * type such as BPF_TRACE_ITER), this function returns a new file descriptor
 * from which user space can sequentially read the iterator's textual or
 * binary output.
 *
 * Reading the returned FD:
 *   - Use read(), pread(), or a buffered I/O layer to consume iterator data.
 *   - Each read() returns zero (EOF) when the iterator has completed producing
 *     all elements; close the FD afterward.
 *   - Short reads are normal; loop until EOF or error.
 *
 * Lifetime & ownership:
 *   - Success returns a new FD; caller owns it and must close() when finished.
 *   - Closing the iterator FD does NOT destroy the underlying link or program.
 *   - You can create multiple iterator FDs from the same link concurrently;
 *     each is an independent traversal.
 *
 * Typical usage:
 *   int link_fd = bpf_link_create(prog_fd, -1, BPF_TRACE_ITER, &opts);
 *   if (link_fd < 0) { // handle error  }
 *   int iter_fd = bpf_iter_create(link_fd);
 *   if (iter_fd < 0) { // handle error  }
 *   char buf[4096];
 *   for (;;) {
 *       ssize_t n = read(iter_fd, buf, sizeof(buf));
 *       if (n < 0) {
 *           if (errno == EINTR) continue;
 *           perror("read iter");
 *           break;
 *       }
 *       if (n == 0) // end of iteration
 *           break;
 *       fwrite(buf, 1, n, stdout);
 *   }
 *   close(iter_fd);
 *
 * Concurrency & races:
 *   - Safe to call concurrently from multiple threads; each iterator FD
 *     represents its own walk.
 *   - Underlying kernel objects (maps, tasks, etc.) may change while iterating;
 *     output is a best-effort snapshot, not a stable, atomic view.
 *
 * Performance considerations:
 *   - Large buffers (e.g., 16-64 KiB) reduce syscall overhead for high-volume
 *     iterators.
 *   - For blocking behavior, select()/poll()/epoll() can be used; EOF is
 *     indicated by read() returning 0.
 *
 * Security & privileges:
 *   - May require CAP_BPF and/or CAP_SYS_ADMIN depending on kernel configuration,
 *     lockdown mode, and LSM policy governing the iterator target.
 *
 * @param link_fd File descriptor of a BPF link representing an attached iterator program.
 *
 * @return >= 0: Iterator stream file descriptor to read from.
 *         < 0 : Negative error code (libbpf style, == -errno) on failure.
 *
 *
 * Error handling (negative libbpf-style return value == -errno):
 *   - -EBADF: @p link_fd is not a valid open FD.
 *   - -EINVAL: @p link_fd does not refer to an iterator-capable BPF link, or
 *              unsupported combination for the running kernel.
 *   - -EPERM / -EACCES: Insufficient privileges / blocked by security policy.
 *   - -EOPNOTSUPP / -ENOTSUP: Kernel lacks iterator creation support for this link.
 *   - -ENOMEM: Kernel could not allocate internal data structures.
 *   - Other -errno codes may be propagated from the underlying bpf() syscall.
 *
 * Robustness tips:
 *   - Verify the program was attached with the correct iterator attach type.
 *   - Treat a 0-length read as normal completion, not an error.
 *   - Always handle transient read() failures (EINTR, EAGAIN if non-blocking).
 *
 */
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

/**
 * @brief Retrieve the next existing BTF object ID after a given starting ID.
 *
 * This helper wraps the kernel's BPF_BTF_GET_NEXT_ID command and enumerates
 * in-kernel BTF (BPF Type Format) objects in strictly ascending order of
 * their kernel-assigned IDs. It is typically used to iterate all currently
 * loaded BTF objects (e.g., vmlinux BTF, module BTFs, user-loaded BTF blobs).
 *
 * Enumeration pattern:
 *   1. Initialize start_id to 0 to obtain the first (lowest) existing BTF ID.
 *   2. On success, *next_id is set to the first BTF ID strictly greater than start_id.
 *   3. Use the returned *next_id as the new start_id in a subsequent call.
 *   4. Repeat until the function returns -ENOENT, which signals there is no
 *      BTF object with ID greater than start_id (end of iteration).
 *
 * Concurrency & races:
 *   - BTF objects can be loaded or unloaded concurrently with enumeration.
 *     An ID retrieved in one call may become invalid (object unloaded) before
 *     you convert it to a file descriptor with bpf_btf_get_fd_by_id().
 *   - Enumeration does not provide a stable snapshot. Newly loaded BTFs may
 *     appear after you've passed their predecessor ID.
 *
 * Lifetime & validity:
 *   - IDs are monotonically increasing and effectively never wrap in normal
 *     operation.
 *   - Successfully retrieving an ID does NOT pin the corresponding BTF object.
 *     Obtain a file descriptor immediately if you need to interact with it.
 *
 * Typical usage:
 *   __u32 id = 0, next;
 *   while (bpf_btf_get_next_id(id, &next) == 0) {
 *       int btf_fd = bpf_btf_get_fd_by_id(next);
 *       if (btf_fd >= 0) {
 *           // Inspect/query BTF (e.g. bpf_btf_get_info_by_fd()).
 *           close(btf_fd);
 *       }
 *       id = next;
 *   }
 *   // Loop ends when bpf_btf_get_next_id() returns -ENOENT.
 *
 * @param start_id
 *        Starting point for the search. The helper finds the first BTF ID
 *        strictly greater than start_id. Use 0 to begin enumeration.
 * @param next_id
 *        Pointer to a __u32 that receives the next BTF ID on success.
 *        Must not be NULL.
 *
 * @return
 *   0        on success (next_id populated);
 *   -ENOENT  if there is no BTF ID greater than start_id (normal end of iteration);
 *   -EINVAL  if next_id is NULL or arguments are otherwise invalid;
 *   -EPERM / -EACCES if denied by security policy or lacking required privileges;
 *   Other negative libbpf-style codes (-errno) on transient or system failures.
 *
 * Error handling notes:
 *   - Treat -ENOENT as normal termination, not an exceptional error.
 *   - For other failures, errno is set to the underlying cause.
 *
 * Follow-up:
 *   - Convert retrieved IDs to FDs with bpf_btf_get_fd_by_id() to inspect
 *     metadata or pin the BTF object.
 */
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
/**
 * @brief Obtain a file descriptor for an existing in-kernel BTF (BPF Type Format)
 *        object given its kernel-assigned ID.
 *
 * bpf_btf_get_fd_by_id() wraps the BPF_BTF_GET_FD_BY_ID command of the bpf(2)
 * syscall. Each loaded BTF object (vmlinux BTF, kernel module BTF, or user-supplied
 * BTF blob loaded via BPF_BTF_LOAD) has a monotonically increasing, unique ID.
 * This helper converts that stable ID into a process-local file descriptor
 * suitable for introspection (e.g., via bpf_btf_get_info_by_fd()), pinning
 * (bpf_obj_pin()), or reuse when loading BPF programs/maps that reference types
 * from this BTF.
 *
 * Typical enumeration + open pattern:
 *   __u32 id = 0, next;
 *   while (bpf_btf_get_next_id(id, &next) == 0) {
 *       int btf_fd = bpf_btf_get_fd_by_id(next);
 *       if (btf_fd >= 0) {
 *           // inspect with bpf_btf_get_info_by_fd(btf_fd, ...)
 *           close(btf_fd);
 *       }
 *       id = next;
 *   }
 *   // Loop ends when bpf_btf_get_next_id() returns -ENOENT.
 *
 * Concurrency & races:
 *   - A BTF object may be unloaded (e.g., module removal) between discovering
 *     its ID and calling this function; in that case the call fails with -ENOENT.
 *   - Successfully obtaining a file descriptor does not prevent later unloading
 *     by other processes; subsequent operations on the FD can still fail.
 *
 * Lifetime & ownership:
 *   - On success the caller owns the returned descriptor and must close() it
 *     when no longer needed.
 *   - Closing the FD does not destroy the underlying BTF object if other
 *     references (FDs or pinned bpffs paths) remain.
 *
 * Privileges / security:
 *   - May require CAP_BPF and/or CAP_SYS_ADMIN depending on kernel configuration,
 *     LSM policies, or lockdown mode. Lack of privilege yields -EPERM / -EACCES.
 *   - Access can also be restricted by namespace or cgroup-based security policies.
 *
 * Use cases:
 *   - Retrieve BTF metadata (type counts, string section size, specific type
 *     definitions) via bpf_btf_get_info_by_fd().
 *   - Pass the FD as prog_btf_fd when loading eBPF programs needing CO-RE or
 *     type validation.
 *   - Pin the BTF object for persistence across process lifetimes.
 *
 * @param id
 *        Kernel-assigned unique (non-zero) BTF object ID. Typically obtained via
 *        bpf_btf_get_next_id() or from a prior info query. Must be > 0.
 *
 * @return
 *   >= 0 : File descriptor referencing the BTF object (caller must close()).
 *   < 0  : Negative libbpf-style error code (== -errno):
 *            - -ENOENT : No BTF object with this ID (unloaded or never existed).
 *            - -EPERM / -EACCES : Insufficient privileges / blocked by policy.
 *            - -EINVAL : Invalid ID (e.g., 0) or kernel rejected the request.
 *            - -ENOMEM : Kernel memory/resource exhaustion.
 *            - Other negative values: Propagated syscall failures.
 *
 * Error handling notes:
 *   - Treat -ENOENT as a normal race outcome if objects can disappear.
 *   - Always close the returned FD to avoid resource leaks.
 *
 * Thread safety:
 *   - Safe to call concurrently; each successful invocation yields an independent FD.
 *
 * Forward compatibility:
 *   - ID space is monotonic; practical wraparound is not expected.
 *   - Future kernels may add additional validation or permission gating; handle
 *     new -errno codes conservatively.
 */
LIBBPF_API int bpf_btf_get_fd_by_id(__u32 id);

/**
 * @brief Obtain a file descriptor for an existing in-kernel BTF (BPF Type Format)
 *        object by its kernel-assigned ID, with extended open options.
 *
 * bpf_btf_get_fd_by_id_opts() is an extended variant of bpf_btf_get_fd_by_id().
 * It wraps the BPF_BTF_GET_FD_BY_ID command of the bpf(2) syscall and converts
 * a stable, monotonically increasing BTF object ID (@p id) into a process-local
 * file descriptor, honoring optional attributes supplied via @p opts.
 *
 * A BTF object represents a loaded collection of type metadata (vmlinux BTF,
 * kernel module BTF, or user-supplied BTF blob). Programs and maps can refer
 * to these types for CO-RE relocations, verification, and introspection.
 *
 * Typical enumeration + open pattern:
 *   __u32 cur = 0, next;
 *   while (bpf_btf_get_next_id(cur, &next) == 0) {
 *       struct bpf_get_fd_by_id_opts o = {
 *           .sz = sizeof(o),
 *           .open_flags = 0,
 *           .token_fd = -1,
 *       };
 *       int btf_fd = bpf_btf_get_fd_by_id_opts(next, &o);
 *       if (btf_fd >= 0) {
 *           // use btf_fd (e.g. bpf_btf_get_info_by_fd())
 *           close(btf_fd);
 *       }
 *       cur = next;
 *   }
 *   // Loop ends when bpf_btf_get_next_id() returns -ENOENT.
 *
 * Initialization & @p opts usage:
 *   - @p opts may be NULL for default behavior (equivalent to zeroed fields).
 *   - If @p opts is non-NULL, opts->sz MUST be set to sizeof(*opts); mismatch
 *     yields -EINVAL.
 *   - opts->open_flags:
 *       Reserved for future kernel extensions; pass 0 unless a documented flag
 *       is supported. Unsupported bits => -EINVAL.
 *   - opts->token_fd:
 *       Optional BPF token FD enabling delegated (restricted) permissions. Set
 *       to -1 or 0 if unused. Provides a way to open BTF objects without full
 *       CAP_BPF/CAP_SYS_ADMIN in controlled environments.
 *
 * Concurrency & races:
 *   - A BTF object can be unloaded (e.g., module removal) after ID discovery
 *     but before this call; expect -ENOENT in such races.
 *   - Successfully obtaining a file descriptor does not guarantee the object
 *     will remain available for its entire lifetime (it could still be removed
 *     depending on kernel policies), so subsequent operations may fail.
 *
 * Lifetime & ownership:
 *   - On success you own the returned FD and must close() it when done.
 *   - Closing the FD does not destroy the BTF object if other references (FDs,
 *     pinned bpffs entries) remain.
 *   - You may pin the BTF object via bpf_obj_pin() for persistence.
 *
 * Security / privileges:
 *   - May require CAP_BPF and/or CAP_SYS_ADMIN depending on kernel configuration,
 *     LSM policy, and lockdown mode.
 *   - Access via a token_fd is subject to token scope; insufficient rights yield
 *     -EPERM / -EACCES.
 *
 * Use cases:
 *   - Retrieve type information with bpf_btf_get_info_by_fd().
 *   - Supply prog_btf_fd when loading eBPF programs needing CO-RE relocations.
 *   - Enumerate and manage user-loaded or kernel-provided BTF datasets.
 *
 * Robustness tips:
 *   - Treat -ENOENT as a normal race when enumerating dynamic BTF objects.
 *   - Always zero-initialize opts before setting recognized fields:
 *       struct bpf_get_fd_by_id_opts o = {};
 *       o.sz = sizeof(o);
 *   - Avoid non-zero open_flags until documented; future kernels may add semantic
 *     modifiers (e.g., restricted viewing modes).
 *
 * @param id   Kernel-assigned unique BTF object ID (> 0).
 * @param opts Optional pointer to struct bpf_get_fd_by_id_opts controlling open
 *             behavior; may be NULL for defaults.
 *
 * @return >= 0: File descriptor referencing the BTF object (caller must close()).
 *         < 0 : Negative error code (libbpf style == -errno) on failure.
 *
 * Error handling (negative return values are libbpf-style == -errno):
 *   - -ENOENT: No BTF object with @p id (unloaded or never existed).
 *   - -EINVAL: Invalid @p id (e.g., 0), malformed @p opts (bad sz), or unsupported
 *              open_flags bits.
 *   - -EPERM / -EACCES: Insufficient privileges or blocked by security policy.
 *   - -ENOMEM: Kernel resource allocation failure.
 *   - Other -errno codes may be propagated from underlying syscall failures.
 *
 */
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
/**
 * @brief Retrieve information about a BPF object (program, map, BTF, or link) given
 *        its file descriptor.
 *
 * This is a generic libbpf wrapper around the kernel's BPF_OBJ_GET_INFO_BY_FD
 * command. Depending on what type of BPF object @p bpf_fd refers to, the kernel
 * expects @p info to point to an appropriately typed info structure:
 *
 *   - struct bpf_prog_info  (for program FDs)
 *   - struct bpf_map_info   (for map FDs)
 *   - struct bpf_btf_info   (for BTF object FDs)
 *   - struct bpf_link_info  (for link FDs)
 *
 * You must:
 *   1. Zero-initialize the chosen info structure (to avoid undefined padding contents).
 *   2. Set *@p info_len to sizeof(struct <relevant_info_type>) before the call.
 *   3. Pass a pointer to the structure as @p info.
 *
 * On success, the kernel fills as much of the structure as it supports/recognizes
 * for the running kernel version and may update *@p info_len with the actual number
 * of bytes written (libbpf preserves kernel behavior). Unrecognized future fields
 * remain zeroed. If *@p info_len is smaller than the minimum required size for that
 * object type, the call fails with -EINVAL.
 *
 * Typical usage (program example):
 *   struct bpf_prog_info pinfo = {};
 *   __u32 len = sizeof(pinfo);
 *   if (bpf_obj_get_info_by_fd(prog_fd, &pinfo, &len) == 0) {
 *       // pinfo now populated (len bytes). Inspect fields like pinfo.id, pinfo.type, ...
 *   } else {
 *       // handle error (errno set; negative return value also provided)
 *   }
 *
 * Concurrency & races:
 *   - The object referenced by @p bpf_fd remains valid while its FD is open, so
 *     races are limited. However, fields referring to related kernel entities
 *     (e.g., map IDs a program references) may change if other management operations
 *     occur concurrently.
 *
 * Forward/backward compatibility:
 *   - Always zero the entire info struct before calling; newer kernels may fill
 *     additional fields.
 *   - Do not assume all fields are populated; check size/version or specific
 *     feature flags if present.
 *
 * Security / privileges:
 *   - Access may require CAP_BPF and/or CAP_SYS_ADMIN depending on kernel configuration,
 *     LSM policy, and lockdown mode. Insufficient privilege yields -EPERM / -EACCES.
 *
 * @param bpf_fd   File descriptor of a loaded BPF object (program, map, BTF, or link).
 * @param info     Pointer to a zero-initialized, type-appropriate info structure
 *                 (see list above).
 * @param info_len Pointer to a __u32 containing the size of *info* on input; on
 *                 success updated to the number of bytes actually written. Must
 *                 not be NULL.
 *
 * @return 0 on success;
 *         < 0 negative error code (libbpf style == -errno) on failure:
 *           - -EBADF:  @p bpf_fd is not a valid BPF object descriptor.
 *           - -EINVAL: Wrong object type, info_len too small, malformed arguments.
 *           - -EFAULT: @p info or @p info_len points to inaccessible user memory.
 *           - -EPERM / -EACCES: Insufficient privileges / blocked by security policy.
 *           - -ENOMEM: Kernel failed to allocate internal resources.
 *           - Other -errno values may be propagated from the underlying syscall.
 *
 * Error handling notes:
 *   - Treat -EINVAL as often indicating a size mismatch; verify that sizeof(your struct)
 *     matches what the kernel expects for your libbpf/kernel version.
 *   - Always inspect errno (or the negative return value) for precise failure reasons.
 *
 */
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
/**
 * @brief Attach a loaded BPF program to a raw tracepoint using extended options.
 *
 * bpf_raw_tracepoint_open_opts() wraps the BPF_RAW_TRACEPOINT_OPEN command and
 * creates a persistent attachment of @p prog_fd to the raw tracepoint named in
 * @p opts->tp_name. On success it returns a file descriptor representing the
 * attachment. Closing that FD detaches the program from the tracepoint.
 *
 * Compared to bpf_raw_tracepoint_open(), this variant allows passing a user
 * cookie (opts->cookie) and provides forward/backward compatibility via the
 * @p opts->sz field.
 *
 * Typical usage:
 *   struct bpf_raw_tp_opts ropts = {
 *       .sz      = sizeof(ropts),
 *       .tp_name = "sched_switch",   // raw tracepoint name (no "tracepoint/" prefix)
 *       .cookie  = 0xdeadbeef,       // optional user cookie (visible to program)
 *   };
 *   int tp_fd = bpf_raw_tracepoint_open_opts(prog_fd, &ropts);
 *   if (tp_fd < 0) {
 *       // handle error (inspect errno or negative return value)
 *   }
 *   // ... use attachment; close(tp_fd) to detach when done.
 *
 * Tracepoint name:
 *   - Use the raw tracepoint identifier as exposed under
 *     /sys/kernel/debug/tracing/events/ without category prefixes. For raw
 *     tracepoints this is typically the internal kernel name (e.g., "sched_switch").
 *   - Passing NULL or an empty string fails with -EINVAL.
 *
 * Cookie:
 *   - opts->cookie (if non-zero) becomes available to the attached program via
 *     bpf_get_attach_cookie() helper (where supported).
 *   - Set to 0 if you don't need a cookie; kernel treats it as absent.
 *
 * Structure initialization:
 *   - opts MUST NOT be NULL.
 *   - Zero-initialize the struct, then set:
 *       opts->sz      = sizeof(struct bpf_raw_tp_opts);
 *       opts->tp_name = "<tracepoint_name>";
 *       opts->cookie  = <optional_cookie>;
 *   - Unrecognized future fields must remain zero for compatibility.
 *
 * Lifetime & detachment:
 *   - The returned FD solely controls the attachment lifetime. Closing it
 *     detaches the program.
 *   - The program FD @p prog_fd may be closed independently after successful
 *     attachment; the link remains active until the tracepoint FD is closed.
 *
 * Concurrency:
 *   - Multiple programs can attach to the same raw tracepoint (each gets its
 *     own FD).
 *   - Attaching/detaching is atomic from the program's perspective; events
 *     arriving after success will invoke the program.
 *
 * Privileges:
 *   - Typically requires CAP_BPF and/or CAP_SYS_ADMIN depending on kernel
 *     configuration, LSM policy, and lockdown mode.
 *
 * Performance considerations:
 *   - Raw tracepoints invoke programs on every event occurrence; ensure program
 *     logic is efficient to avoid noticeable system overhead.
 *
 * @param prog_fd
 *   File descriptor of a previously loaded BPF program (bpf_prog_load()) that
 *   is compatible with raw tracepoint attachment (e.g., program type
 *   BPF_PROG_TYPE_RAW_TRACEPOINT or suitable tracing type).
 *
 * @param opts
 *   Pointer to an initialized bpf_raw_tp_opts structure describing the target
 *   tracepoint and optional cookie. Must not be NULL. opts->sz must equal
 *   sizeof(struct bpf_raw_tp_opts).
 *
 * @return
 *   >= 0 : File descriptor representing the attachment (close to detach).
 *   < 0  : Negative libbpf-style error code (== -errno) on failure:
 *            - -EINVAL   : Bad prog_fd, malformed opts (sz mismatch, NULL tp_name),
 *                         unsupported program type, or kernel lacks raw TP support.
 *            - -EPERM/-EACCES : Insufficient privileges or blocked by security policy.
 *            - -ENOENT   : Tracepoint name not found / not supported by current kernel.
 *            - -EBADF    : Invalid prog_fd.
 *            - -ENOMEM   : Kernel memory/resource exhaustion.
 *            - -EOPNOTSUPP/-ENOTSUP : Raw tracepoint attachment not supported.
 *            - Other -errno codes may be propagated from the underlying syscall.
 *
 * Error handling:
 *   - Inspect the negative return value or errno for diagnostics.
 *   - Treat -ENOENT as "tracepoint unavailable" (kernel config or version gap).
 *
 * After attachment:
 *   - Optionally pin the FD (bpf_obj_pin()) if you need persistence.
 *   - Use bpf_obj_get_info_by_fd() to query attachment metadata if supported.
 */
LIBBPF_API int bpf_raw_tracepoint_open_opts(int prog_fd, struct bpf_raw_tp_opts *opts);

/**
 * @brief Attach a loaded BPF program to a raw tracepoint (legacy/simple API).
 *
 * bpf_raw_tracepoint_open() is a convenience wrapper that issues the
 * BPF_RAW_TRACEPOINT_OPEN command to attach the BPF program referenced
 * by @p prog_fd to the raw tracepoint named @p name. On success it returns
 * a file descriptor representing the attachment; closing that FD detaches
 * the program from the tracepoint.
 *
 * Compared to bpf_raw_tracepoint_open_opts(), this legacy interface
 * provides no ability to specify an attach cookie or future extension
 * fields. For new code prefer bpf_raw_tracepoint_open_opts() to enable
 * forward/backward compatible option passing.
 *
 * Tracepoint name:
 *   - @p name must be a non-NULL, null-terminated string identifying a
 *     raw tracepoint (e.g. "sched_switch").
 *   - Pass the raw kernel tracepoint identifier without any category
 *     prefix (do not include "tracepoint/" or directory components).
 *   - If the tracepoint is not available (kernel config/version) the
 *     call fails with -ENOENT.
 *
 * Program requirements:
 *   - @p prog_fd must refer to a loaded BPF program of a type compatible
 *     with raw tracepoint attachment (e.g., BPF_PROG_TYPE_RAW_TRACEPOINT
 *     or an allowed tracing program type accepted by the kernel).
 *   - The program may be safely closed after a successful attachment;
 *     the returned FD controls the lifetime of the link.
 *
 * Lifetime & detachment:
 *   - Each successful call creates a distinct attachment with its own FD.
 *   - Closing the returned FD immediately detaches the program from the
 *     tracepoint.
 *   - The returned FD can be pinned (bpf_obj_pin()) for persistence.
 *
 * Concurrency:
 *   - Multiple programs can be attached to the same raw tracepoint.
 *   - Attach/detach operations are atomic; events after success invoke
 *     the program until its FD is closed.
 *
 * Privileges & security:
 *   - Typically requires CAP_BPF and/or CAP_SYS_ADMIN depending on
 *     kernel configuration, LSM, and lockdown mode.
 *   - Insufficient privilege yields -EPERM / -EACCES.
 *
 * Performance considerations:
 *   - Raw tracepoints can be very frequent; ensure attached program
 *     logic is efficient to avoid noticeable overhead.
 *
 * @param name    Null-terminated raw tracepoint name (e.g. "sched_switch").
 * @param prog_fd File descriptor of a loaded, compatible BPF program.
 *
 * @return >= 0 : Attachment file descriptor (close to detach).
 *         < 0  : Negative error code (libbpf style == -errno) on failure.
 *
 * Error handling (negative libbpf-style return value == -errno):
 *   - -EINVAL   : Invalid @p prog_fd, NULL/empty @p name, incompatible program type.
 *   - -ENOENT   : Tracepoint not found / unsupported by current kernel.
 *   - -EPERM/-EACCES : Insufficient privileges or blocked by security policy.
 *   - -EBADF    : @p prog_fd is not a valid file descriptor.
 *   - -ENOMEM   : Kernel memory/resource exhaustion.
 *   - -EOPNOTSUPP/-ENOTSUP : Raw tracepoints unsupported by the kernel.
 *   - Other negative codes may be propagated from the underlying syscall.
 *
 * Best practices:
 *   - Prefer bpf_raw_tracepoint_open_opts() for new development to
 *     gain cookie support and extensibility.
 *   - Immediately check the return value; do not rely solely on errno.
 *   - Pin the attachment if you need persistence across process lifetimes.
 *
 */
LIBBPF_API int bpf_raw_tracepoint_open(const char *name, int prog_fd);

/**
 * @brief Query metadata about a file descriptor in another task (process) that
 *        is associated with a BPF tracing/perf event and (optionally) an
 *        attached BPF program.
 *
 * This helper wraps the kernel's BPF_TASK_FD_QUERY command. It inspects the
 * file descriptor number @p fd that belongs to the task identified by @p pid
 * and, if that FD represents a perf event or similar tracing attachment, it
 * returns descriptive information about:
 *   - The attached BPF program (its kernel program ID).
 *   - The nature/type of the FD (tracepoint, raw_tracepoint, kprobe, uprobe, etc.).
 *   - Target symbol/address/offset data for kprobe/uprobes.
 *   - A human-readable identifier (tracepoint name, kprobe function name,
 *     uprobe file path), copied into @p buf when provided.
 *
 * Typical use cases:
 *   - Introspecting perf event FDs opened by another process to discover
 *     which BPF program is attached.
 *   - Enumerating and characterizing dynamically created kprobes or uprobes
 *     (e.g., by observability agents).
 *   - Building higher-level tooling that correlates program IDs with their
 *     originating probe specifications.
 *
 * Usage pattern:
 *   char info[256];
 *   __u32 info_len = sizeof(info);
 *   __u32 prog_id = 0, fd_type = 0;
 *   __u64 probe_off = 0, probe_addr = 0;
 *   int err = bpf_task_fd_query(target_pid, target_fd, 0,
 *                               info, &info_len,
 *                               &prog_id, &fd_type,
 *                               &probe_off, &probe_addr);
 *   if (err == 0) {
 *       // info[] now holds a NUL-terminated identifier (if available)
 *       // info_len == actual length (including terminating '\0')
 *       // fd_type enumerates one of BPF_FD_TYPE_* values
 *       // prog_id is the kernel-assigned BPF program ID (0 if none)
 *       // probe_off / probe_addr describe offsets/addresses for kprobe/uprobe
 *   } else if (err == -ENOSPC) {
 *       // info_len contains required size; allocate larger buffer and retry
 *   }
 *
 * Buffer semantics (@p buf / @p buf_len):
 *   - On input @p *buf_len must hold the capacity (in bytes) of @p buf.
 *   - If @p buf is large enough, the kernel copies a NUL-terminated string
 *     (tracepoint name, kprobe symbol, uprobe path, etc.) and updates
 *     @p *buf_len with the actual string length (including the NUL).
 *   - If @p buf is too small, the call fails with -ENOSPC and sets
 *     @p *buf_len to the required length; reallocate and retry.
 *   - If a textual identifier is not applicable (or unavailable), the kernel
 *     may set @p *buf_len to 0 (and leave @p buf untouched).
 *   - Passing @p buf == NULL is allowed only if @p buf_len is non-NULL and
 *     points to 0; otherwise -EINVAL is returned.
 *
 * Output parameters:
 *   - @p prog_id: Set to the kernel BPF program ID attached to the perf event
 *     FD (0 if no BPF program is attached).
 *   - @p fd_type: Set to one of the BPF_FD_TYPE_* enum values describing the
 *     FD (e.g., BPF_FD_TYPE_TRACEPOINT, BPF_FD_TYPE_KPROBE, BPF_FD_TYPE_UPROBE,
 *     BPF_FD_TYPE_RAW_TRACEPOINT). Use this to disambiguate interpretation of
 *     other outputs.
 *   - @p probe_offset: For kprobe/uprobes, the offset within the symbol or
 *     mapped file that was requested when the probe was created.
 *   - @p probe_addr: For kprobes, the resolved kernel address of the probed
 *     symbol/instruction; for uprobes may be 0 or implementation-dependent.
 *   - Any output pointer may be NULL if the caller is not interested in that
 *     field (it will simply be skipped).
 *
 * Privileges & access control:
 *   - Querying another task's file descriptor typically requires sufficient
 *     permissions (ptrace-like restrictions, CAP_BPF / CAP_SYS_ADMIN, and/or
 *     LSM allowances). Lack of privilege yields -EPERM / -EACCES.
 *   - The target task must exist and the FD must be valid at query time.
 *
 * Concurrency / races:
 *   - The target process may close or replace its FD concurrently; the query
 *     can fail with -EBADF or -ENOENT in such races.
 *   - Retrieved metadata is a point-in-time snapshot and can become stale
 *     immediately after return.
 *
 * @param pid          PID of the target task whose file descriptor table should be queried.
 *                     Use the numeric PID (thread group leader or specific thread PID);
 *                     passing 0 is typically invalid (returns -EINVAL).
 * @param fd           File descriptor number as seen from inside the task identified by @p pid.
 * @param flags        Query modifier flags. Must be 0 on current kernels; non-zero
 *                     (unsupported) bits return -EINVAL.
 * @param buf          Optional user buffer to receive a NUL-terminated identifier string
 *                     (tracepoint name, kprobe symbol, uprobe path). Can be NULL if
 *                     @p buf_len points to 0.
 * @param buf_len      In/out pointer to buffer length. On input: capacity of @p buf.
 *                     On success: actual length copied (including terminating NUL).
 *                     On -ENOSPC: required length (caller should reallocate and retry).
 * @param prog_id      Optional output pointer receiving the attached BPF program ID (0 if none).
 * @param fd_type      Optional output pointer receiving one of BPF_FD_TYPE_* constants identifying FD type.
 * @param probe_offset Optional output pointer receiving the probe offset (for kprobe/uprobe types).
 * @param probe_addr   Optional output pointer receiving resolved kernel address (kprobe) or relevant mapping address.
 *
 * @return 0 on success;
 *         Negative libbpf-style error code (< 0) on failure:
 *           - -EINVAL  : Invalid arguments (bad pid/fd, unsupported flags, inconsistent buf/buf_len).
 *           - -ENOENT  : Task, file descriptor, or associated probe/program not found.
 *           - -EBADF   : Bad file descriptor in target task at time of query.
 *           - -ENOSPC  : @p buf too small; @p *buf_len updated with required size.
 *           - -EPERM / -EACCES : Insufficient privileges or access denied by security policy.
 *           - -EFAULT  : User memory (buf or buf_len or an output pointer) not accessible.
 *           - -ENOMEM  : Temporary kernel memory/resource exhaustion.
 *           - Other -errno codes may be propagated from the underlying syscall.
 *
 * Best practices:
 *   - Initialize *buf_len with the size of your buffer; handle -ENOSPC by allocating
 *     a larger buffer using the returned required length.
 *   - Check @p fd_type first to interpret @p probe_offset / @p probe_addr meaningfully.
 *   - Treat -ENOENT and -EBADF as normal race outcomes in dynamic environments.
 *   - Avoid querying extremely frequently in production paths; this is introspective
 *     debug/management tooling, not a fast data path primitive.
 *
 * Thread safety:
 *   - This helper is thread-safe; multiple threads can query different (or the same)
 *     tasks concurrently. Returned data structures are per-call (no shared state).
 */
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
