.. SPDX-License-Identifier: GPL-2.0

===============================================
Part 5: Advanced Contexts - Concurrency and BTF
===============================================

As BPF evolved from simple packet filtering into a complex subsystem capable of replacing kernel modules (e.g., tracing, LSMs, XDP), the verifier's abstract interpretation framework had to expand.

1. BPF Type Format (BTF) and Introspection
==========================================

The :doc:`btf` is a metadata format that provides full C-language type information for kernel structures. Within the verifier's abstract interpretation framework, BTF acts as a static type system.

**BTF Availability:**

BTF type information is not always available. Its presence depends on:

* **Kernel Configuration**: The kernel must be compiled with ``CONFIG_DEBUG_INFO_BTF=y`` to provide introspection for its own internal types.
* **Program Metadata**: BPF programs themselves can optionally include BTF data to describe their own structures (e.g., map values).
* **Verifier Context**: When BTF is unavailable, the verifier falls back to more coarse-grained checks based purely on memory region boundaries (as described in Part 2).

**Type-Aware Abstract Domains:**

When BTF is enabled and the program traces a kernel function to receive a pointer (e.g., ``struct task_struct *task``), the verifier marks the register with the type ``PTR_TO_BTF_ID``.

* The ``btf_id`` points to the formal type definition in the kernel's BTF metadata.
* When the program executes ``r2 = *(u64 *)(r1 + offsetof(task, pid))``, the verifier doesn't just do numeric bounds checking. It performs **Type Checking**.
* The transfer function looks up the ``btf_id`` for ``struct task_struct``, finds the field at the requested offset, checks its size (e.g., a 4-byte integer), and checks its type.
* The destination register (``r2``) is then updated. If the field was an integer, ``r2`` becomes a ``SCALAR_VALUE``. If the field was a pointer to another struct (e.g., ``task->real_parent``), ``r2`` becomes a new ``PTR_TO_BTF_ID`` representing that parent struct.

This allows BPF programs to traverse arbitrary kernel data structures with compile-time safety guarantees, directly mirroring the type checking performed by the C compiler.

2. Concurrency Analysis (Spinlocks and RCU)
===========================================

BPF programs can run concurrently on multiple CPUs. The verifier must analyze code for data races and illegal lock usage, effectively enforcing **Lock State Tracking**.

**The Abstract Lock State:**

The ``struct bpf_verifier_state`` includes fields like ``active_spin_lock`` and ``active_rcu_lock``.

* **Spinlocks**: When a program calls the helper ``bpf_spin_lock(map_value)``, the verifier's transfer function asserts that no lock is currently held. It then updates ``active_spin_lock`` with the identity of the map value.
* The verifier ensures that while a spinlock is held, the program cannot sleep (e.g., calling certain blocking helpers) and cannot return without releasing it (``bpf_spin_unlock``).
* **RCU Sections**: For tracing and memory traversal, BPF uses RCU. The ``active_rcu_lock`` counter tracks the nesting depth of ``bpf_rcu_read_lock()`` calls. The verifier ensures that RCU pointers (tagged with ``MEM_RCU``) are only dereferenced when the RCU read lock is actively held.

By making lock status an explicit part of the abstract state, the verifier statically proves the absence of deadlocks and use-after-free bugs related to concurrency.

3. Resource Lifecycle and Reference Tracking
============================================

For complex programs that allocate kernel resources (e.g., performing a socket lookup via ``bpf_sk_lookup_tcp``), the verifier enforces a strict **Acquire-Release** lifecycle. This ensures that every allocated resource is either released or appropriately handled before the program terminates.

In the language of Abstract Interpretation, this is implemented by extending the abstract state with a **Reference Tracking** domain.

* **Acquisition (KF_ACQUIRE)**: When the verifier executes a transfer function for an "acquire" helper or kfunc, it generates a unique ``ref_obj_id``. A new entry is added to the ``refs`` array within ``struct bpf_verifier_state``, and the return register (``r0``) is tagged with this ID.
* **Reference Propagation**: The ``ref_obj_id`` is part of the register's abstract state. If the program copies the pointer to another register or spills it to the stack, the ID follows it.
* **Release (KF_RELEASE)**: When a "release" function (e.g., ``bpf_sk_release``) is called, the verifier matches the ``ref_obj_id`` of the argument. It then removes the reference from the abstract state's ``refs`` array and **invalidates** all other registers or stack slots sharing that same ID, preventing use-after-free errors.
* **Termination Proof**: At the ``BPF_EXIT`` instruction, the verifier asserts that the ``refs`` array is empty. If any reference remains, the program is rejected as it has "leaked" a kernel resource.

4. Inter-Procedural Analysis (Subprograms)
==========================================

BPF supports subprograms (calling local BPF functions using ``bpf_call``). Unlike simple inlining, the verifier performs true **Inter-Procedural Analysis (IPA)**.

1. **Call Frame Management**: When a ``bpf_call`` occurs, the verifier pushes a new call frame onto its abstract state. The caller's registers (``r6``-``r9``, which are callee-saved) are preserved in the caller's frame.
2. **Argument Passing**: The arguments (``r1``-``r5``) are passed from the caller to the callee. The verifier enforces that these arguments match the expected types (which it deduces during an initial pass).
3. **Stack Depth Validation**: The verifier computes the total stack size used by a function and its callees to ensure it never exceeds the strict 512-byte limit.
4. **Return Value Tracking**: When the callee hits the ``BPF_EXIT`` instruction, the verifier updates the caller's ``r0`` with the abstract state of the return value, pops the call frame, and resumes exploration in the caller.

By modeling the full call stack in the abstract state, the verifier ensures that function boundaries do not compromise safety.
