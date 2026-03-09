.. SPDX-License-Identifier: GPL-2.0

===============================================
Part 2: The Abstract Domain - Values and Bounds
===============================================

In Abstract Interpretation, the **Abstract Domain** defines the mathematical representation of the values a variable can hold. It determines the level of precision of the static analysis.

The BPF verifier tracks several dimensions of abstract information for each register (and stack slot), encapsulated within ``struct bpf_reg_state`` (defined in ``include/linux/bpf_verifier.h``).

1. The Value Lattice
====================

A lattice is a partially ordered set that models the flow of information. The lattice for the verifier represents knowledge, ranging from:

* **Top ($\top$)**: The most general state. It represents *any* possible value. The verifier has zero knowledge. In the code, this is represented by the ``tnum_unknown`` bitmask and the widest possible numeric bounds (``umin_value = 0``, ``umax_value = U64_MAX``, ``smin_value = S64_MIN``, ``smax_value = S64_MAX``), applied via functions like ``__mark_reg_unknown()`` and ``__mark_reg_unbounded()``.
* **Intermediate Values**: Partial knowledge (e.g., "the value is between 5 and 10," or "the lower 3 bits are 0").
* **Bottom ($\bot$)**: The most specific state. It represents an impossible or contradictory state (e.g., a value that must be simultaneously > 10 and < 5). The verifier does not have an explicit ``struct`` for Bottom; instead, it manifests as contradictory bounds (e.g., ``umin_value > umax_value``). When the verifier encounters this, it identifies the execution path as dead code and stops exploring it.

The goal of the verifier is to start with maximal assumptions ($\top$ for inputs) and use instructions to narrow down the possible values, moving down the lattice without ever falsely restricting the set of possible concrete executions.

2. Tristate Numbers (``tnum``)
==============================

One of the most powerful abstract domains in the BPF verifier is the **Tristate Number**, implemented in ``kernel/bpf/tnum.c``.

Instead of tracking precise bitwise values, a ``tnum`` tracks the state of each bit independently. Each bit can be in one of three states:

1. **0**: Known to be zero.
2. **1**: Known to be one.
3. **u**: Unknown.

A ``tnum`` is represented by two 64-bit masks: ``value`` and ``mask``.

* ``value``: The bits that are known to be 1.
* ``mask``: The bits that are unknown.
* (Bits that are 0 in both ``value`` and ``mask`` are known to be 0).

**Example:**

* ``tnum_const(5)`` (Binary ``0101``): ``value = 0101``, ``mask = 0000``. All bits are known.
* ``tnum_unknown()``: ``value = 0000``, ``mask = 1111...1111``. No bits are known ($\top$).
* If we know a value is a multiple of 4, the lowest two bits must be zero: ``value = 0000``, ``mask = 1111...1100``.

The ``tnum`` domain is exceptional for analyzing bitwise operations like AND (``&``), OR (``|``), and shifts. By tracking individual bits, the verifier can calculate the exact state of the resulting bits wherever possible, preserving a high degree of precision across bitwise operations.

3. Numeric Bounds Tracking
==========================

While ``tnum`` is excellent for bitwise logic, it is imprecise for arithmetic bounds. For example, knowing a value is "less than 10" is difficult to express cleanly with a bitmask.

To solve this, ``struct bpf_reg_state`` also tracks numeric bounds:

* **Unsigned Bounds**: ``umin_value`` and ``umax_value``.
* **Signed Bounds**: ``smin_value`` and ``smax_value``.
* **32-bit Subregister Bounds**: ``u32_min_value``, ``u32_max_value``, ``s32_min_value``, ``s32_max_value``.

When the verifier analyzes an instruction, it updates *both* the ``tnum`` and the numeric bounds. Furthermore, it synchronizes them. If the ``tnum`` dictates the sign bit must be 0, the verifier can update the signed bounds to be positive. If the numeric bounds dictate the maximum value is 7, the verifier can update the ``tnum`` mask to clear bits higher than 2.

4. Pointer Types and Provenance
===============================

Scalars (integers) are only one part of the abstract domain. A critical security function of the verifier is distinguishing raw scalars from **Pointers**.

In ``enum bpf_reg_type``, the verifier tracks the *provenance* (the origin) of pointers. This defines what the pointer fundamentally points to:

* **``SCALAR_VALUE``**: A raw integer. Safe for math, unsafe for memory access.
* **``PTR_TO_CTX``**: A pointer to the BPF context (e.g., ``struct __sk_buff``).
* **``PTR_TO_MAP_VALUE``**: A pointer to an element within a BPF map.
* **``PTR_TO_STACK``**: A pointer to the program's local stack.
* **``PTR_TO_PACKET``**: A pointer to the raw network packet data.

**Type Modifiers (Permissions and Safety):**

Beyond the base type, the verifier enriches pointer states using bitwise modifiers defined in ``enum bpf_type_flag``. These flags act as a strict type system enforcing access permissions and safe usage contexts. Important modifiers include:

* **``PTR_MAYBE_NULL``**: Indicates the pointer might be null. The verifier will aggressively reject any attempt to dereference this pointer until the program explicitly checks it against 0 (which triggers a state split, converting it to a valid pointer on the non-null path).
* **``MEM_RDONLY``**: Denotes that the memory region the pointer references is strictly read-only.
* **``PTR_TRUSTED``**: A vital security flag indicating the pointer was passed directly from the kernel in a safe context and is guaranteed to be valid. It is safe to pass to BPF helpers. Conversely, **``PTR_UNTRUSTED``** means the pointer was obtained by walking a chain of structs and might be invalid, restricting its use to direct, fault-handled dereferencing.
* **``MEM_RCU``**: Indicates the memory access requires an active RCU read lock.

When a register holds a pointer, the verifier conceptually separates its state into:

1. **The Base Pointer**: The origin (e.g., the start of the map value) combined with its type and modifier flags.
2. **The Offset**: The distance from the base. This offset is tracked using the scalar abstract domain (``tnum`` + bounds) described above.

By separating the base and the offset, the verifier can formally prove memory safety: it ensures that for all possible values of the offset (evaluated against the scalar bounds), the resulting memory address never falls outside the allocated boundaries of the Base Pointer.

----

Next: In **Part 3: Data Flow and Transfer Functions**, we will explore how instructions mutate this abstract state, detailing ALU operations and conditional jumps.
