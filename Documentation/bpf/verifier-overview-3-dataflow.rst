.. SPDX-License-Identifier: GPL-2.0

========================================
Part 3: Data Flow and Transfer Functions
========================================

In Programming Language (PL) theory, a **Transfer Function** describes how an abstract state transitions from one state to another when an instruction is processed by the verifier.

For the BPF verifier, the transfer functions map an input ``struct bpf_verifier_state`` to a new output state. This step-by-step symbolic evaluation of bytecode over the abstract domain (Part 2) is the core of the BPF verifier's safety proof.

**Code Organization:**
In the verifier's implementation, a "transfer function" is rarely a single monolithic C function. Because the abstract state consists of multiple domains (numeric bounds, bitwise ``tnum``, pointer provenance), the transfer function for a single instruction is carried out by invoking a specific operation for *each* domain. For example, when processing an addition instruction, the verifier will call ``scalar_min_max_add()`` to transform the bounds domain, and separately call ``tnum_add()`` to transform the bitwise domain, before finally synchronizing them.

1. Transfer Functions for ALU Operations
========================================

Arithmetic and Logic Unit (ALU) operations (e.g., addition, subtraction, bitwise shifts) are analyzed using transfer functions that independently update the ``tnum`` state and the numeric bounds state for the destination register.

The kernel implements these transfer functions in ``adjust_scalar_min_max_vals()`` (within ``kernel/bpf/verifier.c``).

* **Bitwise Operations (AND, OR, XOR)**: These are highly precise in the ``tnum`` domain. For example, in an AND operation, if a bit is known to be 0 in *either* operand, the verifier can conclude the resulting bit is 0. If bits are unknown, the resulting bit is unknown.
* **Arithmetic Operations (ADD, SUB)**: These operations naturally update the minimum and maximum boundaries (e.g., if ``r1`` is ``[2, 5]`` and ``r2`` is ``[10, 20]``, the transfer function for ``r1 += r2`` evaluates to ``[12, 25]``). Crucially, they **also update the ``tnum`` state**. The verifier uses sophisticated bitwise arithmetic in ``tnum_add()`` and ``tnum_sub()`` to track potential carry propagation, ensuring that knowledge about specific bits (like whether a value is even or a multiple of 4) is preserved even through addition and subtraction.

**Handling Overflow (Loss of Precision):**
The verifier explicitly checks for potential integer overflow or underflow during arithmetic (using functions like ``check_add_overflow()``). If an operation could result in an overflow, the verifier handles it by **widening** the abstract bounds to their maximum range (e.g., resetting ``umin`` to 0 and ``umax`` to ``U64_MAX``). This represents a "loss of precision" in the abstract domain: the verifier no longer knows the exact range of the result and must assume the most conservative state ($\top$) to remain sound. If such an unbounded value is later used as a memory offset, the verifier will reject the program.

**Synchronizing Domains:**
Because the verifier uses two parallel abstract domains (``tnum`` for bits, min/max for bounds), the ALU transfer function must synthesize them. After an ADD operation, the verifier calls ``__update_reg_bounds()``, which forces consistency:

* If the numeric bounds determine a value is exactly `7`, the `tnum` is set to `value=7, mask=0`.
* If the `tnum` shows the sign bit is 0, the signed min bound is bumped up to 0 (if it was previously negative).

2. Transfer Functions for Pointers
==================================

When an ALU operation involves a pointer (e.g., ``r1 += r2``, where ``r1`` is a ``PTR_TO_MAP_VALUE`` and ``r2`` is a ``SCALAR_VALUE``), the verifier must handle it differently.

This is processed in ``adjust_ptr_min_max_vals()``. The transfer function calculates how the addition of the scalar affects the allowed bounds of the pointer.

* The verifier checks if the resulting abstract offset exceeds the allocated size of the memory region (e.g., the map value size).
* To prevent speculative execution attacks (Spectre v1), the verifier may also inject runtime mitigations (masking operations) into the bytecode, depending on the abstract bounds it calculated.

3. Branching and Path Exploration
=================================

The most complex transfer functions occur during control flow operations (jumps). Conditional jumps (e.g., ``if (r1 < 10) goto X``) are where the BPF verifier refines its knowledge.

When the verifier evaluates a conditional branch, the abstract state splits. It creates two separate execution paths:

1. **The Fall-Through Path (False Branch)**: The instruction following the jump.
2. **The Target Path (True Branch)**: The destination instruction of the jump.

The transfer function for the jump instruction refines the abstract state on *both* paths independently. This logic lives in ``check_cond_jmp_op()`` and ``reg_set_min_max()``.

**Example:**
Assume ``r1`` is an unknown scalar (``[0, U64_MAX]``). The instruction is ``if (r1 < 10) goto A; else goto B;``.

* **Path A (True Branch)**: The verifier updates the abstract state for ``r1``. Since the condition was true, the new upper bound of ``r1`` is 9. The new state for ``r1`` is ``[0, 9]``.
* **Path B (False Branch)**: The verifier updates the abstract state for ``r1``. Since the condition was false, the new lower bound of ``r1`` is 10. The new state for ``r1`` is ``[10, U64_MAX]``.

By splitting the state, the verifier gains precision. It "learns" from conditionals, ensuring that subsequent memory accesses bounded by ``r1`` are proven safe on Path A, even if they would be out-of-bounds on Path B.

4. Memory Access Verification
=============================

Memory access instructions (loads and stores) are validated to ensure they only read or write within permitted boundaries. The transfer function for these instructions not only updates the abstract state but also determines whether the memory access is safe, rejecting the program if bounds cannot be proven.

When executing ``r2 = *(u32 *)(r1 + 0)`` (in ``check_mem_access()``), the verifier performs the following checks:

1. **Provenance Check**: Is ``r1`` a valid pointer type (e.g., ``PTR_TO_MAP_VALUE``)? If it's a scalar, the verifier rejects the program.
2. **Bounds Check**: Does the abstract offset of ``r1`` (which is a range of possible values, ``[umin, umax]``) plus the access size (4 bytes for ``u32``) fall completely within the boundaries of the memory region?

   * The verifier checks the maximum possible offset. If it exceeds the boundary, the program is rejected.
   * The verifier checks the minimum possible offset. If it is negative, the program is rejected.

3. **Type Update**: After verifying the access, the transfer function updates the destination register (``r2``). The new type is determined by the metadata of the memory being accessed:
    * **Map Values**: Typically results in a ``SCALAR_VALUE`` (unless loading a special kernel pointer/kptr).
    * **Context (``PTR_TO_CTX``)**: The resulting type (e.g., a scalar or a ``PTR_TO_PACKET``) is determined by the specific field being read, as defined in the program type's context definition (e.g., ``struct __sk_buff``).
    * **BTF-backed memory**: If the memory is described by BTF (see Part 5), the load results in the exact type defined in the kernel's C code (e.g., another ``PTR_TO_BTF_ID`` if reading a struct pointer).

----

Next: In **Part 4: State Pruning and Loop Analysis**, we will see how the verifier prevents the explosion of execution paths using state equivalence and bounded loops.
