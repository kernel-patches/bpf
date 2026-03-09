.. SPDX-License-Identifier: GPL-2.0

==============================
Abstract Interpretation in BPF
==============================

The BPF verifier is a security boundary of the Linux kernel's BPF subsystem. Its goal is to ensure that user-provided bytecode is safe to execute in kernel space. To achieve this, it must guarantee two properties:

1. **Termination:** The program must halt in a bounded amount of time (no infinite loops).
2. **Safety:** The program must not perform illegal operations, such as out-of-bounds memory accesses, leaking uninitialized kernel memory, or dereferencing invalid pointers.

BPF relies on **Static Analysis** to enforce these properties before the program is ever executed. Specifically, it uses an approach grounded in **Abstract Interpretation**.

1. What is Abstract Interpretation?
====================================

Abstract interpretation is a theory of sound approximation of the semantics of computer programs. Instead of executing the program with concrete values (e.g., executing `r1 = 5`), the verifier "executes" the program using *abstract values* that represent sets of possible concrete values (e.g., executing `r1 = [1, 10]`, meaning `r1` holds some value between 1 and 10).

This allows the verifier to reason about all possible execution paths simultaneously. If an operation is proven safe for the entire abstract domain (all possible values the abstract state represents), it is guaranteed to be safe for any specific concrete execution at runtime.

2. The Abstract State (``struct bpf_verifier_state``)
=====================================================

In PL theory, a program state at any given instruction is a mapping of memory locations to their current values. In the BPF verifier, the abstract state is represented by ``struct bpf_verifier_state`` (defined in ``include/linux/bpf_verifier.h``).

The abstract state consists of:

* **Registers:** The 11 BPF registers (``r0`` - ``r10``), modeled by ``struct bpf_reg_state``.
* **Stack:** The program's stack memory, modeled as an array of ``struct bpf_stack_state``.
* **Call Frames:** For inter-procedural analysis, the state tracks the current function call depth and the state of the caller.
* **Reference State:** A list of acquired resources (e.g., socket references, spinlocks) that must be released before the program terminates.

Whenever the verifier steps through an instruction (executed primarily within the main verification loop of ``do_check()`` and the instruction-level evaluator ``do_check_insn()`` in ``kernel/bpf/verifier.c``), it takes the current ``struct bpf_verifier_state`` and applies a **Transfer Function** (which we will cover in Part 3) to produce a new abstract state.

3. Control Flow Graph (CFG) Construction
========================================

Before analyzing data flow, the verifier must understand the control flow of the program. This is handled by ``check_cfg()`` in ``kernel/bpf/verifier.c``.

It is important to note that the verifier does not construct an explicit ``Graph`` data structure. Instead, the CFG is **implicit** in the instruction set, and the verifier computes metadata over this implicit graph. The results are maintained within the ``cfg`` member of ``struct bpf_verifier_env``:

* **``insn_stack``**: The stack used for the non-recursive Depth-First Search (DFS) traversal.
* **``insn_state``**: An array tracking the DFS state of each instruction (e.g., ``DISCOVERED``, ``EXPLORED``).
* **``insn_postorder``**: A vector of instruction indexes sorted in post-order. This is used in the **Liveness Analysis** phase (a backward data-flow analysis) performed later, for iterating through instructions efficiently.

During this traversal, the verifier checks for:

* **Unreachable Instructions:** Code that can never be executed.
* **Out-of-Bounds Jumps:** Jumps that land outside the program boundaries.
* **Back-edges (Loops):** A back-edge is a jump to an instruction that is currently on the DFS path.

**Termination and Safety:**

The verifier's approach to termination depends on the user's privilege level:

* **Unprivileged Users**: The verifier still strictly rejects all back-edges during ``check_cfg()``. This ensures that the program is a Directed Acyclic Graph (DAG), trivially guaranteeing termination.
* **Privileged Users (BPF_CAPABLE)**: Back-edges are permitted during the CFG phase. Termination is instead guaranteed during the **Path Exploration** phase (discussed below) by a global **Complexity Limit** (currently 1 million instructions processed). If the verifier exceeds this limit without converging, the program is rejected.

If any fundamental structural error is found during this phase (e.g., an unprivileged back-edge or an out-of-bounds jump), ``check_cfg()`` returns an error, and the verifier **immediately halts analysis and rejects the program**, skipping the much more expensive data-flow analysis.

4. Path Exploration vs. Data Flow Joins
=======================================

When a program branches (e.g., ``if (r1 > 10) goto A; else goto B;``), the execution path splits.

In classical Abstract Interpretation, the analysis often follows both paths and then *joins* the abstract states together where the control flow merges (e.g., taking the union of the abstract values). This is fast but loses precision.

The BPF verifier, prioritizing precision over analysis speed, primarily uses **Path Exploration**. When it encounters a branch, it pushes one path onto a stack and continues executing the other. It analyzes the ``true`` branch with the abstract knowledge that ``r1 > 10``, and it analyzes the ``false`` branch with the knowledge that ``r1 <= 10``.

This path-sensitive approach ensures that the verifier does not falsely reject safe programs due to loss of precision, though it risks path explosion. State Pruning (Part 4) is the mechanism the verifier uses to mitigate this explosion.

----

Next: In **Part 2: The Abstract Domain - Values and Bounds**, we will explore how the verifier represents partial knowledge, detailing the ``tnum`` structure and numeric bounds tracking.
