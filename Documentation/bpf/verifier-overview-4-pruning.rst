.. SPDX-License-Identifier: GPL-2.0

========================================
Part 4: State Pruning and Loop Analysis
========================================

Because the BPF verifier relies on path exploration (splitting states at every branch), a naive implementation would suffer from exponential path explosion. To keep verification times reasonable—and to allow loops—the verifier employs **State Pruning**.

In the context of Abstract Interpretation, pruning is conceptually related to identifying fixed points and utilizing partial ordering between abstract states.

1. State Equivalence (``states_equal``)
=======================================

Before the verifier evaluates an instruction, it checks if it has been here before. It maintains a history of previously verified states at various jump targets.

When the verifier reaches an instruction with a *current state*, it compares it against a *previously verified state* (an *existing state*) at the same instruction.

This comparison is performed by ``states_equal()`` (in ``kernel/bpf/verifier.c``). Crucially, ``states_equal`` is *not* a strict equality check. It is a **subsumption** (or partial order) check.

It asks: *Is the current state "more specific" than (or equal to) the existing state?*

If the *current state* is subsumed by the *existing state*, it means every possible concrete execution represented by the current state is a subset of the executions already proven safe by the existing state. Therefore, the verifier can safely **prune** the current path. It stops evaluating the *current state* and marks the branch as safe.

**Examples of Subsumption:**

* If the *existing state* had a register as $\top$ (completely unknown scalar) and the *current state* has that same register bounded between 5 and 10, then the current state is subsumed. The existing state proved safety for *any* value, so a restricted value is naturally safe.
* If both the *existing state* and the *current state* have a register as a ``PTR_TO_MAP_VALUE`` with the same offset, they are equal, so it's safe to prune.
* If the *existing state* had a register bounded between 5 and 10, but the *current state* has it bounded between 0 and 15, the *current state* is *wider*. It is not subsumed. The verifier must continue evaluating the *current state*.

2. Liveness Tracking (Dead State Elimination)
=============================================

To maximize pruning, the verifier uses **Liveness Analysis** (a classic data-flow analysis technique). If a register's value is never read before being overwritten on a path, it is "dead."

The verifier performs this liveness analysis in a separate pass (``compute_live_registers()``) before the main path exploration (``do_check()``) begins. By analyzing the program's control flow in advance, the verifier pre-determines which registers are dead at any given instruction.

The verifier tracks this using ``REG_LIVE_READ`` and ``REG_LIVE_WRITTEN`` flags. During the ``states_equal()`` check, if a register is marked as dead in the *existing state*, the verifier knows that this register will remain dead regardless of how the current path is explored. As a result, it completely ignores the value of that register in the *current state*.

By ignoring dead registers, the verifier increases the probability that a *current state* is subsumed by an *existing state*, leading to higher pruning rates and faster verification.

3. Loop Verification (Bounded Loops)
====================================

Historically, BPF programs had to be Directed Acyclic Graphs (DAGs). Any back-edge (a jump to an ancestor in the Control Flow Graph) was instantly rejected to guarantee termination.

Modern BPF supports **Bounded Loops** (``bpf_loop`` helper or direct `goto` back-edges under specific conditions).

To verify a loop without infinite analysis, the verifier relies on a form of **Bounded Abstract Interpretation** and **Widening**.

1. **Loop State Generation**: When a back-edge is taken, the verifier evaluates the loop body multiple times.
2. **State Convergence**: On each iteration, the abstract state at the loop header is updated. Variables modified in the loop (e.g., induction variables like ``i = i + 1``) will have their bounds grow.
3. **Termination Proof**: The verifier must prove that the loop induction variable eventually reaches the loop exit condition. If ``i`` is bounded by a constant, and the loop exits when ``i >= MAX``, the verifier can track the maximum bound of ``i``.
4. **State Equivalence in Loops**: If the abstract state at the loop header converges (i.e., iterating the loop no longer widens the abstract bounds, or the new state is subsumed by a previous iteration's state), the verifier has found a safe fixed-point and can prune the loop exploration.

If the verifier cannot prove that a loop terminates (e.g., the upper bound of the induction variable relies on data read from memory rather than a known scalar), or if it hits the maximum instruction complexity limit (historically 1 million simulated instructions), it rejects the program.

----

Next: In **Part 5: Advanced Contexts - Concurrency and BTF**, we will explore how the verifier handles modern extensions like the BPF Type Format, spinlocks, and subprogram analysis.
