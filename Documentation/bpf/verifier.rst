=============
eBPF verifier
=============

The verifier decides if a BPF program is safe to run in the kernel. It checks
the program once, when the program is loaded. It does not run the program.

Read the chapters in order. A new word is *in italics* where it is explained.
The last chapter lists these words.

.. contents::
   :local:
   :depth: 1

Overview
========

The main idea
-------------

The verifier runs the program with sets of values. A *state* says what each
register and each stack slot can hold before an instruction (*insn*)::

  r6 = any number                      the state before the jump
  if r6 > 7 goto out
  r6 = 0..7                            the state after it

A jump makes two states. The two states meet again where the paths meet. The
verifier has two choices there::

  state A: i = 0..7     err = 0   --+
                                    +--> ?
  state B: i = 8..max   err = -22 --+

  keep apart   check the code after it two times    exact, n jumps cost 2^n
  join         i = any, err = -22 or 0              cheap, the relation is lost

Most joins lose no needed fact, and nothing tells in advance which ones do. So
the verifier joins first. If the check of an insn fails, it finds the values
that the insn depends on, and starts again with these values kept apart::

   start: join all numbers
      |
      v
    pass  ------->  error ?  --no-->  ACCEPT
      ^               | yes
      |               v
      +-- yes --  can more be kept apart ?  --no-->  REJECT

One such check of the program is a *pass*. What a pass keeps apart is its
*precision*.

Proof and guess
---------------

One rule holds for the full design:

- A pass without errors, a *good pass*, is a complete proof of the program,
  whatever it kept apart.
- Precision is a guess. A wrong guess costs time, or a valid program is
  rejected. It cannot make the verifier accept an unsafe program.

The same holds for other guesses, such as the bound of a loop: the pass checks
each of them. See `What is trusted`_.

The steps of a load
-------------------

``bpf_check()`` has three parts::

  prepare                    main analysis          rewrite
  -------------------------  ---------------------  --------------------------
  functions, BTF, maps       do_check_all():        add run-time checks
  control flow graph           pass 0               remove dead code
  constant folding             pass 1               convert context accesses
  loops, dominators            ...                  inline helpers
  liveness                                          JIT

The first part looks only at the code. It rejects the program if an insn is not
valid, if no path gets to an insn, or if a jump leaves its function.

The state
=========

``struct bpf_verifier_state`` has a frame for each function on the call chain.
A frame has the registers r0 - r10 and the stack::

  state
   +- frame 0:  r0 .. r10,  fp-8, fp-16, ...,  the loops that it is in
   +- frame 1:  ...
   +- held:       references, locks
   +- equations:  r2 = 4 * r1, ...

An *xreg* is a register or an 8-byte stack slot. Most of the verifier does not
care which one it is. `Loops`_ adds one more kind.

A value has three parts, see ``struct bpf_reg_state``::

  type         object            number
  -----------  ----------------  ------------------
  scalar       -                 the value
  map_value    which map         the offset in it
  fp           which frame       the offset in it
  unreadable   -                 -

An *unreadable* xreg has no value. The check of an insn that reads it fails.

Numbers
-------

``struct scalar`` describes a set of 64-bit numbers in four ways. The number is
in all four sets. What one of them knows refines the others, see
``scalar_bounds_sync()``.

=======  ===========================================  ==========================
part     what it knows                                log text
=======  ===========================================  ==========================
r64      a range of the 64 bits                       smin, smax, umin, umax
r32      a range of the low 32 bits                   smin32, ... umax32
var_off  bits that are known: (value; unknown bits)   ``var_off=(0x0; 0x7c)``
step     ``base + step * k``                          ``step=4+12``
=======  ===========================================  ==========================

A range is an arc on a circle: a start and a size. So one range gives the
signed and the unsigned bounds, and -4..3 is one range. Example::

                        range    var_off        step
  r1 &= 7               0..7     (0x0; 0x7)
  r1 *= 12              0..84    (0x0; 0x7c)    0+12
  r1 += 4               4..88    (0x0; 0x7c)    4+12
  if r1 > 50 goto out   4..40    (0x0; 0x3c)    4+12    4, 16, 28 or 40

Pointers
--------

==========================  ==================  ================================
type                        log text            points to
==========================  ==================  ================================
``PTR_TO_CTX``              ctx                 the context, r1 at the start
``PTR_TO_STACK``            fp                  the stack of a frame
``CONST_PTR_TO_MAP``        map_ptr             a map
``PTR_TO_MAP_VALUE``        map_value           a value of a map, global data
``PTR_TO_PACKET``           pkt                 packet data
``PTR_TO_PACKET_END``       pkt_end             the end of the packet
``PTR_TO_MEM``              mem                 memory of a known size
``PTR_TO_BTF_ID``           ptr\_<struct>       a kernel object with a BTF type
``PTR_TO_SOCKET``, ...      sock, ...           a socket
``PTR_TO_ARENA``            arena               arena memory
``PTR_TO_FUNC``             func                a BPF function
==========================  ==================  ================================

Flags add to a type. ``PTR_MAYBE_NULL`` is for a pointer that can be NULL
(``map_value_or_null``). ``MEM_RDONLY`` is for read-only memory.
``PTR_TRUSTED`` and ``PTR_UNTRUSTED`` say if the object is known to be alive.

Copies of one pointer share an *id*. What the verifier learns about one copy
holds for all of them::

  r0 = bpf_map_lookup_elem()    r0 = map_value_or_null(id=1)
  r6 = r0                       r6 = map_value_or_null(id=1)
  if r0 == 0 goto out           r0 and r6 are map_value
  r0 = *(u64 *)(r6 + 0)         safe

An id stands for the set of xregs that have it. ``bpf_renumber_ids()`` names
each id after the first xreg of its set. So two states with the same sets have
the same ids. The log prints these numbers. The id of an object can change from
one basic block to the next, and another object can get its old number.

The stack
---------

Each byte of a slot has a kind:

=======================  ========  =============================================
kind                     log text  meaning
=======================  ========  =============================================
invalid                  ``?``     not written
spill                    value     a part of a register; the slot has its value
misc                     ``m``     some data
zero                     ``0``     zero
dynptr, iter             name      an object that the kernel put there
irq flag                 ``f``     the same
poison                   ``p``     nothing reads it later, see `Liveness`_
=======================  ========  =============================================

A store of a register to an aligned slot is a *spill*. The load gives the type
and the number back.

An access with many offsets does not know its slot. A write makes misc of the
bytes in its range, and a load gives a number, see *fork* in `Partition`_. A
call with a constant size skips the bytes between two offsets: 8 bytes at
``fp-24`` or at ``fp-8`` do not touch ``fp-16``.

What is held
------------

Some calls give the program something that it has to give back: a reference, a
spin lock, the RCU lock, disabled preemption, a dynptr, an iterator, an irq
flag. All of that is *held*. At ``exit`` of the program all references and locks
have to be released. A release makes all copies of the pointer unusable.

Some dynptrs have no reference and need no release. They count as held too.

The check of one insn
=====================

``do_check_insn()`` checks an insn in one state and changes the state. If the
check fails, the insn is *unproven* in that state. Else it is *proven*. This is
not the verdict: a later pass can prove the insn. Only a program is accepted or
rejected.

Registers
  An insn can read only a register that has a value. At the start these are r1
  and r10. A call makes r1 - r5 unreadable and keeps r6 - r9.

Arithmetic on numbers
  It is safe for all values. The result is a new set of numbers.

Arithmetic on pointers
  ``pointer += number`` and ``pointer -= number`` change the offset. The number
  needs a lower bound. With ``CAP_PERFMON`` the pointer can go out of the
  object: only an access has to be in bounds. A pointer that can be NULL has to
  be tested first. A stack pointer allows only ``+=``, and some types allow no
  arithmetic. Other operations make a number of the pointer, which needs
  ``CAP_PERFMON``.

Loads and stores
  All offsets that the pointer can have must be good:

  ===========  =================================================================
  map value    in the value; special fields such as a lock need a helper
  stack        in the stack, aligned; written before, without ``CAP_PERFMON``
  context      the program type decides, see ``is_valid_access()``
  packet       in the bytes that the program checked, see below
  BTF object   in a member of the type; the member gives the type of the result
  arena        no check, the JIT keeps the address in the arena
  ===========  =================================================================

  An atomic access has to be aligned to its size. With
  ``BPF_F_STRICT_ALIGNMENT``, or if the cpu has no fast unaligned access, all
  accesses have to be aligned. ``BPF_F_ANY_ALIGNMENT`` turns that off. The check
  assumes that a packet starts 2 bytes after an aligned address.

Jumps
  A conditional jump makes two states and *refines* the operands in each. If
  the values decide the jump, only one edge is taken.

Calls of helpers and kfuncs
  The prototype says what each argument has to be: a type, a size, a constant.
  It also gives the type of r0, and says what the call acquires or releases.
  The program type selects the functions that can be called.

Exit
  r0 must be in the range that the program type allows. All references and
  locks must be released.

Packets
-------

The length of a packet is known only at run time. A compare with the end of the
packet tells how many bytes are there. The log shows that as ``r``. If the
pointer has one offset, the bytes from the start of the packet up to ``r`` are
*checked*::

  r2 = skb->data              r2 = pkt(r=0)
  r3 = skb->data_end          r3 = pkt_end
  r4 = r2 + 14                r4 = pkt(r=0, offset 14)
  if r4 > r3 goto out         r2 = pkt(r=14)
  r0 = *(u16 *)(r2 + 12)      safe: 12 + 2 <= 14

If a number with many values is added, the pointer gets a new id. Pointers with
one id differ by a constant, so one compare is good for all of them. Now ``r``
goes with the largest offset: 82 - 60 = 22 bytes after r2 are checked::

  r5 = 0..60                  the length of a header
  r2 += r5                    r2 = pkt(id=1, r=0,  offset 0..60)
  r4 = r2 + 22                r4 = pkt(id=1, r=0,  offset 22..82)
  if r4 > r3 goto out         r2 = pkt(id=1, r=82, offset 0..60)
  r0 = *(u16 *)(r2 + 14)      safe: 60 + 14 + 2 <= 82

This holds only for offsets up to 64K (``MAX_PACKET_OFF``). A helper that can
move the packet data makes all packet pointers unusable.

A pointer also keeps how many bytes are checked from the start of the packet.
The log shows that as ``min_len``, if it is not ``r``. If the largest offset
gets below ``min_len``, ``r`` is at least ``min_len``::

  r2 += 20                    r2 = pkt(r=54, offset 20)
  r2 += 40..60                r2 = pkt(id=1, r=0, min_len=54, offset 60..80)
  r2 += -50..-40              r2 = pkt(id=2, r=54, offset 10..40)

A pass
======

A pass checks the main function, then each global function that is called.
The states move through the program like this::

              +---------+   next    +-------------------+
        +---->| pending |---------->| check basic block |
        |     +---------+           +---------+---------+
        | new                                 v
        |                           +-------------------+   nothing new
        +---------------------------|    join point     |---------------> drop
          joined, or kept apart     +-------------------+

A *basic block* is a run of insns without a jump into it or out of it. A *join
point* is an insn where states can meet. The check of a function ends when no
state is pending.

The verifier counts its work. That is the *cost*, see `Limits`_. A *budget* is a
limit on the cost of one step.

Liveness
--------

An xreg is *live* at an insn if a path from the insn reads it before it writes
it. What is not live cannot matter. So a state that arrives at a basic block is
cleaned first, see ``bpf_clean_verifier_state()``. Then more states are equal::

  0: r0 = random
  1: r1 = 0
  2: if r0 == 0 goto 4
  3: r0 = 1
  4: r0 = r1          r0 is not live: both states are "r1 = 0"
  5: exit

Prune
-----

State A *subsumes* state B if A has all values of B. If the program is safe
from A, it is safe from B. B needs no check, it is *pruned*::

  A: r1 = 0..9   r2 = buf + 0..8
  B: r1 = 3      r2 = buf + 4         A subsumes B

An unreadable xreg subsumes each value: the program is safe from A without a
read of it. See ``bpf_state_subsumes()``.

Join
----

The *join* of two states has all values of both, see ``bpf_states_join()``::

  0..7         |  9             ->  0..9
  0            |  56            ->  0..56, step 56
  buf + 0      |  buf + 8       ->  buf + 0..8
  map_value    |  scalar        ->  unreadable
  buf          |  other_buf     ->  unreadable
  ctx + 0      |  ctx + 8       ->  unreadable, ctx has no range of offsets

If an insn reads the unreadable xreg, the insn is unproven, and the next pass
keeps the two types apart. This is rare, see `Two types in a live xreg`_.

A join can add values that no path has, for example 8 in the first line. After
the first join the pass is *imprecise*: an error does not prove that the
program is wrong. Later chapters have more steps that add or keep such values.
They make the pass imprecise too.

What has no join
----------------

"The lock is held or not held" has no meaning for the verifier. All such facts
are the *join_key* of a state. States with two join_keys never meet:

===============  ===============================================================
what is held     references, locks, dynptrs, iterators, irq flags
where it is      the call chain, the instance (see `Functions`_)
which trip       the peeled trip of each loop (see `Loops`_)
===============  ===============================================================

Prune or join
-------------

A state that arrives is compared with the states that are at the insn, see
``flow_prune_or_join()``:

===================================  ===========================================
if                                   action
===================================  ===========================================
they have two join_keys              they do not meet
they must stay apart (next chapter)  they do not meet
the old one subsumes the new one     prune the new one
the new one subsumes the old one     prune the old one
none of these holds                  join them
===================================  ===========================================

Two types in a live xreg
------------------------

This code is common::

  p = NULL;
  if (...)
          p = buf;
  if (p)                 if joined, p is unreadable and this read is unproven
          use(p);

If the two states are joined, an error is almost sure, and it costs a pass. So
states with two types or two objects in a live xreg stay apart already in pass
0, see ``bpf_hash_live_types()``. The same holds for a packet pointer with and
without checked bytes.

N such xregs can make 2^N states. So this rule has a budget. If a pass is over
it, the pass joins from there on, and so do the next passes. The rule does not
apply to the arguments of two calls, see `Instances`_.

The order
---------

A join point has to get all its states before it runs. Else the code after it
is checked again for each late state. ``flow_set_pending()`` sets the order:
both branches before the code after them, an iteration before the next one, a
loop before the code after the loop. See `Instances`_ for calls. The insns are
in a weak topological order: reverse post order, and each loop is in one piece.

With this order most states can meet no later state, and are freed at once.
``flow_keep()`` keeps a state only where another one can come: in a loop, at the
start of a function, after a call that can return with one more state, or in an
async callback.

Precision: data and control dependences
=======================================

This example is used from here on::

  char buf[8];                      0: r0 = random
                                    1: r6 = r0
  u64 i = random();                 2: r7 = 0
  int err = 0;                      3: if r6 <= 7 goto 5
  if (i > 7)                        4: r7 = -22
          err = -22;                5: r0 = 0                 join point
  ...                               6: if r7 != 0 goto 11
  if (err)                          7: r1 = buf
          return 0;                 9: r1 += r6
  return buf[i];                   10: r0 = *(u8 *)(r1 + 0)
                                   11: exit

The program is safe. Pass 0 does not prove it::

                   r6        r7
  from 3 to 5      0..7      0
  from 4 to 5      8..max    -22
  join             any       -22 or 0
  after insn 6     any       0            no path has r6 = 8 with r7 = 0
  insn 9           unproven: r6 has no bound

The next pass has to keep the two states at insn 5 apart. To keep all states
apart is too costly. Which xregs does insn 9 depend on?

==============  ================================================================
*data_deps*     xregs whose value flows into an operand of the unproven insn
*control_deps*  xregs whose value flows into a jump that can skip that insn
==============  ================================================================

Both sets together are the *deps*.

How they are found
------------------

``bpf_compute_deps()`` makes a backward slice. It goes back from *seeds*, in the
same way as liveness. If an insn writes an xreg of the set, that xreg leaves the
set, and what the insn reads comes in::

  liveness       starts from the reads of all insns
  data_deps      start from the reads of the unproven insn
  control_deps   start from the reads of the jumps that can skip it

                                before the insn:
                                data     control
   1: r6 = r0                   r0       -
   2: r7 = 0                    r6       -
   3: if r6 <= 7 goto 5         r6       r7
   4: r7 = -22                  r6       -
   5: r0 = 0                    r6       r7
   6: if r7 != 0 goto 11        r6       r7     <- seed of control_deps
   7: r1 = buf                  r6       -
   9: r1 += r6                  r1 r6    -      <- seed of data_deps

Insn 6 can skip insn 9: one edge leads to it and the other edge does not. Both
edges of insn 3 lead to insn 9, so insn 3 is no seed. See
``find_control_seeds()``.

The sets go through spills, calls, returns and the frames of callers. What is
held is tracked like an xreg: the insns that acquire or release write it.

The join rule
-------------

One rule decides at all join points, ``bpf_must_keep_apart()``. It looks only at
the deps that differ in the two states:

=================================  ==========  =================================
what differs                       action      why
=================================  ==========  =================================
nothing in data_deps               join        the insn gets the same operands
one xreg of data_deps, no gap      join        0..7 and 8..9 are 0..9: nothing
                                               is added
one xreg of data_deps, with a gap  keep apart  0..1 and 100: the join has 50
a type or an object in data_deps   keep apart  the join is unreadable
two xregs, one is in data_deps     keep apart  the join has pairs that no path
                                               has
=================================  ==========  =================================

A *gap* is a value of the join that is in neither state. The numbers 0 and 3
have no gap: the join is 0..3 with step 3. ``buf + 0`` and ``buf + 3`` have one,
because a load ignores the step. Two packet pointers with one id have a gap
if their distance differs: the join gives them two ids.

The last line does not apply if one state has all values of the other one in
the deps: then the join adds no pair.

In pass 0 the deps are empty, so all numbers are joined. In pass 1 of the
example r6 (data) and r7 (control) differ at insn 5::

                   r6        r7
  from 3 to 5      0..7      0       ->  insn 9 is proven
  from 4 to 5      8..max    -22     ->  goes to insn 11

r7 stores the result of the test at insn 3: it is a *stored condition*. Insn 6
tests it, so the two branches are *correlated*. Other values are still joined.
A stored condition that only selects a message keeps no states apart. This is
why the number of states stays small.

One pass finds many errors
--------------------------

A pass does not stop at its first error. It notes the insn and continues as if
the insn was proven. This is error recovery, as in a compiler. See
``skip_unproven_insn()``::

  r0 = *(u64 *)(r2 + 0)     unproven, r0 is unknown now
  r4 = *(u8 *)(r0 + 0)      unproven because of r0: not a new error
  r5 = *(u8 *)(r7 + 0)      unproven: a second seed

So the next pass has the deps of all unproven insns. A pass with an error
accepts nothing.

If an unproven call changes what is held, the path ends there. The later uses
of the lock or of the dynptr are not new errors, and must not add deps.

The pass stops when it has found all errors of the last pass again, or when it
is over a budget that starts at its first error. It does not stop at the errors
if it found a new xreg that moves with a trip index. Later trips can show that
the xreg does so only at first.

Equations
=========

A range does not tell how two numbers are related::

  r2 = r1
  r2 <<= 3
  if r1 > 7 goto out       r2 is 0..56, but only r1 was tested

So each state has a table of *equations*. A *sym* is a number that equations
use. There are three kinds. All hold mod 2^64, as the registers do::

  xreg = coef * sym + off                         r2 = 8 * sym0
  sym  = coef * sym + coef * sym + off    (sum)   sym2 = sym0 + sym1
  sym  = what an insn makes of two values (op)    sym3 = sym2 & 0xf8

For a pointer the number is its offset. A state says: there are numbers for the
syms, in their ranges, for which all equations hold.

An insn makes equations
-----------------------

An insn deletes the equation of the xreg that it writes. The result gets a new
one::

  r2 = r1             r1 = sym0, r2 = sym0
  r2 += 8             r2 = sym0 + 8
  r2 <<= 2            r2 = 4 * sym0 + 32
  r2 += r3            r2 = sym2,  sum: sym2 = 4 * sym0 + sym1 + 32
  w4 = w1             r4 = low,   sum: low = sym0 - 2^32 * high
  r1 ^= 5             r1 = sym3,  op:  sym3 = sym0 ^ 5
  *(fp - 8) = r1      fp-8 has the equation of r1

A jump uses them
----------------

A jump refines its operand, then all numbers that are related::

  xreg -> its sym -> the other syms -> their xregs

  if r1 > 7 goto out        r1 0..7  ->  sym0 0..7  ->  r2 0..56

A sum refines all of its syms. An op refines only its result. A jump that
compares two numbers also compares their difference with 0, if the difference
cannot wrap::

  off = 0..63                        off = sym0
  left = 64 - off                    left = 64 - sym0
  if (len > left) goto out           len = sym1, sym2 = len - left, sym2 <= 0
                                     so off + len = 64 + sym2 <= 64

An equation has a cost. So this jump makes sym2 only if left is a constant minus
a number, and len is in data_deps. If len is not there, the pass is imprecise.
Pass 0 has no deps, so this example needs pass 1.

A jump can compare a number with its low 32 bits. Code with no 32-bit insns does
that to test the carry of a sum::

  r5 = r2; r5 <<= 32; r5 >>= 32
  if r5 != r2 goto carry             if the jump is taken, r2 is above U32_MAX

If a range becomes empty, the equations cannot hold. No run of the program has
such a state: it is *infeasible*. It ends after the next conditional jump.

A call uses them
----------------

A helper or a kfunc gets a pointer and a size. The largest offset and the
largest size do not have to go together::

  n = bpf_get_stack(ctx, buf, 800, 0);
  if (n < 0) return;                                 n is 0..800
  bpf_get_stack(ctx, buf + n, 800 - n, 0);

                 offset      size          offset + size
  ranges         0..800      0..800        0..1600
  equations      sym0        800 - sym0    800

The check asks the equations for the largest sum. It does that for map_value, fp
and mem. It does not do that for packets: their checked bytes are relative to
the pointer.

A join guesses them
-------------------

A join looks for equations that hold in both states. It makes a sym that has
one value in each state::

              r6          r7
  state A     0           56
  state B     56          0
  join        56 * sym0   56 - 56 * sym0      sym0 is 0..1
  r6 += r7    56                              not 0..112

So many programs need no second pass. These equations are a guess.
``check_equations()`` checks them in both states and deletes what fails.

A prune checks them
-------------------

A state with an equation has fewer values than its ranges show::

  old:  r1 0..7, r2 0..7, r1 == r2
  new:  r1 0..7, r2 0..7              old does not subsume new

``check_equations()`` looks for a value in the new state for each sym of the
old state. If there is none, there is no prune.

A state without an equation has more values. So it is always safe to delete an
equation. ``normalize_equations()`` deletes those that say nothing, and keeps
the table small.

The join rule uses the equations too. If only one of two states has
``r1 == r6``, the two xregs count as different.

Loops
=====

A *trip* is one iteration. The *header* is the insn where each trip starts. A
back edge leads to it. The verifier has to prove two things: each insn is safe
in all trips, and the loop ends.

One state for all trips
-----------------------

The state that comes back to the header is joined with the state that is there.
The body is checked again with the join. This stops when the state at the
header subsumes the state that comes back. That is the *fixpoint*.

A counter grows in each trip, so plain joins do not stop. The first growth is a
join. After that the bound is *widened*: it jumps to a *threshold*::

  i = 0;
  while (random()) {
          if (!big[i])                char big[64]
                  continue;
          i += 3;
          if (i >= 30)
                  break;
  }

  i at the header:
  pass 0    0  ->  0..3  ->  0..S32_MAX     big[i] is unproven
  pass 1    0  ->  0..3  ->  0..29          i is in the deps now

The thresholds of an xreg in the deps are the constants of the loop, one less,
and one step more. Other xregs stop at 0, ``S32_MAX``, ``U32_MAX`` or
``S32_MIN``. A threshold is a guess. If it is too small, the state that comes
back is not subsumed, and the bound goes to the next threshold.

An *entry* is a state that enters the loop. The join rule keeps two entries
apart, as at any join point. A state that comes back meets the state of its own
entry. There the join rule does not apply to numbers, else the check of the
loop has no end.

The trip index
--------------

The *trip index* k counts how many times the program came back to the header.
It is an xreg: 0 at the entry, + 1 at each back edge. So it is the canonical
induction variable of the loop. The join at the header finds the xregs that move
with it, the other induction variables (*iv*). A *walk* is one check of the
body::

  i = 0; p = big;
  do {
          use(*(u64 *)p);
          i++; p += 8;
  } while (i < 8);

  at the header:
  walk 1    k = 0       i = 0        p = big
  walk 2    k = 0..1    i = k        p = big + 8 * k      the join finds these
  walk 3    k = 0..7    i = k        p = big + 8 * k      'i < 8': threshold 7

A jump that tests a number that moves with k gives k a threshold. This needs no
precision, so it works in pass 0.

In walk 3 the jump refines i, so k, so p. No jump tests p. The back edge brings
k = 1..7, and the header subsumes that.

Walks 1 and 2 only collect the steps and the threshold. Often the code shows
them. Then ``bpf_guess_first_trips()`` starts with walk 3, and the body is
checked once. This is a guess too.

Two entries can have two bounds. So each entry has its own threshold for k.

The loop must end
-----------------

A state that is pruned by its own ancestor closes a cycle::

  t --> ... --> header --> ... --> s
  ^                                |
  `----------- subsumes -----------'

Each state also counts how many times the verifier came back to the header with
it. A join has the larger count. All pruned states go through
``flow_check_trip_counts()``. If s has a larger count than t, s can come from
t, and something has to stop the loop:

=====================================  =========================================
if                                     the loop ends because
=====================================  =========================================
k of s is at most 2^32                 k grows in each trip and has a bound;
                                       the largest k + 1 is the *trip count*
each trip runs ``may_goto``            it leaves the loop after some time or
                                       some number of trips
each trip takes from an iterator       an iterator has an end
none of these holds                    the verifier adds ``may_goto``
=====================================  =========================================

*may_goto* is a jump that is taken when the program has looped too long. The
verifier puts it before a jump that leaves the loop, or at the header. It
checks the new edge like any other edge::

  do {                          do {
          p = lookup();                 p = lookup();
  } while (!p);                         may_goto leave;
  use(p);                       } while (!p);
                                use(p);
                                ...
                                leave: return 0;

Where does the edge go? The verifier takes the first line that is possible:

- In the main function: ``return 0``, if nothing has to be released and 0 is a
  valid result.
- In another function: *unwind*, if nothing has to be released and each call has
  an ``unwind_goto`` after it. The function leaves with ``unwind_exit``, and
  ``unwind_goto`` jumps to the code of the caller that cleans up.
- The exit of the loop. The code there has to be safe. From a header the edge
  leaves the outer loops too. If the code there reads a register that is not
  set, the function returns 0.

A loop without an exit is an error.

A pass assumes what stops a loop
--------------------------------

At run time ``may_goto`` is there for all states. So a pass has to know at the
start which loops get it:

- Pass 0 does not know the trip counts. It checks the new edge in all loops.
  After a good pass the verifier drops each ``may_goto`` that no state needed.
- A later pass checks the edge only in the loops that needed it before.
- An iterator is assumed to stop its loop. It does not stop a loop that creates
  it in each trip, or a loop that goes on when no element is left.

If an assumption is wrong, the pass starts again, see ``pass_needs_restart()``.

Peeled trips and the leftover
-----------------------------

One state for all trips loses what differs between trips::

  x = 1;
  for (i = 0; i < 5; i++)
          x *= 2;
  big[x]                      x is 32, but the widened x has no bound

To *peel* a trip is to check it apart from the other trips. All trips that are
not peeled are the *leftover*::

  entry -> [0] -> [1] -> ... -> [d-1] -> +----------+ <--+
           peeled trips                  | LEFTOVER |    |
                                         | widened  |----+
                                         +----------+

Pass 0 peels nothing. A later pass peels if an error asks for it. Peeling stops
when the loop exits, when a trip has nothing new in the deps, or when the budget
is used up. If all trips are peeled, no state closes a cycle, and the loop needs
nothing to stop it. If an earlier trip subsumes a peeled trip, the trip is
pruned, and the loop gets ``may_goto``.

Which loop has to be peeled? If the join at a header adds to an xreg of
data_deps, the state notes that loop. If an insn is unproven in the state later,
the noted loops are the *suspects*::

  for (i = 0; i < 8; i++)
          sum += i;           makes sum imprecise: suspect
  while (random())
          n++;                not a suspect, it is not peeled
  big[sum]                    unproven

Pass 0 has no deps, so it finds no suspect here. Pass 1 finds it, and pass 2
peels.

A state also notes a loop if it leaves by a ``may_goto`` that the verifier
added, or if it holds more after each trip.

What is held in a loop
----------------------

What is held has no join. A loop that acquires in each trip makes new states
without end. ``check_held_in_leftover()`` stops that: a reference that is in no
xreg is a leak, and the number of peeled trips limits the locks.

Functions
=========

==================  ===========================  ===============================
function            checked                      the caller gets
==================  ===========================  ===============================
global              for all arguments of its     a number
                    BTF prototype
static, on its own  once for each instance       the exit states of the instance
static, in frames   at each call, with the       the state at the exit
                    frames of the callers
==================  ===========================  ===============================

A function that is checked *on its own* has a state without the frames of its
callers. A static function is checked *in frames* if it can change what its
callers see: it gets a pointer to the stack, tests a pointer for the caller,
moves packet data, or releases what the caller holds. A callback is always in
frames. See ``func_is_on_its_own()``. If only the exit state shows such a
change, the call is checked again in frames. An error can ask for frames too,
see IN_FRAMES in `Partition`_.

Instances
---------

18 levels with 2 calls each are 2^18 call chains. To check a function on its
own avoids that. The states of two calls meet only at the first insn of the
function. An *instance* is an entry state, its exit states and the calls that
wait for them. It is a function summary for one entry state.

Callers run first, so that calls collect at the first insn. The function runs
when a call has no exit state to continue with. Here two calls are on two
branches, and both arrive before f starts::

  call1 f(7)   --+
  call2 f(any) --+--> first insn

  in pass 0                one instance, both calls get "any"
  if r1 is in data_deps    two instances, call1 gets 7

At the first insn one xreg of data_deps that differs is sufficient to keep
the calls apart.

An instance that has started does not grow. If a call comes later, the join
starts a new instance::

  call1 f(0)   instance 1: f(0)      exits 1 --> call1
  call2 f(1)   instance 2: f(0..1)   exits 1 --> call2 at once
                                     exits 2 --> call2 later, if they have more

Instance 2 subsumes instance 1, so exits 1 are a part of exits 2. They can add
values to call2. They cannot hide a value.

Instances can multiply too, so they have a budget. When a function has used its
part, the next calls are joined.

Calls that go around
--------------------

The calls of a callback and recursive calls go around like the body of a loop.
They use the same code: join, widen, peel.

==================  ============================  ==============================
kind                header                        what stops it
==================  ============================  ==============================
loop                the target of the back edge   trip count or ``may_goto``
callback            the call of the helper        the helper
recursion           the start of the function     a check at run time
==================  ============================  ==============================

A recursive function starts with ``may_goto`` and a test of the free stack. If
there is no room, it returns 0 or unwinds. The verifier checks that edge too.
A recursion in frames is not joined. It has to end in ``MAX_CALL_FRAMES``.

An async callback, for example of a timer, runs later. It starts as a new state
with an empty stack. ``callx`` is checked as a call of each function that the
register can hold. ``bpf_throw()`` ends the program from any frame, so nothing
can be held there.

After an error
==============

If an insn is unproven, the state can have values that no path has. The
verifier has two tools:

============  =================  ===============================================
tool          when               what
============  =================  ===============================================
partition     after the pass     keep more states apart in the next pass
failing path  after a partition  if the error is real: limit the passes, log it
============  =================  ===============================================

Partition
---------

A *partition* keeps more states apart in the next pass. Abstract interpretation
calls this trace partitioning. More precision costs more. So
``bpf_partition_more()`` takes the cheap steps first. It takes the first line of
this list that adds something.

ADD_DEPS
  Add the deps of the unproven insns. If the insn reads an unreadable xreg,
  keep only the types apart first.

PEEL
  Peel the suspects. If the last trip is known: all trips. Else one trip, then
  as many as the budget pays for. The first trip is often different::

    off = 255; ok = 0;
    while (...) { if (ok) big[off]; off = x & 63; ok = x | 1; }

PEELED_APART
  States that start the same peeled trip are joined. Now the join rule applies
  there too::

    for (i = 0; i < 7; i++) { if (x) a++; else b++; big[a * a + b * b]; }

TRANSITIVE_DEPS
  A jump can decide which value an xreg of data_deps gets. Add control_deps to
  data_deps, and add the jumps that can skip a write to data_deps. Each such
  partition goes one level further::

    ok = i <= 7; ... off = 0; if (ok) off = i; buf[off];

DISJOINT_APART
  Values in data_deps without a common number stay apart, also without a gap::

    d = x ? 2 : 3; buf[6 / d * d + 1];

LOOP_DISJOINT_APART
  The same in a suspect, also at the header of the leftover. It is for an xreg
  that has few values in a long loop. It replaces peeling::

    while (...) { if (n * n < 49) n++; if (x) n = 0; buf[n]; }

PEEL_MORE
  If PEEL was too costly, or if it stopped at a pruned trip, peel a fixed number
  of trips, more in each pass. Do not prune them.

IN_FRAMES
  On its own a function does not get the equations of its arguments. If such an
  argument is in the deps and the function is not recursive, check the call in
  frames. That can multiply the work, so this line is the last one::

    if (!ok(x)) return 0; buf[x];

After an error two insns can *fork* a state: the insn is checked once for each
part of the values of an operand, and the states meet at the next insn.

- ``x u>= 3`` leaves -4..-1 and 3 of the range -4..3, and one range cannot show
  the gap. If x is in the deps, ``cut_range()`` does the jump once for -4..-1
  and once for 0..3.
- A load from the stack with many offsets makes a number of a spilled pointer.
  If an insn needed a pointer and got that number, ``fork_stack_load()`` does
  the load once for each slot::

    char *p[2] = { a, b };
    bpf_for(i, 0, 2) sum += p[i][63];

A partition can be the wrong one. To peel a loop of 100000 trips does not help
if the error needs control_deps. So each partition but ADD_DEPS has a budget,
and is undone if the pass is over it::

            +-----------------+   in the budget     -> keep for now
       +--->| partition, pass |-- it helped         -> keep for good
       |    +--------+--------+
       |             | over the budget
       |             v
       +--- undo, take the next line
       |             | no line left, one was too costly
       |             v
       +--- a larger budget, undo all since a partition helped

A partition *helped* if the first unproven insn of the last pass has no error
now, and no old error came back, see ``partition_helped()``::

  for (i = 0; i < 8; i++) sum += i;
  big[sum]                                              A
  ok = x <= 7; off = 0; if (ok) off = x;
  big[off]                                              B

  pass   partition          A          B
  0      -                  unproven   unproven
  1      ADD_DEPS           unproven   unproven
  2      PEEL               proven     unproven         PEEL helped
  3      TRANSITIVE_DEPS    proven     proven

If a partition was too costly for a loop, a later one is a second choice. It is
undone when the budget grows, also if it helped.

A pass can cost what a pass cost before, plus the budget. The suspects divide
a part of it. The first budget grows with the cost of a pass, and it is at least
``BPF_MIN_BUDGET``.

The failing path
----------------

After a join a pass cannot tell a real error from a false one. If the error is
real, more passes are wasted work, and the log of a joined state does not show
the bug. So ``find_failing_path()`` tries to reproduce the error with no joins.
It checks one path after another until the check of an unproven insn fails. This
is a *path-sensitive run*. The path on which the check fails is the *failing
path*. It has two uses:

- The program is probably wrong, so the next passes get a small budget. A path
  with a guess is the exception, see below.
- The log shows this path, from the first insn to the error.

If there is no failing path, the passes continue with the same limit.

The example with ``i > 8``::

  insns       r6       r7
  0 1 2 3     any      0      both edges are possible
  3 -> 4      9..max   0      waits
  3 -> 5      0..8     0      goes first, it is nearer to insn 9
  5 6 7 9     0..8     0
  10          0..8     0      r1 = buf + 0..8: buf[8] fails

The failing path is 0 1 2 3 5 6 7 9 10. The check of insn 9 does not fail now.
Insn 10 reads the result of insn 9, so it was unproven in pass 0 too.

The run has the same checks as a pass, and other rules:

- There are no joins. Each call is in frames. Each trip is peeled.
- It goes depth first. The edge with the shortest way to an unproven insn goes
  first.
- A state is dropped if a state with the same values in the deps was at the
  insn.
- If only the jump on the iv depends on the xregs that moved in a trip, and all
  other live xregs are the same, the path skips trips.
- If a loop does not end, the path continues where ``may_goto`` leaves it.

The path can end only at an unproven insn of the last pass. This includes an
insn that was unproven because of another one. An error at any other insn drops
the path.

The run needs the deps, so it comes after the partition. It starts when there
is something new: after ADD_DEPS, after a partition helped, after the budget
grew, and before the final reject. It does not start again when there is a
failing path.

Three guesses of the run can make a path that the program cannot take. If such
a path cuts the budget, a valid program can be rejected. So a path of such a
run, a *path with a guess*, goes to the log, but the budget is not cut. If a
pass has a real error, the log has that error.

The first guess is the skip. Two trips show a step also for an xreg that has no
constant step::

  for (i = 0; i < 1000; i++) sum += i;
  buf[sum - 499500]                        valid, this is buf[0]

  trip   i      sum    real sum
  2      2      1      1          saved
  3      3      3      3
  4      4      6      6          since trip 2: i +2, sum +5; 996 trips left
  skip   998    2491   497503     497 times: (996 - 1) / 2
  999    999    3489   498501
  exit   1000   4488   499500     buf[-495012] fails

``bpf_steps_are_constant()`` looks at the xregs that the skip moves, and at the
operands of the jump on the iv. One "yes" makes the skip a guess:

==================================  =============================  =====
if the loop writes the xreg with    example                        guess
==================================  =============================  =====
an add of an immediate              ``i += 1``                     no
a copy of an xreg with equal step   ``x = (u32)i``                 no
what a pass found linear            a spilled iv                   no
anything else                       ``sum += i``, ``i < n / i``    yes
==================================  =============================  =====

The second guess is "the loop is infinite". Two trips give more than 2^32 trips
also for a ring index. The same function finds it::

  u64 i = 600; do { i = (i + 1) & 1023; } while (i != 88);

  the jump sees   601, 602                step 1, 2^64 - 514 trips left
  real            601 .. 1023, 0 .. 88    512 trips

The next runs keep this answer. So it is also a guess if the run made a guess
before it.

The third guess is the target of ``may_goto``. All states have the same one::

  large = x > 7;
  while (...) {
          if (large && x <= 7) lock();        only a join gets here
          do { p = lookup(); } while (!p);    gets may_goto
          *p
  }

With no lock the target is ``return 0``. The joined state gets to ``lock()``, so
the pass selects the code after the loop. A path with no lock goes there too,
and ``*p`` fails.

The run accepts nothing: it drops states and skips trips. It is not the verdict
either: a path has ranges too, and it can fail at an insn that a pass proves.

All passes
----------

``do_check_all()`` puts the parts together::

          pass 0: join all numbers
                    |
    +---------> run a pass
    |               |
    |            error ? --- no ---> pessimized ? --- no ---> ACCEPT
    |               | yes                 | yes
    |               v                     v
    |       good pass before ?      save the good pass,
    |          | no      | yes      partition, cut the budget
    |          |         v                |
    |          |   ACCEPT, use that pass  +---> run a pass
    |          v
    |      partition
    |          |
    |  failing path ? --- yes ---> log it; if no guess, cut the budget
    |          | no                       |
    |          +<-------------------------+
    |          v
    +- yes - is more kept apart ? --- no ---> REJECT

The last answer is no in three cases:

- Nothing made the pass imprecise before its first error. The error is real.
- No partition adds something.
- The budget is used up.

A pass that is over the limit of the load ends it too. The next chapter explains
"pessimized".

The example, and the same program with ``i > 8``::

                 i > 7                   i > 8
  pass 0         insn 9 is unproven      insn 9 is unproven
  partition      ADD_DEPS                ADD_DEPS
  failing path   none                    0 1 2 3 5 6 7 9 10: buf[8]
  pass 1         no error                insn 10 is unproven
  result         ACCEPT                  REJECT, the log has the failing path

What a pass leaves behind
=========================

Fixups
------

After the last pass the verifier rewrites the program. A load from the context
gets the real offset. A load through an untrusted pointer gets a fault handler.
``bpf_obj_drop()`` gets the fields of the type. A pass notes what the rewrite
needs: these notes are the *fixups*.

An insn has one fixup for all states. If two states need two fixups, the
verifier takes one that fits both: no inlining, a fault handler. If there is
none, the insn is unproven. If both states are real, no pass can prove it, and
the program is rejected::

  if (...) p = a; else p = b;     a has a kptr, b has none
  bpf_obj_drop(p);                unproven: one call, two types

A pass can write a fixup on a path that only a join makes. The next pass must
not see it. A *snapshot* is a copy of the fixups and of the bounds that a pass
writes to the program. Each pass starts from the snapshot that was taken before
pass 0.

What a pass learns about loops is not in a snapshot. The next pass gets it as a
guess.

``check_after_pass()`` checks what holds for the program as a whole, such as the
depth of the stack over all call chains. Its error is handled like an unproven
insn.

Pessimized insns
----------------

A good pass can still ask for too much::

  (off, len) = (0, 64) or (56, 8)      each path needs 64 bytes of the context
  join: off = 0..56, len = 8..64       the pass asks for 120 bytes

Such a bound is checked when the program is attached or run. The insn that
raised it is *pessimized* if the pass is imprecise and an operand has a range.
An insn that gets a barrier (next chapter) in an imprecise pass is pessimized
too. The verifier saves the good pass in a second snapshot, and partitions more
in a small budget. If a later pass has an error, the saved pass is the result.

Dead code
---------

An insn that no state got to is dead. A jump with a dead edge becomes a goto,
and the dead insns are removed. Without ``CAP_BPF`` they are replaced by
``goto -1``. If both edges of a jump are dead, no run gets to the jump. It
becomes ``goto -1``.

Only a conditional jump can lose an edge. So an infeasible state ends only
after such a jump.

Offload
-------

The driver of an offloaded program sees each insn with its state, and cannot
forget. So it sees only a pass without errors: that pass runs once more for the
driver, after ``prepare()``. An insn that the driver refuses is unproven. If a
later pass has no error, the driver gets ``destroy()``, ``prepare()`` and that
pass. What it noted in a map stays. An offloaded program gets no ``may_goto``
and no rewrite of fastcall patterns.

Speculation and privileges
==========================

The cpu can run code after a jump before it knows the result of the jump. What
such code loads can leak through the cache::

  if (i > 7) goto out;        the cpu predicts "not taken" for i = 1000
  x = buf[i];                 reads out of bounds

Without ``CAP_PERFMON`` the verifier prevents that, unless the mitigations are
off or the cpu does not need them:

==========================  ====================================================
``pointer += number``       The number gets a mask that cuts it to the object.
                            If no mask fits all states, the insn gets a
                            *barrier*: ``nospec`` stops speculation.
a jump that values decide   The dead edge is checked too, as a *speculative*
                            state.
an error in such a state    It is no error. The insn gets a barrier.
a store to the stack        A barrier follows if a later load could see an old
                            value that matters.
==========================  ====================================================

A barrier has to stop each edge that leads to the insn::

  fall-through, jump, call, return     barrier before the insn
  exit of a callback --> helper        barrier at the exit
  may_goto --> r0 = 0; exit            barrier before r0 = 0
  call --> recursion in frames         barrier at the call
  return --> dead code                 goto -1 replaces the code

A speculative state is joined only with speculative states, and it subsumes
only speculative states.

Some mechanisms depend on a capability. The last line is there because the cpu
can go past the jump that a proof needs:

=================================  =============================================
``CAP_BPF``                        loops, calls of functions, equations, numbers
                                   in stack slots, 1M insns (else 4096), the
                                   full `Limits`_
``CAP_PERFMON``                    trip count, reads of stack that is not
                                   written, pointers as numbers, access to BTF
                                   objects, arena
``CAP_PERFMON`` or no mitigations  equations of pointers, equations that a join
                                   makes from constants, the end of infeasible
                                   states, skipped first trips, stack access
                                   with many offsets, pointers out of the object
=================================  =============================================

Without a trip count a loop gets ``may_goto``, or it is peeled.

Limits
======

There is no limit on the number of states or of checked insns. There are two
limits for the full load:

======  ========================================================================
cost    ``BPF_MAX_COST``. Each kind of work has a weight, see ``BPF_COST_SCAN``.
memory  ``BPF_MAX_MEM``. It counts the states and the large tables. The passes
        of a small program get less, see ``BPF_PASS_MEM_BASE``.
======  ========================================================================

Both limits are smaller without ``CAP_BPF``. If a load is over a limit, the log
shows both limits.

Cost counts work, not time. So the verdict does not depend on the speed or the
load of the machine.

A program that no precision can prove must not use up the limit on cost. So the
verifier cuts what is left after the first error. It cuts more after a failing
path with no guess, and after a good pass with a pessimized insn.

Other limits:

=======================  =======================================================
``MAX_CALL_FRAMES``      32 frames in a state
``BPF_ID_MAP_SIZE``      less than 9152 ids in a state
``LOOP_STACK_SIZE``      16 nested loops in a function
``MAX_BPF_STACK``        512 bytes of stack; 2048 if the JIT supports it
``BPF_MAX_VAR_OFF``      a pointer that can be 2^29 away gives no access without
                         a fault handler
``BPF_MAX_TRIPS``        a loop gets ``may_goto`` if k can be above 2^32
=======================  =======================================================

What is trusted
===============

A bug in trusted code can accept an unsafe program. A bug in a guess cannot.

The table has the guesses and what checks them. All other code is trusted.

========================  ======================================================
guess                     check
========================  ======================================================
what is kept apart        none is needed: a join and two states are both proofs
sym of a difference       none is needed: a state without it has more values
equations of a join       ``check_equations()`` in both states
threshold                 the state that comes back has to be subsumed
first trips               they are joined with the entry; then the same check
what stops a loop         ``pass_needs_restart()``
trip count                the trip index of each state that closes a cycle
path-sensitive run        none is needed: it accepts nothing
========================  ======================================================

The log
=======

=====  =========================================================================
level  content
=====  =========================================================================
1      the failing path; if there is none, or if it has a guess and a pass has a
       real error: the basic block of an error
2      the analyses of the code, all passes and path-sensitive runs
4      time, stack depth and insns of each function
=====  =========================================================================

In level 1 the later passes and the path-sensitive runs have no log. The one
that gives the log runs once more. That work is not in the limit on cost. It
costs at most as much as the work before it.

A line has the insn and the registers that it reads or changes::

  9: (0f) r1 += r6     ; R1=map_value(map=.data.buf,ks=4,vs=8,smin=0,smax=8,...)
  10: (71) r0 = *(u8 *)(r1 +0)
  invalid access to map value, value_size=8 off=8 size=1
  R1 max value is outside of the allowed memory range

  Verification failed: Memory Safety: Access outside bounds
  ...

Most errors have a report: the reason, the source line, the insns that made the
value, and a suggestion. An error that does not end the path gets no report:

- an error in a speculative state,
- an argument that does not fit the BTF of a static function.

In level 2 each pass and each path-sensitive run has its report.

Other lines
-----------

Most of these lines are only in level 2.

=====================================  =========================================
text                                   meaning
=====================================  =========================================
``pass 1``                             a new pass starts
``path-sensitive run after pass 0``    see `The failing path`_
``from 4 to 5: R6=...``                the state at the start of a basic block
``from 5 to 6: pruned``                another state subsumes it
``from 3 to 7: joined``                it is joined with another state
``from 8 to 2: widened``               the same, at the header of a leftover
``(speculative execution)``            a speculative state
``loop_stack=3``                       in the loop with header 3
``iter(3)=1``                          in peeled trip 1 of that loop
``0:r7=8*sym0+0 sym0=[0,+7]``          frame 0: r7 = 8 * sym0; sym0 is 0..0+7
``0:trip0=1*sym0+0``                   the trip index of the first loop
``sym2=1*sym0-1*sym1+4``               a sum: sym2 = sym0 - sym1 + 4
``sym3=insn5(1*sym2+0,248)``           an op: what insn 5 makes of sym2 and 248
``loop at 3 has trip count 8``         no ``may_goto`` is needed
``loop at 0 has no trip count``        the loop gets ``may_goto``
``call at 1 waits for func#1``         the function is checked on its own
``fork R1``                            the load is checked once for each slot
=====================================  =========================================

Common errors
-------------

``unreachable insn 2``
  No path gets to the insn.

``R2 !read_ok``
  The register was not written, a call clobbered it, or it has two types on two
  paths.

``R1 invalid mem access 'scalar'``
  A number is used as a pointer.

``R0 invalid mem access 'map_value_or_null'``
  Test the pointer for NULL first.

``invalid access to map value, value_size=8 off=8 size=1``
  The largest offset is out of the value. Test the index.

``math between map_value pointer and register with unbounded min value is not allowed``
  The number that is added has no lower bound.

``invalid access to packet, off=12 size=2, R2(id=0,off=12,r=0)``
  Compare the pointer with ``data_end`` first.

``invalid write to stack R10 off=8 size=8``
  The stack is below r10.

``misaligned stack access off 0+-12 size 8``
  An access to the stack has to be aligned to its size.

``invalid read from stack R10 off=-8 size=8``, ``invalid read from stack off -8+0 size 8``
  The bytes were not written.

``invalid bpf_context access off=1000 size=8``
  The program type does not allow this field.

``Unreleased reference id=5 alloc_insn=4``
  A path does not release what insn 4 acquired.

``loop at insn 2 never exits``
  The loop has no edge that leaves it.

``BPF program is too complex``, ``the limit on cost or memory ended pass 6``
  The load is over a limit. If a pass had an error before, the log has that
  error, or a path with a guess. That path can be false.

Words
=====

==================  ============================================================
barrier             the ``nospec`` insn, it stops speculative execution
basic block         a run of insns without a jump into it or out of it
budget              a limit on the cost of one step
checked             the bytes of a packet that are known to be before its end
control_deps        xregs whose value flows to a jump that can skip an unproven
                    insn
correlated          two branches: one tests a result that the other one stored
cost                the work that is done
data_deps           xregs whose value flows into an operand of an unproven insn
deps                data_deps and control_deps
entry               a state that enters a loop
equation            how two or three numbers are related
failing path        a path without joins on which the check of an unproven insn
                    fails; it is the result of a path-sensitive run
fixpoint            the state at a header subsumes all states that come back
fixups              what a pass notes for the rewrite of the program
fork                check an insn once for each part of the values of an operand
gap                 a value of a join that is in neither state
good pass           a pass without errors
guess               a choice that can be wrong and cannot accept an unsafe
                    program
header              the insn where each trip of a loop starts
held                references, locks, dynptrs, iterators, irq flags
helped              after a partition the first unproven insn of the last pass
                    has no error, and no old error came back
id                  the name of a set of xregs that hold copies of one pointer
imprecise           a state of the pass possibly has values that no path has
in frames           a function is checked with the frames of its callers
infeasible          no run of the program has the state
insn                an instruction
instance            an entry state of a function, its exit states and its calls
iv                  induction variable: each trip adds a constant to it
join                two states become one that has the values of both
join point          an insn where states can meet
join_key            what has no join: states with two join_keys never meet
leftover            all trips that are not peeled
live                read later, before it is written
may_goto            a jump that is taken when the program has looped too long
on its own          a function is checked without the frames of its callers
partition           keep more states apart in the next pass
pass                one run of the main analysis over all functions
path with a guess   the failing path of a run that made a guess; it can be false
path-sensitive run  a search for a failing path, one path after another
peel                check a trip apart from the other trips
pessimized          proven, but a join possibly raised a bound
precision           what a pass keeps apart
proven              an insn whose check did not fail in a state of the pass
prune               drop a state that another state subsumes
refine              remove values that a jump excludes
seed                an insn whose reads start the backward slice
snapshot            a copy of the fixups and bounds that a pass writes
speculative         the cpu can have the state only after a wrong prediction
spill               a store of a register to a stack slot
state               what each xreg can hold before an insn
step                all values of a number are ``base + step * k``; in a loop:
                    what one trip adds
stored condition    an xreg that stores the result of a test
subsumes            has all values of another state
suspect             a loop that made an xreg of data_deps imprecise
sym                 a number that equations use
threshold           a value at which a range that grows can stop
trip                one iteration of a loop
trip count          the largest trip index + 1
trip index          how many times the program came back to the header
unproven            an insn or a part whose check failed in a state of the pass
unreadable          an xreg without a value: an insn that reads it is unproven
unwind              leave a function with ``unwind_exit``
walk                one check of the body of a loop
widen               move a bound that grows to a threshold
xreg                a register, a stack slot or the trip index of a loop
==================  ============================================================
