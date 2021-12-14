
====================
eBPF Instruction Set
====================

Registers and calling convention
================================

eBPF has 10 general purpose registers and a read-only frame pointer register,
all of which are 64-bits wide.

The eBPF calling convention is defined as:

 * R0: return value from function calls, and exit value for eBPF programs
 * R1 - R5: arguments for function calls
 * R6 - R9: callee saved registers that function calls will preserve
 * R10: read-only frame pointer to access stack

R0 - R5 are scratch registers and eBPF programs needs to spill/fill them if
necessary across calls.

eBPF opcode encoding
====================

eBPF is reusing most of the opcode encoding from classic to simplify conversion
of classic BPF to eBPF. For arithmetic and jump instructions the 8-bit 'code'
field is divided into three parts::

  +----------------+--------+--------------------+
  |   4 bits       |  1 bit |   3 bits           |
  | operation code | source | instruction class  |
  +----------------+--------+--------------------+
  (MSB)                                      (LSB)

Three LSB bits store instruction class which is one of:

  ===================     ===============
  Classic BPF classes     eBPF classes
  ===================     ===============
  BPF_LD    0x00          BPF_LD    0x00
  BPF_LDX   0x01          BPF_LDX   0x01
  BPF_ST    0x02          BPF_ST    0x02
  BPF_STX   0x03          BPF_STX   0x03
  BPF_ALU   0x04          BPF_ALU   0x04
  BPF_JMP   0x05          BPF_JMP   0x05
  BPF_RET   0x06          BPF_JMP32 0x06
  BPF_MISC  0x07          BPF_ALU64 0x07
  ===================     ===============

When BPF_CLASS(code) == BPF_ALU or BPF_JMP, 4th bit encodes source operand ...

    ::

	BPF_K     0x00
	BPF_X     0x08

 * in classic BPF, this means::

	BPF_SRC(code) == BPF_X - use register X as source operand
	BPF_SRC(code) == BPF_K - use 32-bit immediate as source operand

 * in eBPF, this means::

	BPF_SRC(code) == BPF_X - use 'src_reg' register as source operand
	BPF_SRC(code) == BPF_K - use 32-bit immediate as source operand

... and four MSB bits store operation code.

If BPF_CLASS(code) == BPF_ALU or BPF_ALU64 [ in eBPF ], BPF_OP(code) is one of::

  BPF_ADD   0x00
  BPF_SUB   0x10
  BPF_MUL   0x20
  BPF_DIV   0x30
  BPF_OR    0x40
  BPF_AND   0x50
  BPF_LSH   0x60
  BPF_RSH   0x70
  BPF_NEG   0x80
  BPF_MOD   0x90
  BPF_XOR   0xa0
  BPF_MOV   0xb0  /* eBPF only: mov reg to reg */
  BPF_ARSH  0xc0  /* eBPF only: sign extending shift right */
  BPF_END   0xd0  /* eBPF only: endianness conversion */

If BPF_CLASS(code) == BPF_JMP or BPF_JMP32 [ in eBPF ], BPF_OP(code) is one of::

  BPF_JA    0x00  /* BPF_JMP only */
  BPF_JEQ   0x10
  BPF_JGT   0x20
  BPF_JGE   0x30
  BPF_JSET  0x40
  BPF_JNE   0x50  /* eBPF only: jump != */
  BPF_JSGT  0x60  /* eBPF only: signed '>' */
  BPF_JSGE  0x70  /* eBPF only: signed '>=' */
  BPF_CALL  0x80  /* eBPF BPF_JMP only: function call */
  BPF_EXIT  0x90  /* eBPF BPF_JMP only: function return */
  BPF_JLT   0xa0  /* eBPF only: unsigned '<' */
  BPF_JLE   0xb0  /* eBPF only: unsigned '<=' */
  BPF_JSLT  0xc0  /* eBPF only: signed '<' */
  BPF_JSLE  0xd0  /* eBPF only: signed '<=' */

So BPF_ADD | BPF_X | BPF_ALU means 32-bit addition in both classic BPF
and eBPF. There are only two registers in classic BPF, so it means A += X.
In eBPF it means dst_reg = (u32) dst_reg + (u32) src_reg; similarly,
BPF_XOR | BPF_K | BPF_ALU means A ^= imm32 in classic BPF and analogous
src_reg = (u32) src_reg ^ (u32) imm32 in eBPF.

Classic BPF is using BPF_MISC class to represent A = X and X = A moves.
eBPF is using BPF_MOV | BPF_X | BPF_ALU code instead. Since there are no
BPF_MISC operations in eBPF, the class 7 is used as BPF_ALU64 to mean
exactly the same operations as BPF_ALU, but with 64-bit wide operands
instead. So BPF_ADD | BPF_X | BPF_ALU64 means 64-bit addition, i.e.:
dst_reg = dst_reg + src_reg

Classic BPF wastes the whole BPF_RET class to represent a single ``ret``
operation. Classic BPF_RET | BPF_K means copy imm32 into return register
and perform function exit. eBPF is modeled to match CPU, so BPF_JMP | BPF_EXIT
in eBPF means function exit only. The eBPF program needs to store return
value into register R0 before doing a BPF_EXIT. Class 6 in eBPF is used as
BPF_JMP32 to mean exactly the same operations as BPF_JMP, but with 32-bit wide
operands for the comparisons instead.

For load and store instructions the 8-bit 'code' field is divided as::

  +--------+--------+-------------------+
  | 3 bits | 2 bits |   3 bits          |
  |  mode  |  size  | instruction class |
  +--------+--------+-------------------+
  (MSB)                             (LSB)

Size modifier is one of ...

::

  BPF_W   0x00    /* word */
  BPF_H   0x08    /* half word */
  BPF_B   0x10    /* byte */
  BPF_DW  0x18    /* eBPF only, double word */

... which encodes size of load/store operation::

 B  - 1 byte
 H  - 2 byte
 W  - 4 byte
 DW - 8 byte (eBPF only)

Mode modifier is one of::

  BPF_IMM     0x00  /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
  BPF_ABS     0x20
  BPF_IND     0x40
  BPF_MEM     0x60
  BPF_LEN     0x80  /* classic BPF only, reserved in eBPF */
  BPF_MSH     0xa0  /* classic BPF only, reserved in eBPF */
  BPF_ATOMIC  0xc0  /* eBPF only, atomic operations */

eBPF has two non-generic instructions: (BPF_ABS | <size> | BPF_LD) and
(BPF_IND | <size> | BPF_LD) which are used to access packet data.

They had to be carried over from classic to have strong performance of
socket filters running in eBPF interpreter. These instructions can only
be used when interpreter context is a pointer to ``struct sk_buff`` and
have seven implicit operands. Register R6 is an implicit input that must
contain pointer to sk_buff. Register R0 is an implicit output which contains
the data fetched from the packet. Registers R1-R5 are scratch registers
and must not be used to store the data across BPF_ABS | BPF_LD or
BPF_IND | BPF_LD instructions.

These instructions have implicit program exit condition as well. When
eBPF program is trying to access the data beyond the packet boundary,
the interpreter will abort the execution of the program. JIT compilers
therefore must preserve this property. src_reg and imm32 fields are
explicit inputs to these instructions.

For example::

  BPF_IND | BPF_W | BPF_LD means:

    R0 = ntohl(*(u32 *) (((struct sk_buff *) R6)->data + src_reg + imm32))
    and R1 - R5 were scratched.

Unlike classic BPF instruction set, eBPF has generic load/store operations::

    BPF_MEM | <size> | BPF_STX:  *(size *) (dst_reg + off) = src_reg
    BPF_MEM | <size> | BPF_ST:   *(size *) (dst_reg + off) = imm32
    BPF_MEM | <size> | BPF_LDX:  dst_reg = *(size *) (src_reg + off)

Where size is one of: BPF_B or BPF_H or BPF_W or BPF_DW.

It also includes atomic operations, which use the immediate field for extra
encoding::

   .imm = BPF_ADD, .code = BPF_ATOMIC | BPF_W  | BPF_STX: lock xadd *(u32 *)(dst_reg + off16) += src_reg
   .imm = BPF_ADD, .code = BPF_ATOMIC | BPF_DW | BPF_STX: lock xadd *(u64 *)(dst_reg + off16) += src_reg

The basic atomic operations supported are::

    BPF_ADD
    BPF_AND
    BPF_OR
    BPF_XOR

Each having equivalent semantics with the ``BPF_ADD`` example, that is: the
memory location addresed by ``dst_reg + off`` is atomically modified, with
``src_reg`` as the other operand. If the ``BPF_FETCH`` flag is set in the
immediate, then these operations also overwrite ``src_reg`` with the
value that was in memory before it was modified.

The more special operations are::

    BPF_XCHG

This atomically exchanges ``src_reg`` with the value addressed by ``dst_reg +
off``. ::

    BPF_CMPXCHG

This atomically compares the value addressed by ``dst_reg + off`` with
``R0``. If they match it is replaced with ``src_reg``. In either case, the
value that was there before is zero-extended and loaded back to ``R0``.

Note that 1 and 2 byte atomic operations are not supported.

Clang can generate atomic instructions by default when ``-mcpu=v3`` is
enabled. If a lower version for ``-mcpu`` is set, the only atomic instruction
Clang can generate is ``BPF_ADD`` *without* ``BPF_FETCH``. If you need to enable
the atomics features, while keeping a lower ``-mcpu`` version, you can use
``-Xclang -target-feature -Xclang +alu32``.

You may encounter ``BPF_XADD`` - this is a legacy name for ``BPF_ATOMIC``,
referring to the exclusive-add operation encoded when the immediate field is
zero.

eBPF has one 16-byte instruction: ``BPF_LD | BPF_DW | BPF_IMM`` which consists
of two consecutive ``struct bpf_insn`` 8-byte blocks and interpreted as single
instruction that loads 64-bit immediate value into a dst_reg.
Classic BPF has similar instruction: ``BPF_LD | BPF_W | BPF_IMM`` which loads
32-bit immediate value into a register.
