#!/usr/bin/env python3
#
# A proof on the property of tnum_in(tnum_range(a, b), ...) using the Z3
# theorem prover
#
# Requires the z3 Python module (aka Z3Py), which can be installed with the
# command `pip3 install z3-solver`
#
from uuid import uuid4
from z3 import And, BitVec, BitVecs, BitVecVal, Extract, If, Implies, Or, ULE, UGT, ZeroExt, prove


class Tnum:
    """A model of tristate number use in Linux kernel's BPF verifier.

    Largely based on the "Sound, Precise, and Fast Abstract Interpretation with
    Tristate Numbers" paper <https://arxiv.org/abs/2105.05398>.
    """
    SIZE = 64
    def __init__(self, val=None, mask=None):
        uid = uuid4() # Ensure that the BitVec are uniq, required by the Z3 solver
        self.val = BitVec(f'Tnum-val-{uid}', bv=Tnum.SIZE) if val is None else val
        self.mask = BitVec(f'Tnum-mask-{uid}', bv=Tnum.SIZE) if mask is None else mask

    def contains(self, bitvec):
        # Mask out the unknown bits, if what left is that same as value, then
        # this that integer is represented by this tnum
        return (~self.mask & bitvec) == self.val

    def wellformed(self):
        # Bit cannot be set in both val and mask, such tnum is not valid
        return self.val & self.mask == BitVecVal(0, bv=Tnum.SIZE)


def is_power_of_2(n):
    return And(n != 0, n & (n-1) == 0)


def fls64(bv):
    size = Tnum.SIZE
    num = BitVecVal(0, bv=Tnum.SIZE)
    while size > 1:
        half_size = size // 2
        h = Extract(size - 1, half_size, bv)
        bv = If(
            h != 0,
            h,
            Extract(half_size - 1, 0, bv),
        )
        num += If(h != 0, BitVecVal(half_size, bv=Tnum.SIZE), BitVecVal(0, bv=Tnum.SIZE))
        size = half_size

    assert(size == 1) # Size is now 1
    num += If(bv != 0, BitVecVal(1, bv=Tnum.SIZE), BitVecVal(0, bv=Tnum.SIZE))
    return num


def tnum_range(min_, max_): # Don't shadow built-in min & max
    """tnum_range() implementation modeling what's found in the Linux Kernel"""
    chi = min_ ^ max_
    bits = fls64(chi)
    delta = (BitVecVal(1, bv=Tnum.SIZE) << bits) - 1
    too_large = UGT(bits, BitVecVal(Tnum.SIZE - 1, bv=Tnum.SIZE))

    val = If(
        too_large,
        BitVecVal(0, bv=Tnum.SIZE),
        min_ & ~delta,
    )
    mask = If(
        too_large,
        BitVecVal(-1, bv=Tnum.SIZE),
        delta,
    )
    return Tnum(val=val, mask=mask)


def tnum_in(a, b):
    """tnum_in() implementation modeling what's found in the Linux Kernel"""
    return If(
        (b.mask & ~a.mask) != 0,
        False,
        a.val == (b.val & ~a.mask),
    )


# a, b, and x are integers which could be of any value
a, b, x = BitVecs('a b x', bv=Tnum.SIZE)
assumptions = []

t = tnum_range(a, b) # Any possible range we could get out of tnum_range()
assumptions += [
    ULE(a, b), # a <= b
]

st = Tnum() # The second argument can be any tnum
assumptions += [
    st.wellformed(), # As long as it is a valid one
    st.contains(x), # And contains the number x (that could be any integers)
]

condition = [
    # When tnum_in() returns true
    tnum_in(t, st) == True,
]

print("""\
Trying to proof that tnum_in(tnum_range(a,b), ...) can always be trusted when
it returns true...
""")
prove(
    Implies(
        # When using tnum_in(tnum_range(a, b), ...)
        And(assumptions + condition),
        # Try to prove that we can always trust it when it returns true
        # That is, all number that the second argument can represent (i.e. x) is
        # inclusively between a and b
        And(ULE(a, x), ULE(x, b)),
    )
)
print("")

# Additional constrains, namely that the first argument need to be in the form of either
#   tnum_const()
# or
#   tnum_range(0, 2**n - 1)
# or
#   tnum_range(2**n, 2**(n+1) - 1)
additional_assumptions = [
    Or(
        a == b, # since a == b, tnum_range(a, b) == tnum_const()
        And(a == 0, is_power_of_2(b + 1)), # b is 2**n - 1
        And(is_power_of_2(a), b == (a << 1) - 1) # a is 2**n and b is 2**(n+1) - 1
    ),
]

print("""\
Trying to proof that tnum_in(tnum_range(a,b), ...) can always be trusted when
it returns true, again, but with constrains on a and b, namely the first
argument of tnum_in() must be in one of the following forms:
- tnum_in(tnum_const(), ...)
- tnum_in(tnum_range(0, 2**n - 1), ...)
- tnum_in(tnum_range(2**n, 2**(n+1) - 1), ...)
""")
prove(
    Implies(
        # When tnum_in() is used in the form of
        #   tnum_in(tnum_const(), ...)
        # or
        #   tnum_in(tnum_range(0, 2**n - 1), ...)
        # or
        #   tnum_in(tnum_range(2**n, 2**(n+1) - 1), ...)
        And(assumptions + additional_assumptions + condition),
        # Try to prove that we can always trust it when it returns true when the additional
        # contrains above is inplace
        And(ULE(a, x), ULE(x, b)),
    )
)
