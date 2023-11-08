#!/usr/bin/env python3
from z3 import *
from wrange import *


# This could be further improved if needed
def wrange_mul(a: Wrange, b: Wrange):
    wrange_class = type(a)
    assert(a.SIZE == b.SIZE)

    too_large = Or(UGT(a.end, BitVecVal(2**(a.SIZE/2)-1, bv=a.SIZE)), UGT(b.end, BitVecVal(2**(b.SIZE/2)-1, bv=b.SIZE)))
    negative = Or(a.smin < 0, b.smin < 0)
    giveup = Or(too_large, negative)
    new_start = If(giveup, BitVecVal(0, a.SIZE), a.start * b.start)
    new_end = If(giveup, BitVecVal(-1, a.SIZE), a.end * b.end)
    return wrange_class(f'{a.name} * {b.name}', new_start, new_end)


def main():
    x = BitVec32('x')
    w = wrange_mul(
        # {1, 2, 3}
        Wrange32('w1', start=BitVecVal32(1), end=BitVecVal32(3)),
        # - {0}
        Wrange32('w2', start=BitVecVal32(0), end=BitVecVal32(0)),
    )   # = {0}
    print('Checking {1, 2, 3} * {0} = {0}')
    prove(               #x can only be 0
        w.contains(x) == (x == BitVecVal32(0))
    )

    w = wrange_mul(
        # {0xfff0..0xffff}
        Wrange32('w1', start=BitVecVal32(0xff0), end=BitVecVal32(0xfff)),
        # - {0xf0..0xff}
        Wrange32('w2', start=BitVecVal32(0xf0), end=BitVecVal32(0xff)),
    )   # = {0xeff100..0xfeff01}
    print('Checking {0xff0..0xfff} * {0xf0..0xff} = {0xef100..0xfef01}')
    prove(               # 0xef100 <= x <= 0xfef01
        w.contains(x) == And(ULE(BitVecVal32(0xef100), x), ULE(x, BitVecVal32(0xfef01)))
    )

    # Multiplication is not implemented when there's negative number, but it
    # could be made to work
    w = wrange_mul(
        # {-1}
        Wrange32('w1', start=BitVecVal32(-1), end=BitVecVal32(-1)),
        # * {0, 1, 2}
        Wrange32('w2', start=BitVecVal32(0), end=BitVecVal32(2)),
    )   # = {-2, -1, 0}
    print('\nChecking {-1} * {0, 1, 2} = {S32_MIN..S32_MAX}')
    prove(
        w.contains(x) == BoolVal(True),
    )

    # A general check to make sure wrange_mul() is sound
    w1 = Wrange32('w1')
    w2 = Wrange32('w2')
    w = wrange_mul(w1, w2)
    x = BitVec32('x')
    y = BitVec32('y')
    premise = And(
        w1.wellformed(),
        w2.wellformed(),
        w1.contains(x),
        w2.contains(y),
    )
    # Suppose we have a wrange32 called w1 that contains the 32-bit integer x
    # (where x can be any possible value contained inside w1), and another
    # wrange32 called w2 that similarly contains 32-bit integer y.
    #
    # The product of w1 and w2 calculated from wrange32_mul(w1, w2), called w,
    # should _always_ contains the product of x and y, no matter what.
    print('\nChecking that if w1.contains(x) and w2.contains(y), then wrange32_mul(w1, w2).contains(x*y)')
    print('(note: this takes a very, very, long time to run)')
    prove(
        Implies(
            premise,
            And(
                w.contains(x * y),
                w.wellformed(),
            ),
        )
    )

if __name__ == '__main__':
    main()
