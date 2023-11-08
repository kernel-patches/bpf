#!/usr/bin/env python3
from z3 import *
from wrange import *


def wrange_add(a: Wrange, b: Wrange):
    wrange_class = type(a)
    assert(a.SIZE == b.SIZE)

    new_length = a.length + b.length
    too_wide = Or(ULT(new_length, a.length), ULT(new_length, b.length))
    new_start = If(too_wide, BitVecVal(0, a.SIZE), a.start + b.start)
    new_end = If(too_wide, BitVecVal(2**a.SIZE-1, a.SIZE), a.end + b.end)
    return wrange_class(f'{a.name} + {b.name}', new_start, new_end)


def main():
    x = BitVec32('x')
    w = wrange_add(
        # {1, 2, 3}
        Wrange32('w1', start=BitVecVal32(1), end=BitVecVal32(3)),
        # + {0}
        Wrange32('w2', start=BitVecVal32(0), end=BitVecVal32(0)),
    )   # = {1, 2, 3}
    print('Checking {1, 2, 3} + {0} = {1, 2, 3}')
    prove(               # 1 <= x <= 3
        w.contains(x) == And(BitVecVal32(1) <= x, x <= BitVecVal32(3)),
    )

    w = wrange_add(
        # {-1}
        Wrange32('w1', start=BitVecVal32(-1), end=BitVecVal32(-1)),
        # + {0, 1, 2}
        Wrange32('w2', start=BitVecVal32(0), end=BitVecVal32(2)),
    )   # = {-1, 0, 1}
    print('\nChecking {-1} + {0, 1, 2} = {-1, 0, 1}')
    prove(               # -1 <= x <= 1
        w.contains(x) == And(BitVecVal32(-1) <= x, x <= BitVecVal32(1)),
    )

    # A general check to make sure wrange_add() is sound
    x = BitVec32('x')
    y = BitVec32('y')
    w1 = Wrange32('w1')
    w2 = Wrange32('w2')
    w = wrange_add(w1, w2)
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
    # The sum of w1 and w2 calculated from wrange_add(w1, w2), called w, should
    # _always_ contains the sum of x and y, no matter what.
    print('\nChecking that if w1.contains(x) and w2.contains(y), then wrange32_add(w1, w2).contains(x+y)')
    print('(note: this may take awhile)')
    prove(
        Implies(
            premise,
            And(
                w.contains(x + y),
                w.wellformed(),
            ),
        )
    )


if __name__ == '__main__':
    main()
