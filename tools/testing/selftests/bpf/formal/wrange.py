#!/usr/bin/env python3
import abc
from z3 import *


# Helpers
BitVec32 = lambda n: BitVec(n, bv=32)
BitVecVal32 = lambda v: BitVecVal(v, bv=32)

class Wrange(abc.ABC):
    SIZE = None # Bitwidth, this will be defined in the subclass
    name: str
    start: BitVecRef
    end: BitVecRef

    def __init__(self, name, start=None, end=None):
        self.name = name
        self.start = BitVec(f'Wrange32-{name}-start', bv=self.SIZE) if start is None else start
        assert(self.start.size() == self.SIZE)
        self.end = BitVec(f'Wrange32-{name}-end', bv=self.SIZE) if end is None else end
        assert(self.end.size() == self.SIZE)

    def wellformed(self):
        # allow end < start, so any start/end combination is valid
        return BoolVal(True)

    @property
    def uwrapping(self):
        # unsigned comparison, (u32)end < (u32)start
        return ULT(self.end, self.start)

    @property
    def umin(self):
        return If(self.uwrapping, BitVecVal(0, bv=self.SIZE), self.start)

    @property
    def umax(self):
        return If(self.uwrapping, BitVecVal(2**self.SIZE - 1, bv=self.SIZE), self.end)

    @property
    def swrapping(self):
        # signed comparison, (s32)end < (s32)start
        return self.end < self.start

    @property
    def smin(self):
        return If(self.swrapping, BitVecVal(1 << (self.SIZE - 1), bv=self.SIZE), self.start)

    @property
    def smax(self):
        return If(self.swrapping, BitVecVal((2**self.SIZE - 1) >> 1, bv=self.SIZE), self.end)

    # Not used in wrange.c, but helps with checking later
    def contains(self, val: BitVecRef):
        assert(val.size() == self.SIZE)
        # start <= val <= end
        nonwrapping_cond = And(ULE(self.start, val), ULE(val, self.end))
        # 0 <= val <= end or start <= val <= 2**32-1
        # (omit checking 0 <= val and val <= 2**32-1 since they're always true)
        wrapping_cond = Or(ULE(val, self.end), ULE(self.start, val))
        return If(self.uwrapping, wrapping_cond, nonwrapping_cond)


class Wrange32(Wrange):
    SIZE = 32 # Working with 32-bit integers


__all__ = [
        'Wrange',
        'Wrange32',
        'BitVec32',
        'BitVecVal32',
]


def main():
    # A random 32-bit integer called x, that can be of any possible value
    # unless constrained
    x = BitVec32('x')

    w1 = Wrange32('w1', start=BitVecVal32(1), end=BitVecVal32(1))
    print(f'Given w1 start={w1.start} end={w1.end}')
    print('\nChecking w1 is wellformed')
    prove(
        w1.wellformed(),
    )
    print('\nChecking w1.umin is 1')
    prove(
        w1.umin == BitVecVal32(1),
    )
    print('\nChecking w1.umax is 1')
    prove(
        w1.umax == BitVecVal32(1),
    )
    print('\nChecking w1.smin is 1')
    prove(
        w1.smin == BitVecVal32(1),
    )
    print('\nChecking w1.smax is 1')
    prove(
        w1.smax == BitVecVal32(1),
    )
    print('\nChecking that w1 contains 1')
    prove(
        w1.contains(BitVecVal32(1)),
    )
    print('\nChecking that w1 is a set of {1}, with only one element')
    prove(
        w1.contains(x) == (x == BitVecVal32(1)),
    )

    w2 = Wrange32('w2', start=BitVecVal32(2), end=BitVecVal32(2**32 - 1))
    print(f'\nGiven w2 start={w2.start} end={w2.end}')
    print('\nChecking w2 is wellformed')
    prove(
        w2.wellformed(),
    )
    print('\nChecking w2.umin is 2')
    prove(
        w2.umin == BitVecVal32(2),
    )
    print('\nChecking w2.umax is 2**32-1')
    prove(
        w2.umax == BitVecVal32(2**32 - 1),
    )
    print('\nChecking w2.smin is -2147483648/0x80000000')
    prove(
        w2.smin == BitVecVal32(0x80000000),
    )
    print('\nChecking w2.smax is 2147483647/0x7fffffff')
    prove(
        w2.smax == BitVecVal32(0x7fffffff),
    )
    print('\nChecking that w2 contains 2**32 - 1')
    prove(
        w2.contains(BitVecVal32(2**32 - 1)),
    )
    print('\nChecking that w2 does NOT contains 1')
    prove(
        Not(w2.contains(BitVecVal32(1))),
    )
    print('\nChecking that w2 is a set of {2..2**32-1}')
    prove(
        # Contrain x such that 2 <= x <= 2**32-1 and check that if x between 2
        # and 2**32-1 (inclusive), then w2.contains(x) will return true.
        #
        # In addition to that, check that the reverse is also true. That is if
        # x it _not_ a value between 2 and 2**32-1, then w2.contains(x) will
        # return false.
        w2.contains(x) == And(ULE(BitVecVal32(2), x), ULE(x, BitVecVal32(2**32-1))),
    )

    # Right now our semantic doesn't allow umax/end < umin/start
    w3 = Wrange32('w3', start=BitVecVal32(2), end=BitVecVal32(0))
    print(f'\nGiven w3 start={w3.start} end={w3.end}')
    print('\nChecking w3 is also wellformed')
    prove(
        w3.wellformed(),
    )
    print('\nChecking w3.umin is 0')
    prove(
        w3.umin == BitVecVal32(0),
    )
    print('\nChecking w3.umax is 2**32-1')
    prove(
        w3.umax == BitVecVal32(2**32 - 1),
    )
    print('\nChecking w3.smin is -2147483648/0x80000000')
    prove(
        w3.smin == BitVecVal32(0x80000000),
    )
    print('\nChecking w3.smax is 2147483647/0x7fffffff')
    prove(
        w3.smax == BitVecVal32(0x7fffffff),
    )
    print('\nChecking that w3 contains 0')
    prove(
        w3.contains(BitVecVal32(0)),
    )
    print('\nChecking that w3 does NOT contain 1')
    prove(
        Not(w3.contains(BitVecVal32(1))),
    )
    print('\nChecking that w3 is a union set of ({0} U {2..2**32-1})')
    prove(
        w3.contains(x) == Or(x == BitVecVal32(0), And(ULE(2, x), ULE(x, 2**32-1))),
    )

    w4 = Wrange32('w4', start=BitVecVal32(2**32 - 1), end=BitVecVal32(1))
    print(f'\nGiven w4 start={w4.start} end={w4.end}')
    print('\nChecking w4 is also wellformed')
    prove(
        w4.wellformed(),
    )
    print('\nChecking w4.umin is 0')
    prove(
        w4.umin == BitVecVal32(0),
    )
    print('\nChecking w4.umax is 2**32-1')
    prove(
        w4.umax == BitVecVal32(2**32 - 1),
    )
    print('\nChecking w4.smin is -1')
    prove(
        w4.smin == BitVecVal32(-1),
    )
    print('\nChecking w4.smax is 1')
    prove(
        w4.smax == BitVecVal32(1),
    )
    print('\nChecking that w4 contains 0')
    prove(
        w4.contains(BitVecVal32(0)),
    )
    print('\nChecking that w4 does contain 2**32-1')
    prove(
        w4.contains(BitVecVal32(2**32-1)),
    )
    print('\nChecking that w4 is a union set of ({2**32-1} U {0..1})')
    prove(
        w4.contains(x) == Or(x == BitVecVal32(2**32-1), x == BitVecVal32(0), x == BitVecVal32(1)),
    )

    # General checks for umin/umax/smin/smax
    w = Wrange32('w') # Given a Wrange32 called w
    x = BitVec32('x') # And an 32-bit integer x (redeclared for clarity)
    print(f'\nGiven any possible Wrange32 called w, and any possible 32-bit integer called x')
    print('\nChecking if w.contains(x) == True, then w.umin <= (u32)x is also true')
    prove(
        Implies(
            And(
                w.wellformed(), # Always true, but keeping it for now
                w.contains(x),
            ),
            ULE(w.umin, x),
        )
    )
    print('\nChecking if w.contains(x) == True, then (u32)x <= w.umax is also true')
    prove(
        Implies(
            And(
                w.wellformed(),
                w.contains(x),
            ),
            ULE(x, w.umax),
        )
    )
    print('\nChecking if w.contains(x) == True, then w.smin <= (s32)x is also true')
    prove(
        Implies(
            And(
                w.wellformed(),
                w.contains(x),
            ),
            w.smin <= x,
        )
    )
    print('\nChecking if w.contains(x) == True, then (s32)x <= w.smax is also true')
    prove(
        Implies(
            And(
                w.wellformed(),
                w.contains(x),
            ),
            x <= w.smax,
        )
    )

if __name__ == '__main__':
    main()
