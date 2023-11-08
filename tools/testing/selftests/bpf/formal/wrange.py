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
        # start <= end
        return ULE(self.start, self.end)

    @property
    def umin(self):
        return self.start

    @property
    def umax(self):
        return self.end

    # Not used in wrange.c, but helps with checking later
    def contains(self, val: BitVecRef):
        assert(val.size() == self.SIZE)
        # umin <= val <= umax
        return And(ULE(self.umin, val), ULE(val, self.umax))


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
    print('\nChecking w3 is NOT wellformed')
    prove(
        Not(w3.wellformed()),
    )

    # General checks that does not assum the value of start/end, except that it
    # meets the requirement that start <= end.
    w = Wrange32('w') # Given a Wrange32 called w
    x = BitVec32('x') # And an 32-bit integer x (redeclared for clarity)
    print(f'\nGiven any possible Wrange32 called w, and any possible 32-bit integer called x')
    print('\nChecking if w.contains(x) == True, then w.umin <= (u32)x is also true')
    prove(
        Implies(
            And(
                w.wellformed(),
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

if __name__ == '__main__':
    main()
