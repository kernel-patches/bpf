// SPDX-License-Identifier: GPL-2.0
/*
 * The state that enters a loop that is not counted is left as it is. So is the state that ends
 * a walk through the iterations of such a loop. What stands for many iterations is a join of states
 * that were seen, not a guess that is written into one of them.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64[9]);
} map SEC(".maps");

#define LOOKUP(reg)							\
	"r1 = 0;"							\
	"*(u32 *)(r10 - 4) = r1;"					\
	"r2 = r10;"							\
	"r2 += -4;"							\
	"r1 = %[map] ll;"						\
	"call %[bpf_map_lookup_elem];"					\
	#reg " = r0;"							\
	"if r0 == 0 goto 9f;"

#define END								\
"9:"									\
	"r0 = 0;"							\
	"exit;"								\
	:								\
	: __imm(bpf_map_lookup_elem), __imm_addr(map)			\
	: __clobber_all

#define OK(text)	SEC("socket") __description("as is: " text) __success __retval(0)
#define BAD(text)	SEC("socket") __description("as is: " text) __failure

/*
 *	do { n += 3; } while (v[0]);
 * Two iterations are looked at as they are. The second one ends the walk: its jump goes both
 * ways. Its state is joined with the one before, nothing stops n, so n is any number.
 * What comes back next is within that. The number of insns tells that there is no fourth pass.
 * The loop gets may_goto when the walk ends, and all is done again: two times 24 insns.
 */
OK("the state that ends a walk is joined with the one before")
__log_level(1) __msg("processed 48 insns")
__naked void two_passes(void)
{
	asm volatile (
	LOOKUP(r7)
	"r6 = 0;"
"1:"
	"r6 += 3;"
	"r1 = *(u32 *)(r7 + 0);"
	"if r1 != 0 goto 1b;"
	"r6 &= 63;"
	"r7 += r6;"
	"r0 = *(u8 *)(r7 + 8);"
	END);
}

/*
 *	x = (v[0] & 1) << 62; do { x |= x >> 1; if (x > 1 << 62) break; } while (v[1]);
 * The range at the head is 0..1 << 62 in every pass, the lower half is 0, and one more bit is not
 * known: bit 61, 60 .. 32. That is not followed bit by bit, 30 passes and more in a nest of loops:
 * the known bits are what the range says after the first one.
 */
OK("known bits are not lost one by one")
__log_level(1) __msg("processed 74 insns")
__naked void bits_one_by_one(void)
{
	asm volatile (
	LOOKUP(r7)
	"r6 = *(u64 *)(r7 + 0);"
	"r6 &= 1;"
	"r6 <<= 62;"
	"r8 = 1;"
	"r8 <<= 62;"
"1:"
	"r1 = r6;"
	"r1 >>= 1;"
	"r6 |= r1;"
	"if r6 > r8 goto 9f;"
	"r1 = *(u64 *)(r7 + 8);"
	"if r1 != 0 goto 1b;"
	"r6 >>= 60;"
	"r7 += r6;"
	"r0 = *(u8 *)(r7 + 0);"
	END);
}

/*
 *	if (x < 1000000) return; do { if (x && !v[2]) x--; } while (v[1]);
 * x is 1000000..U64_MAX, then 999999..U64_MAX. As a signed number it's S64_MIN..S64_MAX all the
 * time: no signed bound moves, and the range does, a million times if nothing is done about it.
 */
OK("a range moves and its signed bounds do not")
__log_level(1) __msg("processed 68 insns")
__naked void unsigned_bound_moves(void)
{
	asm volatile (
	LOOKUP(r7)
	"r6 = *(u64 *)(r7 + 0);"
	"if r6 < 1000000 goto 9f;"
"1:"
	"if r6 == 0 goto 2f;"
	"r1 = *(u64 *)(r7 + 16);"
	"if r1 != 0 goto 2f;"
	"r6 += -1;"
"2:"
	"r1 = *(u64 *)(r7 + 8);"
	"if r1 != 0 goto 1b;"
	"r6 &= 7;"
	"r7 += r6;"
	"r0 = *(u8 *)(r7 + 0);"
	END);
}

/*
 *	n = 3; while (v[0]) { if (v[0] != 1 && n) n--; }
 * n goes from 3 to 0. The bound that moves at the head of the loop is put at 0, the nearest of the
 * fixed stops, and that holds. Without it n goes on to fall, and n & 63 is up to 63.
 */
OK("a number that falls stops at 0")
__naked void stops_at_0(void)
{
	asm volatile (
	LOOKUP(r6)
	"r7 = 3;"
"1:"
	"r1 = *(u64 *)(r6 + 0);"
	"if r1 == 0 goto 3f;"
	"if r1 == 1 goto 2f;"
	"if r7 == 0 goto 2f;"
	"r7 += -1;"
"2:"
	"goto 1b;"
"3:"
	"r7 &= 63;"
	"r6 += r7;"
	"r0 = *(u8 *)(r6 + 68);"
	END);
}

/*
 *	n = 0; while (v[0]) { if (v[0] != 1 && n < 8) n++; }
 *	((u8 *)v)[n + off]
 * n grows in some iterations only, and no edge of the jump that looks at it leaves the loop. n is
 * an index behind the loop, where no jump has cut it: what counts is its range at the head.
 * 7 goes on to the add, so 8 comes back at most.
 * @load, @store: n lives in a register, or in 32 bits of a stack slot.
 */
#define GROWS(name, load, store, off)					\
__naked void name(void)							\
{									\
	asm volatile (							\
	LOOKUP(r6)							\
	"r7 = 0;"							\
	store								\
"1:"									\
	"r1 = *(u64 *)(r6 + 0);"					\
	"if r1 == 0 goto 3f;"						\
	"if r1 == 1 goto 2f;"						\
	load								\
	"if r7 >= 8 goto 2f;"						\
	"r7 += 1;"							\
	store								\
"2:"									\
	"goto 1b;"							\
"3:"									\
	load								\
	"r6 += r7;"							\
	"r0 = *(u8 *)(r6 + " #off ");"					\
	END);								\
}

OK("a jump of the loop stops a number at 8")
GROWS(stops_at_8, "", "", 63)

BAD("a jump of the loop stops a number at 8, one byte too far")
__msg("invalid access to map value, value_size=72 off=72 size=1")
GROWS(stops_at_8_bad, "", "", 64)

OK("a jump of the loop stops a number in a stack slot at 8")
GROWS(slot_stops_at_8, "r7 = *(u32 *)(r10 - 16);", "*(u32 *)(r10 - 16) = r7;", 63)

/* 8 comes back to the head of the inner loop, and goes from there to the head of the outer one */
OK("a jump of the inner loop stops a number at 8")
int inner_loop_stops_at_8(void *ctx)
{
	__u32 key = 0;
	__u64 n = 0, *v;
	int i, j;

	v = bpf_map_lookup_elem(&map, &key);
	if (!v)
		return 0;
	bpf_for(i, 0, 100) {
		bpf_for(j, 0, 100) {
			if (*(volatile __u64 *)v == 1)
				continue;
			if (n < 8)
				v[n++] = 0;
		}
	}
	return v[n];
}

/*
 *	for (i = n; i >= 0; i--) sum += v[i];
 * A compiler counts in bytes and leaves the loop one element below the array:
 *	off = n * 8; do { sum += *(u64 *)(v + off); off -= @step; } while (off != -8);
 * n is a range, so the loop is not counted. Only -8 leaves it. The offset doesn't get past -8
 * because it is a multiple of 8, and that has to be known at the head of the loop.
 */
#define DOWN(name, step)						\
__naked void name(void)							\
{									\
	asm volatile (							\
	LOOKUP(r7)							\
	"r6 = *(u32 *)(r7 + 64);"					\
	"if r6 > 7 goto 9f;"						\
	"r6 <<= 3;"							\
"1:"									\
	"r2 = r7;"							\
	"r2 += r6;"							\
	"r0 = *(u64 *)(r2 + 0);"					\
	"r6 += -" #step ";"						\
	"if r6 != -8 goto 1b;"						\
	END);								\
}

OK("down by 8 bytes, left at -8")
DOWN(down_by_8, 8)

/* 16, 4, -8 is fine, 8, -4 is not */
BAD("down by 12 bytes, left at -8")
__msg("min value is negative")
DOWN(down_by_12, 12)

static __naked __noinline __used void nothing(void)
{
	asm volatile ("r0 = 0; exit;" ::: __clobber_all);
}

/*
 *	if (v[0]) { n = 7; have = 1; }
 *	nothing();
 *	i = 0; do { if (v[0] != 3) i++; } while (i < 8 && v[0] != 2);
 *	if (have) return n;
 * (have = 0, n is not set) and (have = 1, n = 7) wait for the function. What comes out of it goes
 * to both at once, and the insn behind the call is the head of the loop: two walks begin, and no
 * insn is looked at in between. The state that ends one of them is joined with a state of
 * that walk. With a state of the other one it would be (have = 0 or 1, n is not set).
 */
#define TWO_WALKS(name, test)						\
__naked void name(void)							\
{									\
	asm volatile (							\
	LOOKUP(r8)							\
	"r9 = 0;"							\
	"r1 = *(u32 *)(r8 + 0);"					\
	"if r1 != 0 goto 1f;"						\
	"r7 = 0;"							\
	"goto 2f;"							\
"1:"									\
	"r6 = 7;"							\
	"r7 = 1;"							\
"2:"									\
	"call nothing;"							\
"3:"									\
	"r1 = *(u32 *)(r8 + 0);"					\
	"if r1 == 3 goto +1;"						\
	"r9 += 1;"							\
	"if r9 > 7 goto 4f;"						\
	"if r1 == 1 goto 3b;"						\
	"if r1 != 2 goto 3b;"						\
"4:"									\
	test								\
	"r0 = r6;"							\
	"exit;"								\
	END);								\
}

OK("two walks begin at the same time")
TWO_WALKS(two_walks_at_once, "if r7 == 0 goto 9f;")

/* n is read when it is not set */
BAD("two walks begin at the same time, the register is not set")
__msg("R6 !read_ok")
TWO_WALKS(two_walks_at_once_bad, "if r7 != 0 goto 9f;")

char _license[] SEC("license") = "GPL";
