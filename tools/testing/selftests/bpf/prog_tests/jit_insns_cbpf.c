// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */
/*
 * The classic BPF cases of the former test_bpf module, run as socket
 * filters: the data cases on an AF_UNIX datagram pair, which takes any
 * length down to zero and puts the tail of a long datagram into page
 * frags, the cases reading the link layer or the metadata of a packet on
 * a veth pair in their own netns. The return of a filter decides over the
 * packet, zero drops it and any other value truncates it to that length,
 * so the returns of a program get rewritten: the expected result stays,
 * any other constant becomes zero and a returned accumulator is compared
 * at the end, so that a wrong result shows as a dropped packet.
 */
#include <test_progs.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <linux/filter.h>

#include "network_helpers.h"
#include "sysctl_helpers.h"

#define MAX_K		0xffffffff
#define SKB_TYPE	PACKET_OTHERHOST	/* the frames go to a foreign MAC */
#define SKB_MARK	0x1234aaaa		/* the mark of the sending socket */
#define SKB_VLAN_TCI	0xffff
#define SKB_VLAN_PRESENT 1
#define SKB_DEV_IFINDEX	0			/* that of the receiving veth */
#define SKB_DEV_TYPE	1			/* ARPHRD_ETHER, that of a veth */
/*
 * A datagram of four pages splits into three pages of head and one page of
 * frag data: what exceeds SKB_MAX_ALLOC, four pages less the shared info,
 * goes into frags, rounded up to a page. The table cases take 4K pages, a
 * larger page keeps their datagram linear; the sweep goes by the page size.
 */
#define FRAG_OFF	(3 * 4096)		/* the frag data starts here */
#define SWEEP_SPAN	16			/* offsets swept either side of it */
#define NETNS		"jit_insns_cbpf"

static int page_size;
static int dgram_max;				/* four pages */

enum {
	CB_FAIL		= 1,	/* the attach has to fail */
	CB_PKT		= 2,	/* needs the link layer or the metadata of a packet */
	CB_VLAN		= 4,	/* a tagged frame, the stack pulls the tag out */
	CB_FRAG		= 8,	/* the length is the head, the frag data goes at its end */
	CB_IFINDEX	= 16,	/* the result is the ifindex of the receiving veth */
	CB_DSTMAC	= 32,	/* the frame goes to the MAC of the receiving veth */
	CB_NOBLIND	= 64,	/* blinding grows the converted jump past 16 bits */
	CB_RAW		= 128,	/* the returns stay, the kept length shows the result */
};

struct cbpf_run {
	int len;
	__u32 result;
};

struct cbpf_case {
	const char *descr;
	const struct sock_filter *insns;
	int cnt;
	int (*fill)(struct sock_filter *insns);
	const __u8 *data;
	int data_len;
	const __u8 *frag;
	int frag_len;
	const struct cbpf_run *runs;
	int nr_runs;
	unsigned int flags;
};

#define INSNS(...)							\
	(const struct sock_filter[]){ __VA_ARGS__ },			\
	.cnt = ARRAY_SIZE(((const struct sock_filter[]){ __VA_ARGS__ }))
#define DATA(...)							\
	(const __u8[]){ __VA_ARGS__ },					\
	.data_len = sizeof((const __u8[]){ __VA_ARGS__ })
#define FRAG(...)							\
	(const __u8[]){ __VA_ARGS__ },					\
	.frag_len = sizeof((const __u8[]){ __VA_ARGS__ })
#define RUNS(...)							\
	(const struct cbpf_run[]){ __VA_ARGS__ },			\
	.nr_runs = ARRAY_SIZE(((const struct cbpf_run[]){ __VA_ARGS__ }))

/* The uapi forms are initializers, these are values */
#define STMT(code, k)		((struct sock_filter)BPF_STMT(code, k))
#define JUMP(code, k, jt, jf)	((struct sock_filter)BPF_JUMP(code, k, jt, jf))

/* Jumps with gaps in between, the former __bpf_fill_ja() */
static int fill_ja(struct sock_filter *insns, int len, int plen)
{
	int rlen = (len % plen) - 1, i, j;

	for (i = 0; i + plen < len; i += plen)
		for (j = 0; j < plen; j++)
			insns[i + j] = JUMP(BPF_JMP | BPF_JA, plen - 1 - j, 0, 0);
	for (j = 0; j < rlen; j++)
		insns[i + j] = JUMP(BPF_JMP | BPF_JA, rlen - 1 - j, 0, 0);
	insns[len - 1] = STMT(BPF_RET | BPF_K, 0xababcbac);
	return len;
}

static int fill_ja_short(struct sock_filter *insns)
{
	return fill_ja(insns, 12, 9);
}

static int fill_ja_long(struct sock_filter *insns)
{
	return fill_ja(insns, BPF_MAXINSNS, 68);
}

static int fill_too_many(struct sock_filter *insns)
{
	int i;

	for (i = 0; i <= BPF_MAXINSNS; i++)
		insns[i] = STMT(BPF_RET | BPF_K, 0xfefefefe);
	return BPF_MAXINSNS + 1;
}

/*
 * A jump over MSH loads, each of which becomes 18 instructions: the
 * converted offset has to fit 16 bits, which 1820 of them do.
 */
static int fill_jump_over_msh(struct sock_filter *insns, int nr)
{
	int i;

	insns[0] = JUMP(BPF_JMP | BPF_JA, nr, 0, 0);
	for (i = 1; i <= nr; i++)
		insns[i] = STMT(BPF_LDX | BPF_B | BPF_MSH, 0);
	insns[nr + 1] = STMT(BPF_RET | BPF_K, 0xabababab);
	return nr + 2;
}

static int fill_jump_over_all_msh(struct sock_filter *insns)
{
	return fill_jump_over_msh(insns, BPF_MAXINSNS - 2);
}

static int fill_jump_over_1821_msh(struct sock_filter *insns)
{
	return fill_jump_over_msh(insns, 1821);
}

static int fill_jump_over_1820_msh(struct sock_filter *insns)
{
	return fill_jump_over_msh(insns, 1820);
}

static int fill_empty(struct sock_filter *insns)
{
	return 0;
}

/* A conditional jump past 32K converted instructions */
static int fill_late_jump(struct sock_filter *insns)
{
	int i;

	for (i = 0; i < 2000; i++)
		insns[i] = STMT(BPF_LDX | BPF_B | BPF_MSH, 0);
	insns[2000] = STMT(BPF_LD | BPF_IMM, 1);
	insns[2001] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 1);
	insns[2002] = STMT(BPF_RET | BPF_K, 1);
	insns[2003] = STMT(BPF_RET | BPF_K, 2);
	return 2004;
}

/* A conditional jump over 254 loads, which expand to 12 instructions each */
static int fill_jump_over_ld_abs(struct sock_filter *insns, bool taken)
{
	int i;

	insns[0] = STMT(BPF_LD | BPF_B | BPF_ABS, 0);
	insns[1] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, taken ? 255 : 0, taken ? 0 : 255);
	for (i = 2; i < 256; i++)
		insns[i] = STMT(BPF_LD | BPF_B | BPF_ABS, 0);
	insns[256] = STMT(BPF_RET | BPF_K, 2);
	insns[257] = STMT(BPF_RET | BPF_K, 3);
	return 258;
}

static int fill_jt_over_ld_abs(struct sock_filter *insns)
{
	return fill_jump_over_ld_abs(insns, true);
}

static int fill_jf_over_ld_abs(struct sock_filter *insns)
{
	return fill_jump_over_ld_abs(insns, false);
}

/* The result is small enough for the kept length to show it as is */
static int fill_all_msh(struct sock_filter *insns)
{
	int len = BPF_MAXINSNS, i;

	for (i = 0; i < len - 3; i++)
		insns[i] = STMT(BPF_LDX | BPF_B | BPF_MSH, 0);
	insns[len - 3] = STMT(BPF_LD | BPF_IMM, 0x2a);
	insns[len - 2] = STMT(BPF_ALU | BPF_XOR | BPF_X, 0);
	insns[len - 1] = STMT(BPF_RET | BPF_A, 0);
	return len;
}

static int fill_ld_abs_cpu(struct sock_filter *insns)
{
	int len = BPF_MAXINSNS, i;

	for (i = 0; i < len - 1; i += 2) {
		insns[i] = STMT(BPF_LD | BPF_B | BPF_ABS, 0);
		insns[i + 1] = STMT(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_CPU);
	}
	insns[len - 1] = STMT(BPF_RET | BPF_K, 0xbee);
	return len;
}

static const struct cbpf_case cases[] = {
	{
		.descr = "TAX",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 1),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_ALU | BPF_NEG, 0), /* A == -3 */
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_LEN, 0),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_MISC | BPF_TAX, 0), /* X == len - 3 */
			BPF_STMT(BPF_LD | BPF_B | BPF_IND, 1),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(10, 20, 30, 40, 50),
		.runs = RUNS({ 2, 10 }, { 3, 20 }, { 4, 30 }),
	},
	{
		.descr = "TXA",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0) /* A == len * 2 */
		),
		.data = DATA(10, 20, 30, 40, 50),
		.runs = RUNS({ 1, 2 }, { 3, 6 }, { 4, 8 }),
	},
	{
		.descr = "ADD_SUB_MUL_K",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 1),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 2),
			BPF_STMT(BPF_LDX | BPF_IMM, 3),
			BPF_STMT(BPF_ALU | BPF_SUB | BPF_X, 0),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 0xffffffff),
			BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, 3),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 0, 0xfffffffd }),
	},
	{
		.descr = "DIV_MOD_KX",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 8),
			BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 2),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_IMM, 0xffffffff),
			BPF_STMT(BPF_ALU | BPF_DIV | BPF_X, 0),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_IMM, 0xffffffff),
			BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 0x70000000),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_IMM, 0xffffffff),
			BPF_STMT(BPF_ALU | BPF_MOD | BPF_X, 0),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_IMM, 0xffffffff),
			BPF_STMT(BPF_ALU | BPF_MOD | BPF_K, 0x70000000),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 0, 0x20000000 }),
	},
	{
		.descr = "AND_OR_LSH_K",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0xff),
			BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),
			BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 27),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_IMM, 0xf),
			BPF_STMT(BPF_ALU | BPF_OR | BPF_K, 0xf0),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 0, 0x800000ff }, { 1, 0x800000ff }),
	},
	{
		.descr = "LD_IMM_0",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0), /* ld #0 */
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 1 }),
	},
	{
		.descr = "LD_IND",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_IND, MAX_K),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 0 }, { 10, 0 }, { 60, 0 }),
	},
	{
		.descr = "LD_ABS",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 1000),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 0 }, { 10, 0 }, { 60, 0 }),
	},
	{
		.descr = "LD_ABS_NET",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, SKF_NET_OFF),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, SKF_NET_OFF + 1),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3),
		.runs = RUNS({ 15, 0 }, { 16, 3 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_IND_NET",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, SKF_NET_OFF - 15),
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3),
		.runs = RUNS({ 14, 0 }, { 15, 1 }, { 17, 3 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_PKTTYPE",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PKTTYPE),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SKB_TYPE, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PKTTYPE),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SKB_TYPE, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PKTTYPE),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SKB_TYPE, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 1, 3 }, { 10, 3 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_MARK",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_MARK),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 1, SKB_MARK}, { 10, SKB_MARK}),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_IFINDEX",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_IFINDEX),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 1, SKB_DEV_IFINDEX }, { 10, SKB_DEV_IFINDEX }),
		.flags = CB_PKT | CB_IFINDEX,
	},
	{
		.descr = "LD_HATYPE",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_HATYPE),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 1, SKB_DEV_TYPE }, { 10, SKB_DEV_TYPE }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_CPU",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_CPU),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_CPU),
			BPF_STMT(BPF_ALU | BPF_SUB | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 1, 0 }, { 10, 0 }),
	},
	{
		.descr = "LD_NLATTR",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 2),
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_LDX | BPF_IMM, 3),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_NLATTR),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
#if __BYTE_ORDER == __BIG_ENDIAN
		.data = DATA(0xff, 0xff, 0, 4, 0, 2, 0, 4, 0, 3),
#else
		.data = DATA(0xff, 0xff, 4, 0, 2, 0, 4, 0, 3, 0),
#endif
		.runs = RUNS({ 4, 0 }, { 20, 6 }),
	},
	{
		.descr = "LD_NLATTR_NEST",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_LDX | BPF_IMM, 3),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_NLATTR_NEST),
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_NLATTR_NEST),
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_NLATTR_NEST),
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_NLATTR_NEST),
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_NLATTR_NEST),
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_NLATTR_NEST),
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_NLATTR_NEST),
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_NLATTR_NEST),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
#if __BYTE_ORDER == __BIG_ENDIAN
		.data = DATA(0xff, 0xff, 0, 12, 0, 1, 0, 4, 0, 2, 0, 4, 0, 3),
#else
		.data = DATA(0xff, 0xff, 12, 0, 1, 0, 4, 0, 2, 0, 4, 0, 3, 0),
#endif
		.runs = RUNS({ 4, 0 }, { 20, 10 }),
	},
	{
		.descr = "LD_PAYLOAD_OFF",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PAY_OFFSET),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PAY_OFFSET),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PAY_OFFSET),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PAY_OFFSET),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PAY_OFFSET),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
			     0x00, 0x54, 0xac, 0x8b, 0x40, 0x00, 0x40, 0x01,
			     0x90, 0x1b, 0x7f, 0x00, 0x00, 0x01),
		.runs = RUNS({ 30, 0 }, { 100, 42 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_ANC_XOR",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 10),
			BPF_STMT(BPF_LDX | BPF_IMM, 300),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_ALU_XOR_X),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 4, 0xA ^ 300 }, { 20, 0xA ^ 300 }),
	},
	{
		.descr = "SPILL_FILL",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_LD | BPF_IMM, 2),
			BPF_STMT(BPF_ALU | BPF_RSH, 1),
			BPF_STMT(BPF_ALU | BPF_XOR | BPF_X, 0),
			BPF_STMT(BPF_ST, 1), /* M1 = 1 ^ len */
			BPF_STMT(BPF_ALU | BPF_XOR | BPF_K, 0x80000000),
			BPF_STMT(BPF_ST, 2), /* M2 = 1 ^ len ^ 0x80000000 */
			BPF_STMT(BPF_STX, 15), /* M3 = len */
			BPF_STMT(BPF_LDX | BPF_MEM, 1),
			BPF_STMT(BPF_LD | BPF_MEM, 2),
			BPF_STMT(BPF_ALU | BPF_XOR | BPF_X, 0),
			BPF_STMT(BPF_LDX | BPF_MEM, 15),
			BPF_STMT(BPF_ALU | BPF_XOR | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 1, 0x80000001 }, { 2, 0x80000002 }, { 60, 0x80000000 ^ 60 }),
	},
	{
		.descr = "JEQ",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 2),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_RET | BPF_K, MAX_K)
		),
		.data = DATA(3, 3, 3, 3, 3),
		.runs = RUNS({ 1, 0 }, { 3, 1 }, { 4, MAX_K }),
	},
	{
		.descr = "JGT",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 2),
			BPF_JUMP(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_RET | BPF_K, MAX_K)
		),
		.data = DATA(4, 4, 4, 3, 3),
		.runs = RUNS({ 2, 0 }, { 3, 1 }, { 4, MAX_K }),
	},
	{
		.descr = "JGE (jt 0), test 1",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 2),
			BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_RET | BPF_K, MAX_K)
		),
		.data = DATA(4, 4, 4, 3, 3),
		.runs = RUNS({ 2, 0 }, { 3, 1 }, { 4, 1 }),
	},
	{
		.descr = "JGE (jt 0), test 2",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 2),
			BPF_JUMP(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_RET | BPF_K, MAX_K)
		),
		.data = DATA(4, 4, 5, 3, 3),
		.runs = RUNS({ 4, 1 }, { 5, 1 }, { 6, MAX_K }),
	},
	{
		.descr = "JGE",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_IND, MAX_K),
			BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 1, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 10),
			BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 2, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 20),
			BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 3, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 30),
			BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 4, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 40),
			BPF_STMT(BPF_RET | BPF_K, MAX_K)
		),
		.data = DATA(1, 2, 3, 4, 5),
		.runs = RUNS({ 1, 20 }, { 3, 40 }, { 5, MAX_K }),
	},
	{
		.descr = "JSET",
		.insns = INSNS(
			BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0),
			BPF_JUMP(BPF_JMP | BPF_JA, 1, 1, 1),
			BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0),
			BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0),
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_ALU | BPF_SUB | BPF_K, 4),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_W | BPF_IND, 0),
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 1, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 10),
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x80000000, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 20),
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0xffffff, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 30),
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0xffffff, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 30),
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0xffffff, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 30),
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0xffffff, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 30),
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0xffffff, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 30),
			BPF_STMT(BPF_RET | BPF_K, MAX_K)
		),
		.data = DATA(0, 0xAA, 0x55, 1),
		.runs = RUNS({ 4, 10 }, { 5, 20 }, { 6, MAX_K }),
	},
	{
		.descr = "tcpdump port 22",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86dd, 0, 8), /* IPv6 */
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 20),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x84, 2, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x6, 1, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x11, 0, 17),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 54),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 22, 14, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 56),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 22, 12, 13),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 0, 12), /* IPv4 */
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x84, 2, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x6, 1, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x11, 0, 8),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 20),
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x1fff, 6, 0),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),
			BPF_STMT(BPF_LD | BPF_H | BPF_IND, 14),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 22, 2, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_IND, 16),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 22, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 0xffff),
			BPF_STMT(BPF_RET | BPF_K, 0)
		),
		.data = DATA(0x10, 0xbf, 0x48, 0xd6, 0x43, 0xd6, 0x3c, 0x07,
			     0x54, 0x43, 0xe5, 0x76, 0x08, 0x00, 0x45, 0x10,
			     0x00, 0x64, 0x75, 0xb5, 0x40, 0x00, 0x40, 0x06,
			     0xad, 0x2e, 0x0a, 0x01, 0x01, 0x95, 0x0a, 0x01,
			     0x02, 0x0a, 0xc2, 0x24, 0x00, 0x16),
		.runs = RUNS({ 10, 0 }, { 30, 0 }, { 100, 65535 }),
	},
	{
		.descr = "tcpdump complex",
		.insns = INSNS(
			/* tcpdump -nei eth0 'tcp port 22 and (((ip[2:2] -
			 * ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0) and
			 * (len > 115 or len < 30000000000)' -d
			 */
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86dd, 30, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x800, 0, 29),
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x6, 0, 27),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 20),
			BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x1fff, 25, 0),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),
			BPF_STMT(BPF_LD | BPF_H | BPF_IND, 14),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 22, 2, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_IND, 16),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 22, 0, 20),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 16),
			BPF_STMT(BPF_ST, 1),
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 14),
			BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
			BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 2),
			BPF_STMT(BPF_MISC | BPF_TAX, 0x5), /* libpcap emits K on TAX */
			BPF_STMT(BPF_LD | BPF_MEM, 1),
			BPF_STMT(BPF_ALU | BPF_SUB | BPF_X, 0),
			BPF_STMT(BPF_ST, 5),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),
			BPF_STMT(BPF_LD | BPF_B | BPF_IND, 26),
			BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),
			BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 2),
			BPF_STMT(BPF_MISC | BPF_TAX, 0x9), /* libpcap emits K on TAX */
			BPF_STMT(BPF_LD | BPF_MEM, 5),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_X, 0, 4, 0),
			BPF_STMT(BPF_LD | BPF_LEN, 0),
			BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 0x73, 1, 0),
			BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0xfc23ac00, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0xffff),
			BPF_STMT(BPF_RET | BPF_K, 0)
		),
		.data = DATA(0x10, 0xbf, 0x48, 0xd6, 0x43, 0xd6,
			     0x3c, 0x07, 0x54, 0x43, 0xe5, 0x76,
			     0x08, 0x00,
			     0x45, 0x10, 0x00, 0x64, 0x75, 0xb5,
			     0x40, 0x00, 0x40, 0x06, 0xad, 0x2e, /* IP header */
			     0x0a, 0x01, 0x01, 0x95, /* ip src */
			     0x0a, 0x01, 0x02, 0x0a, /* ip dst */
			     0xc2, 0x24,
			     0x00, 0x16 /* dst port */),
		.runs = RUNS({ 10, 0 }, { 30, 0 }, { 100, 65535 }),
	},
	{
		.descr = "RET_A",
		.insns = INSNS(
			/* check that uninitialized X and A contain zeros */
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({1, 0}, {2, 0}),
	},
	{
		.descr = "check: missing ret",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 1)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: div_k_0",
		.insns = INSNS(
			BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 0),
			BPF_STMT(BPF_RET | BPF_K, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: unknown insn",
		.insns = INSNS(
			/* seccomp insn, rejected in socket filter */
			BPF_STMT(BPF_LDX | BPF_W | BPF_ABS, 0),
			BPF_STMT(BPF_RET | BPF_K, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: out of range spill/fill",
		.insns = INSNS(
			BPF_STMT(BPF_STX, 16),
			BPF_STMT(BPF_RET | BPF_K, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "JUMPS + HOLES",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_JUMP(BPF_JMP | BPF_JGE, 0, 13, 15),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ, 0x90c2894d, 3, 4),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ, 0x90c2894d, 1, 2),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_JUMP(BPF_JMP | BPF_JGE, 0, 14, 15),
			BPF_JUMP(BPF_JMP | BPF_JGE, 0, 13, 14),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ, 0x2ac28349, 2, 3),
			BPF_JUMP(BPF_JMP | BPF_JEQ, 0x2ac28349, 1, 2),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_JUMP(BPF_JMP | BPF_JGE, 0, 14, 15),
			BPF_JUMP(BPF_JMP | BPF_JGE, 0, 13, 14),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ, 0x90d2ff41, 2, 3),
			BPF_JUMP(BPF_JMP | BPF_JEQ, 0x90d2ff41, 1, 2),
			BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 0),
			BPF_STMT(BPF_RET | BPF_A, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(0x00, 0x1b, 0x21, 0x3c, 0x9d, 0xf8,
			     0x90, 0xe2, 0xba, 0x0a, 0x56, 0xb4,
			     0x08, 0x00,
			     0x45, 0x00, 0x00, 0x28, 0x00, 0x00,
			     0x20, 0x00, 0x40, 0x11, 0x00, 0x00, /* IP header */
			     0xc0, 0xa8, 0x33, 0x01,
			     0xc0, 0xa8, 0x33, 0x02,
			     0xbb, 0xb6,
			     0xa9, 0xfa,
			     0x00, 0x14, 0x00, 0x00,
			     0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			     0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			     0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			     0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			     0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			     0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			     0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			     0xcc, 0xcc, 0xcc, 0xcc),
		.runs = RUNS({ 88, 0x001b }),
	},
	{
		.descr = "check: RET X",
		.insns = INSNS(
			BPF_STMT(BPF_RET | BPF_X, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: LDX + RET X",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 42),
			BPF_STMT(BPF_RET | BPF_X, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: SKF_AD_MAX",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_MAX),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "JMP_JA: Jump, gap, jump, ...",
		.fill = fill_ja_short,
		.runs = RUNS({ 0, 0xababcbac }),
	},
	{
		.descr = "BPF_MAXINSNS: Too many instructions",
		.fill = fill_too_many,
		.flags = CB_FAIL,
	},
	{
		.descr = "BPF_MAXINSNS: Jump, gap, jump, ...",
		.fill = fill_ja_long,
		.runs = RUNS({ 0, 0xababcbac }),
	},
	{
		.descr = "BPF_MAXINSNS: jump over MSH",
		.fill = fill_jump_over_all_msh,
		.data = DATA(0xfa, 0xfb, 0xfc, 0xfd),
		.flags = CB_FAIL,
	},
	{
		/* A rewritten return would be a jump past 32K converted instructions */
		.descr = "BPF_MAXINSNS: exec all MSH",
		.fill = fill_all_msh,
		.data = DATA(0xfa, 0xfb, 0xfc, 0xfd),
		.runs = RUNS({ 4, 2 }),
		.flags = CB_RAW,
	},
	{
		.descr = "BPF_MAXINSNS: ld_abs+get_processor_id",
		.fill = fill_ld_abs_cpu,
		.runs = RUNS({ 1, 0xbee }),
	},
	{
		.descr = "LD_IND byte positive offset",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3e),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, 0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x82 }),
	},
	{
		.descr = "LD_IND byte negative offset",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3e),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, -0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x05 }),
	},
	{
		.descr = "LD_IND byte positive offset, all ff",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3e),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, 0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0xff, [0x3d] = 0xff,  [0x3e] = 0xff, [0x3f] = 0xff),
		.runs = RUNS({0x40, 0xff }),
	},
	{
		.descr = "LD_IND byte positive offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3e),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, 0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
	},
	{
		.descr = "LD_IND byte negative offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3e),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, -0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
	},
	{
		.descr = "LD_IND byte negative offset, multiple calls",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3b),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, SKF_LL_OFF + 1),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, SKF_LL_OFF + 2),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, SKF_LL_OFF + 3),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, SKF_LL_OFF + 4),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x82 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_IND halfword positive offset",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x20),
			BPF_STMT(BPF_LD | BPF_IND | BPF_H, 0x2),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88),
		.runs = RUNS({0x40, 0xdd88 }),
	},
	{
		.descr = "LD_IND halfword negative offset",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x20),
			BPF_STMT(BPF_LD | BPF_IND | BPF_H, -0x2),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88),
		.runs = RUNS({0x40, 0xbb66 }),
	},
	{
		.descr = "LD_IND halfword unaligned",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x20),
			BPF_STMT(BPF_LD | BPF_IND | BPF_H, -0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88),
		.runs = RUNS({0x40, 0x66cc }),
	},
	{
		.descr = "LD_IND halfword positive offset, all ff",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3d),
			BPF_STMT(BPF_LD | BPF_IND | BPF_H, 0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0xff, [0x3d] = 0xff,  [0x3e] = 0xff, [0x3f] = 0xff),
		.runs = RUNS({0x40, 0xffff }),
	},
	{
		.descr = "LD_IND halfword positive offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3e),
			BPF_STMT(BPF_LD | BPF_IND | BPF_H, 0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
	},
	{
		.descr = "LD_IND halfword negative offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3e),
			BPF_STMT(BPF_LD | BPF_IND | BPF_H, -0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
	},
	{
		.descr = "LD_IND word positive offset",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x20),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, 0x4),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0xee99ffaa }),
	},
	{
		.descr = "LD_IND word negative offset",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x20),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, -0x4),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0xaa55bb66 }),
	},
	{
		.descr = "LD_IND word unaligned (addr & 3 == 2)",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x20),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, -0x2),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0xbb66cc77 }),
	},
	{
		.descr = "LD_IND word unaligned (addr & 3 == 1)",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x20),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, -0x3),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0x55bb66cc }),
	},
	{
		.descr = "LD_IND word unaligned (addr & 3 == 3)",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x20),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, -0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0x66cc77dd }),
	},
	{
		.descr = "LD_IND word positive offset, all ff",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3b),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, 0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0xff, [0x3d] = 0xff,  [0x3e] = 0xff, [0x3f] = 0xff),
		.runs = RUNS({0x40, 0xffffffff }),
	},
	{
		.descr = "LD_IND word positive offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3e),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, 0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
	},
	{
		.descr = "LD_IND word negative offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0x3e),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, -0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
	},
	{
		.descr = "LD_ABS byte",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, 0x20),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0xcc }),
	},
	{
		.descr = "LD_ABS byte positive offset, all ff",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, 0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0xff, [0x3d] = 0xff,  [0x3e] = 0xff, [0x3f] = 0xff),
		.runs = RUNS({0x40, 0xff }),
	},
	{
		.descr = "LD_ABS byte positive offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, 0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
	},
	{
		.descr = "LD_ABS byte negative offset, out of bounds load",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, -1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "LD_ABS byte negative offset, in bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, SKF_LL_OFF + 0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x82 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_ABS byte negative offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, SKF_LL_OFF + 0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_ABS byte negative offset, multiple calls",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, SKF_LL_OFF + 0x3c),
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, SKF_LL_OFF + 0x3d),
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, SKF_LL_OFF + 0x3e),
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, SKF_LL_OFF + 0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x82 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_ABS halfword",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_H, 0x22),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0xdd88 }),
	},
	{
		.descr = "LD_ABS halfword unaligned",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_H, 0x25),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0x99ff }),
	},
	{
		.descr = "LD_ABS halfword positive offset, all ff",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_H, 0x3e),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0xff, [0x3d] = 0xff,  [0x3e] = 0xff, [0x3f] = 0xff),
		.runs = RUNS({0x40, 0xffff }),
	},
	{
		.descr = "LD_ABS halfword positive offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_H, 0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
	},
	{
		.descr = "LD_ABS halfword negative offset, out of bounds load",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_H, -1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "LD_ABS halfword negative offset, in bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_H, SKF_LL_OFF + 0x3e),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x1982 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_ABS halfword negative offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_H, SKF_LL_OFF + 0x3e),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_ABS word",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0x1c),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0xaa55bb66 }),
	},
	{
		.descr = "LD_ABS word unaligned (addr & 3 == 2)",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0x22),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0xdd88ee99 }),
	},
	{
		.descr = "LD_ABS word unaligned (addr & 3 == 1)",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0x21),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0x77dd88ee }),
	},
	{
		.descr = "LD_ABS word unaligned (addr & 3 == 3)",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0x23),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x1c] = 0xaa, [0x1d] = 0x55,
			     [0x1e] = 0xbb, [0x1f] = 0x66,
			     [0x20] = 0xcc, [0x21] = 0x77,
			     [0x22] = 0xdd, [0x23] = 0x88,
			     [0x24] = 0xee, [0x25] = 0x99,
			     [0x26] = 0xff, [0x27] = 0xaa),
		.runs = RUNS({0x40, 0x88ee99ff }),
	},
	{
		.descr = "LD_ABS word positive offset, all ff",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0x3c),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0xff, [0x3d] = 0xff,  [0x3e] = 0xff, [0x3f] = 0xff),
		.runs = RUNS({0x40, 0xffffffff }),
	},
	{
		.descr = "LD_ABS word positive offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, 0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
	},
	{
		.descr = "LD_ABS word negative offset, out of bounds load",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, -1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "LD_ABS word negative offset, in bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, SKF_LL_OFF + 0x3c),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x25051982 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_ABS word negative offset, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, SKF_LL_OFF + 0x3c),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x3f, 0 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LDX_MSH standalone, preserved A",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0xffeebbaa),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0x3c),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0xffeebbaa }),
	},
	{
		.descr = "LDX_MSH standalone, preserved A 2",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0x175e9d63),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0x3c),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0x3d),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0x3e),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0x3f),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x175e9d63 }),
	},
	{
		.descr = "LDX_MSH standalone, test result 1",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0xffeebbaa),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0x3c),
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x14 }),
	},
	{
		.descr = "LDX_MSH standalone, test result 2",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0xffeebbaa),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0x3e),
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x24 }),
	},
	{
		.descr = "LDX_MSH standalone, negative offset",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0xffeebbaa),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, -1),
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0 }),
	},
	{
		.descr = "LDX_MSH standalone, negative offset 2",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0xffeebbaa),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, SKF_LL_OFF + 0x3e),
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0x24 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LDX_MSH standalone, out of bounds",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0xffeebbaa),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0x40),
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3c] = 0x25, [0x3d] = 0x05,  [0x3e] = 0x19, [0x3f] = 0x82),
		.runs = RUNS({0x40, 0 }),
	},
	{
		.descr = "ADD default X",
		.insns = INSNS(
			/*
			 * A = 0x42
			 * A = A + X
			 * ret A
			 */
			BPF_STMT(BPF_LD | BPF_IMM, 0x42),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.runs = RUNS({0x1, 0x42 }),
	},
	{
		.descr = "ADD default A",
		.insns = INSNS(
			/*
			 * A = A + 0x42
			 * ret A
			 */
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 0x42),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.runs = RUNS({0x1, 0x42 }),
	},
	{
		.descr = "SUB default X",
		.insns = INSNS(
			/*
			 * A = 0x66
			 * A = A - X
			 * ret A
			 */
			BPF_STMT(BPF_LD | BPF_IMM, 0x66),
			BPF_STMT(BPF_ALU | BPF_SUB | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.runs = RUNS({0x1, 0x66 }),
	},
	{
		.descr = "SUB default A",
		.insns = INSNS(
			/*
			 * A = A - -0x66
			 * ret A
			 */
			BPF_STMT(BPF_ALU | BPF_SUB | BPF_K, -0x66),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.runs = RUNS({0x1, 0x66 }),
	},
	{
		.descr = "MUL default X",
		.insns = INSNS(
			/*
			 * A = 0x42
			 * A = A * X
			 * ret A
			 */
			BPF_STMT(BPF_LD | BPF_IMM, 0x42),
			BPF_STMT(BPF_ALU | BPF_MUL | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.runs = RUNS({0x1, 0x0 }),
	},
	{
		.descr = "MUL default A",
		.insns = INSNS(
			/*
			 * A = A * 0x66
			 * ret A
			 */
			BPF_STMT(BPF_ALU | BPF_MUL | BPF_K, 0x66),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.runs = RUNS({0x1, 0x0 }),
	},
	{
		.descr = "DIV default X",
		.insns = INSNS(
			/*
			 * A = 0x42
			 * A = A / X ; this halt the filter execution if X is 0
			 * ret 0x42
			 */
			BPF_STMT(BPF_LD | BPF_IMM, 0x42),
			BPF_STMT(BPF_ALU | BPF_DIV | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_K, 0x42)
		),
		.runs = RUNS({0x1, 0x0 }),
	},
	{
		.descr = "DIV default A",
		.insns = INSNS(
			/*
			 * A = A / 1
			 * ret A
			 */
			BPF_STMT(BPF_ALU | BPF_DIV | BPF_K, 0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.runs = RUNS({0x1, 0x0 }),
	},
	{
		.descr = "MOD default X",
		.insns = INSNS(
			/*
			 * A = 0x42
			 * A = A mod X ; this halt the filter execution if X is 0
			 * ret 0x42
			 */
			BPF_STMT(BPF_LD | BPF_IMM, 0x42),
			BPF_STMT(BPF_ALU | BPF_MOD | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_K, 0x42)
		),
		.runs = RUNS({0x1, 0x0 }),
	},
	{
		.descr = "MOD default A",
		.insns = INSNS(
			/*
			 * A = A mod 1
			 * ret A
			 */
			BPF_STMT(BPF_ALU | BPF_MOD | BPF_K, 0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.runs = RUNS({0x1, 0x0 }),
	},
	{
		.descr = "JMP EQ default A",
		.insns = INSNS(
			/*
			 * cmp A, 0x0, 0, 1
			 * ret 0x42
			 * ret 0x66
			 */
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 0x42),
			BPF_STMT(BPF_RET | BPF_K, 0x66)
		),
		.runs = RUNS({0x1, 0x42 }),
	},
	{
		.descr = "JMP EQ default X",
		.insns = INSNS(
			/*
			 * A = 0x0
			 * cmp A, X, 0, 1
			 * ret 0x42
			 * ret 0x66
			 */
			BPF_STMT(BPF_LD | BPF_IMM, 0x0),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_X, 0x0, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 0x42),
			BPF_STMT(BPF_RET | BPF_K, 0x66)
		),
		.runs = RUNS({0x1, 0x42 }),
	},
	{
		.descr = "JNE signed compare, test 7",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0xffff0000),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_IMM, 0xfefbbc12),
			BPF_STMT(BPF_ALU | BPF_AND | BPF_X, 0),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xfefb0000, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_RET | BPF_K, 2)
		),
		.runs = RUNS({ 0, 2 }),
	},
	/*
	 * The corner cases of the conversion: a division by a zero X returns
	 * zero from the program, a device extension without a device returns
	 * the accumulator as is, an indirect load never is an extension, and
	 * the offset of a converted jump has to fit 16 bits.
	 */
	{
		.descr = "DIV_X by zero",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 8),
			BPF_STMT(BPF_LDX | BPF_IMM, 0),
			BPF_STMT(BPF_ALU | BPF_DIV | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 0 }),
	},
	{
		.descr = "MOD_X by zero",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 8),
			BPF_STMT(BPF_LDX | BPF_IMM, 0),
			BPF_STMT(BPF_ALU | BPF_MOD | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 0 }),
	},
	{
		.descr = "LD_IFINDEX without a device",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0x1234),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_IFINDEX),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 0x1234 }),
	},
	{
		.descr = "LD_HATYPE without a device",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_HATYPE),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 0 }),
	},
	{
		.descr = "LD_IND with an ancillary offset",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, 0),
			BPF_STMT(BPF_LD | BPF_W | BPF_IND,
				 SKF_AD_OFF + SKF_AD_ALU_XOR_X),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 0 }),
	},
	{
		.descr = "LDX_MSH with an ancillary offset",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 0x1234),
			BPF_STMT(BPF_LDX | BPF_B | BPF_MSH,
				 SKF_AD_OFF + SKF_AD_ALU_XOR_X),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 0 }),
	},
	{
		.descr = "BPF_MAXINSNS: jump over 1820 MSH",
		.fill = fill_jump_over_1820_msh,
		.data = DATA(0xfa, 0xfb, 0xfc, 0xfd),
		.runs = RUNS({ 4, 0xabababab }),
		.flags = CB_NOBLIND,
	},
	/*
	 * The first pass of the conversion knows no target ahead of a jump
	 * yet and takes minus the jump's own address for the offset, which
	 * falls out of range past 32K converted instructions. A classic
	 * program of that length is broken anyway, so this stays as it is.
	 */
	{
		.descr = "check: jump past 32K converted instructions",
		.fill = fill_late_jump,
		.flags = CB_FAIL,
	},
	{
		.descr = "BPF_MAXINSNS: jump over 1821 MSH",
		.fill = fill_jump_over_1821_msh,
		.flags = CB_FAIL,
	},
	{
		.descr = "jump taken over 254 LD_ABS",
		.fill = fill_jt_over_ld_abs,
		.data = DATA(1),
		.runs = RUNS({ 1, 3 }),
	},
	{
		.descr = "jump not taken over 254 LD_ABS",
		.fill = fill_jt_over_ld_abs,
		.data = DATA(0),
		.runs = RUNS({ 1, 2 }),
	},
	{
		.descr = "inverted jump taken over 254 LD_ABS",
		.fill = fill_jf_over_ld_abs,
		.data = DATA(0),
		.runs = RUNS({ 1, 3 }),
	},
	{
		.descr = "inverted jump not taken over 254 LD_ABS",
		.fill = fill_jf_over_ld_abs,
		.data = DATA(1),
		.runs = RUNS({ 1, 2 }),
	},
	{
		.descr = "check: empty program",
		.fill = fill_empty,
		.flags = CB_FAIL,
	},
	{
		.descr = "check: lsh by 32",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 1),
			BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 32),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: rsh by 32",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, 1),
			BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 32),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: ja out of range",
		.insns = INSNS(
			BPF_JUMP(BPF_JMP | BPF_JA, 1, 0, 0),
			BPF_STMT(BPF_RET | BPF_K, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: jt out of range",
		.insns = INSNS(
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: jf out of range",
		.insns = INSNS(
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: load of an unwritten M[]",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_MEM, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "check: M[] written on one path only",
		.insns = INSNS(
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
			BPF_STMT(BPF_ST, 0),
			BPF_STMT(BPF_LD | BPF_MEM, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.flags = CB_FAIL,
	},
	{
		.descr = "LD_PKTTYPE host",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PKTTYPE),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PACKET_HOST, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_RET | BPF_K, 2)
		),
		.runs = RUNS({ 14, 1 }),
		.flags = CB_PKT | CB_DSTMAC,
	},
	{
		.descr = "LD_PKTTYPE broadcast",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PKTTYPE),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PACKET_BROADCAST, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_RET | BPF_K, 2)
		),
		.data = DATA(0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
		.runs = RUNS({ 14, 1 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_PKTTYPE multicast",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PKTTYPE),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PACKET_MULTICAST, 0, 1),
			BPF_STMT(BPF_RET | BPF_K, 1),
			BPF_STMT(BPF_RET | BPF_K, 2)
		),
		.data = DATA(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01),
		.runs = RUNS({ 14, 1 }),
		.flags = CB_PKT,
	},
	/*
	 * The metadata the module put into its skb comes from the frames and
	 * the sending socket here: the protocol from the frame, the mark from
	 * the socket, the hash and the queue are whatever the stack picks and
	 * only compared with themselves, the device is a veth.
	 */
	{
		.descr = "LD_PROTOCOL",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 1),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 20, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_PROTOCOL),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 2),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 30, 1, 0),
			BPF_STMT(BPF_RET | BPF_K, 0),
			BPF_STMT(BPF_MISC | BPF_TXA, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(10, 20, 30, [12] = 0x08, [13] = 0x00),
		.runs = RUNS({ 14, ETH_P_IP }, { 100, ETH_P_IP }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_RXHASH",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_RXHASH),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_RXHASH),
			BPF_STMT(BPF_ALU | BPF_SUB | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x08, 0x00,
			     0x45, 0x00, 0x00, 0x54, 0xac, 0x8b, 0x40, 0x00, 0x40,
			     0x01, 0x90, 0x1b, 0x7f, 0x00, 0x00, 0x01),
		.runs = RUNS({ 100, 0 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_QUEUE",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_QUEUE),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_QUEUE),
			BPF_STMT(BPF_ALU | BPF_SUB | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 14, 0 }, { 100, 0 }),
		.flags = CB_PKT,
	},
	/*
	 * The tagged frames are full size: skb_vlan_untag() pulls two bytes
	 * behind the tag for its 802.3 check and frees a frame without them
	 * before any tap sees it, so 18 bytes never arrive while 20 do.
	 */
	{
		.descr = "LD_VLAN_TAG",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_VLAN_TAG),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x81, 0x00, 0xff, 0xff, 0x08, 0x00),
		.runs = RUNS({ 64, SKB_VLAN_TCI }, { 100, SKB_VLAN_TCI }),
		.flags = CB_PKT | CB_VLAN,
	},
	{
		.descr = "LD_VLAN_TAG_PRESENT",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x81, 0x00, 0xff, 0xff, 0x08, 0x00),
		.runs = RUNS({ 64, SKB_VLAN_PRESENT }, { 100, SKB_VLAN_PRESENT }),
		.flags = CB_PKT | CB_VLAN,
	},
	{
		.descr = "LD_LEN of a tagged frame",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_LEN, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x81, 0x00, 0xff, 0xff, 0x08, 0x00),
		.runs = RUNS({ 64, 60 }, { 100, 96 }),
		.flags = CB_PKT | CB_VLAN,
	},
	{
		.descr = "LD_VLAN_TAG_PRESENT, untagged",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.runs = RUNS({ 14, 0 }, { 100, 0 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_VLAN_TPID",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_VLAN_TPID),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x81, 0x00, 0xff, 0xff, 0x08, 0x00),
		.runs = RUNS({ 64, ETH_P_8021Q }, { 100, ETH_P_8021Q }),
		.flags = CB_PKT | CB_VLAN,
	},
	{
		.descr = "LD_RANDOM",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 SKF_AD_OFF + SKF_AD_RANDOM),
			BPF_STMT(BPF_RET | BPF_K, 1)
		),
		.runs = RUNS({ 1, 1 }),
	},
	/* A frame has at least its header: the loads of the module's short ones */
	{
		.descr = "LD_ABS_LL",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, SKF_LL_OFF),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_ABS, SKF_LL_OFF + 1),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(1, 2, 3),
		.runs = RUNS({ 14, 3 }, { 100, 3 }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_IND_LL",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_IMM, SKF_LL_OFF - 1),
			BPF_STMT(BPF_LDX | BPF_LEN, 0),
			BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
			BPF_STMT(BPF_MISC | BPF_TAX, 0),
			BPF_STMT(BPF_LD | BPF_B | BPF_IND, 0),
			BPF_STMT(BPF_RET | BPF_A, 0)
		),
		.data = DATA(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xff),
		.runs = RUNS({ 14, 14 }, { 15, 15 }, { 16, 0xff }),
		.flags = CB_PKT,
	},
	{
		.descr = "LD_IND byte frag",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, FRAG_OFF),
			BPF_STMT(BPF_LD | BPF_IND | BPF_B, 0x0),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.frag = FRAG(0x42, 0x00, 0x00, 0x00, 0x43, 0x44, 0x00, 0x00,
			     0x21, 0x07, 0x19, 0x83),
		.runs = RUNS({ FRAG_OFF, 0x42 }),
		.flags = CB_FRAG,
	},
	{
		.descr = "LD_IND halfword frag",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, FRAG_OFF),
			BPF_STMT(BPF_LD | BPF_IND | BPF_H, 0x4),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.frag = FRAG(0x42, 0x00, 0x00, 0x00, 0x43, 0x44, 0x00, 0x00,
			     0x21, 0x07, 0x19, 0x83),
		.runs = RUNS({ FRAG_OFF, 0x4344 }),
		.flags = CB_FRAG,
	},
	{
		.descr = "LD_IND word frag",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, FRAG_OFF),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, 0x8),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.frag = FRAG(0x42, 0x00, 0x00, 0x00, 0x43, 0x44, 0x00, 0x00,
			     0x21, 0x07, 0x19, 0x83),
		.runs = RUNS({ FRAG_OFF, 0x21071983 }),
		.flags = CB_FRAG,
	},
	{
		.descr = "LD_IND halfword mixed head/frag",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, FRAG_OFF),
			BPF_STMT(BPF_LD | BPF_IND | BPF_H, -0x1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3e] = 0x25, [0x3f] = 0x05),
		.frag = FRAG(0x19, 0x82),
		.runs = RUNS({ FRAG_OFF, 0x0519 }),
		.flags = CB_FRAG,
	},
	{
		.descr = "LD_IND word mixed head/frag",
		.insns = INSNS(
			BPF_STMT(BPF_LDX | BPF_IMM, FRAG_OFF),
			BPF_STMT(BPF_LD | BPF_IND | BPF_W, -0x2),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3e] = 0x25, [0x3f] = 0x05),
		.frag = FRAG(0x19, 0x82),
		.runs = RUNS({ FRAG_OFF, 0x25051982 }),
		.flags = CB_FRAG,
	},
	{
		.descr = "LD_ABS byte frag",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_B, FRAG_OFF),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.frag = FRAG(0x42, 0x00, 0x00, 0x00, 0x43, 0x44, 0x00, 0x00,
			     0x21, 0x07, 0x19, 0x83),
		.runs = RUNS({ FRAG_OFF, 0x42 }),
		.flags = CB_FRAG,
	},
	{
		.descr = "LD_ABS halfword frag",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_H, FRAG_OFF + 4),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.frag = FRAG(0x42, 0x00, 0x00, 0x00, 0x43, 0x44, 0x00, 0x00,
			     0x21, 0x07, 0x19, 0x83),
		.runs = RUNS({ FRAG_OFF, 0x4344 }),
		.flags = CB_FRAG,
	},
	{
		.descr = "LD_ABS word frag",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, FRAG_OFF + 8),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.frag = FRAG(0x42, 0x00, 0x00, 0x00, 0x43, 0x44, 0x00, 0x00,
			     0x21, 0x07, 0x19, 0x83),
		.runs = RUNS({ FRAG_OFF, 0x21071983 }),
		.flags = CB_FRAG,
	},
	{
		.descr = "LD_ABS halfword mixed head/frag",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_H, FRAG_OFF - 1),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3e] = 0x25, [0x3f] = 0x05),
		.frag = FRAG(0x19, 0x82),
		.runs = RUNS({ FRAG_OFF, 0x0519 }),
		.flags = CB_FRAG,
	},
	{
		.descr = "LD_ABS word mixed head/frag",
		.insns = INSNS(
			BPF_STMT(BPF_LD | BPF_ABS | BPF_W, FRAG_OFF - 2),
			BPF_STMT(BPF_RET | BPF_A, 0x0)
		),
		.data = DATA([0x3e] = 0x25, [0x3f] = 0x05),
		.frag = FRAG(0x19, 0x82),
		.runs = RUNS({ FRAG_OFF, 0x25051982 }),
		.flags = CB_FRAG,
	},
};

/*
 * Rewrite the returns for the expected result: it stays, every other
 * constant becomes zero and a returned accumulator gets compared at the
 * end, so that a wrong result drops the packet. A result of zero is a
 * drop as is.
 */
static int rewrite_returns(struct sock_filter *insns, int cnt, __u32 result)
{
	bool ret_a = false;
	int i, n = cnt;

	if (!result)
		return cnt;
	for (i = 0; i < cnt; i++) {
		if (insns[i].code == (BPF_RET | BPF_K)) {
			insns[i].k = insns[i].k == result ? result : 0;
		} else if (insns[i].code == (BPF_RET | BPF_A)) {
			insns[i] = JUMP(BPF_JMP | BPF_JA, cnt - i - 1, 0, 0);
			ret_a = true;
		}
	}
	if (!ret_a)
		return cnt;
	insns[n++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, result, 0, 1);
	insns[n++] = STMT(BPF_RET | BPF_K, result);
	insns[n++] = STMT(BPF_RET | BPF_K, 0);
	return n;
}

static int attach_filter(int fd, struct sock_filter *insns, int cnt)
{
	struct sock_fprog fprog = { .len = cnt, .filter = insns };

	return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
}

/* -1 for a dropped datagram, -2 for a failure, else the length received */
static int run_unix(struct sock_filter *insns, int cnt, const __u8 *pkt, int len, __u8 *buf,
		    const char *desc)
{
	int sv[2], n = -2;

	if (!ASSERT_OK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv), "socketpair"))
		return -2;
	/* Room for dgram_max, which the kernel doubles: four 64K pages exceed the default */
	if (!ASSERT_OK(setsockopt(sv[0], SOL_SOCKET, SO_SNDBUFFORCE, &dgram_max,
				  sizeof(dgram_max)), "sndbuf") ||
	    !ASSERT_OK(attach_filter(sv[1], insns, cnt), desc))
		goto out;
	if (!ASSERT_EQ(send(sv[0], pkt, len, 0), len, desc))
		goto out;
	n = recv(sv[1], buf, dgram_max, MSG_DONTWAIT);
	if (n < 0 && ASSERT_EQ(errno, EAGAIN, desc))
		n = -1;
out:
	close(sv[0]);
	close(sv[1]);
	return n;
}

static struct {
	struct nstoken *tok;
	int tx, v0, v1;
	__u8 v1_mac[ETH_ALEN];
} net;

static int net_setup(void)
{
	struct ifreq ifr = {};
	int mark = SKB_MARK;

	net.tx = -1;
	if (!ASSERT_OK(make_netns(NETNS), "netns"))
		return -1;
	net.tok = open_netns(NETNS);
	if (!ASSERT_OK_PTR(net.tok, "open netns"))
		return -1;
	SYS(fail, "ip link add v0 type veth peer name v1");
	SYS(fail, "sysctl -qw net.ipv6.conf.v0.disable_ipv6=1 net.ipv6.conf.v1.disable_ipv6=1");
	SYS(fail, "ip link set v0 up");
	SYS(fail, "ip link set v1 up");
	net.v0 = if_nametoindex("v0");
	net.v1 = if_nametoindex("v1");
	net.tx = socket(AF_PACKET, SOCK_RAW, 0);
	if (!ASSERT_GE(net.tx, 0, "tx socket") ||
	    !ASSERT_OK(setsockopt(net.tx, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)), "mark"))
		goto fail;
	strcpy(ifr.ifr_name, "v1");
	if (!ASSERT_OK(ioctl(net.tx, SIOCGIFHWADDR, &ifr), "v1 mac"))
		goto fail;
	memcpy(net.v1_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
fail:
	return -1;
}

static void net_teardown(void)
{
	if (net.tx >= 0)
		close(net.tx);
	if (net.tok)
		close_netns(net.tok);
	remove_netns(NETNS);
}

/* The same, for a frame from v0 to v1 */
static int run_packet(struct sock_filter *insns, int cnt, const __u8 *frame, int len, __u8 *buf,
		      const char *desc)
{
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = net.v1,
	};
	struct pollfd pfd;
	int rx, n = -2;

	rx = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (!ASSERT_GE(rx, 0, "rx socket"))
		return -2;
	if (!ASSERT_OK(bind(rx, (struct sockaddr *)&sll, sizeof(sll)), "bind") ||
	    !ASSERT_OK(attach_filter(rx, insns, cnt), desc))
		goto out;
	sll.sll_protocol = 0;
	sll.sll_ifindex = net.v0;
	sll.sll_halen = ETH_ALEN;
	if (!ASSERT_EQ(sendto(net.tx, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll)), len,
		       desc))
		goto out;
	pfd = (struct pollfd){ .fd = rx, .events = POLLIN };
	if (poll(&pfd, 1, 200) <= 0) {
		n = -1;
		goto out;
	}
	n = recv(rx, buf, dgram_max, MSG_DONTWAIT);
	if (n < 0 && ASSERT_EQ(errno, EAGAIN, desc))
		n = -1;
out:
	close(rx);
	return n;
}

static void run_case(const struct cbpf_case *c, struct sock_filter *orig, struct sock_filter *insns,
		     __u8 *pkt, __u8 *buf)
{
	int cnt, nr, i, len, seen, n, want;
	char desc[96];

	if (c->fill) {
		cnt = c->fill(orig);
	} else {
		cnt = c->cnt;
		memcpy(orig, c->insns, cnt * sizeof(*orig));
	}
	if (c->flags & CB_FAIL) {
		int sv[2];

		if (!ASSERT_OK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv), "socketpair"))
			return;
		if (ASSERT_ERR(attach_filter(sv[1], orig, cnt), c->descr))
			ASSERT_EQ(errno, EINVAL, c->descr);
		close(sv[0]);
		close(sv[1]);
		return;
	}
	for (i = 0; i < c->nr_runs; i++) {
		__u32 result = c->runs[i].result;

		len = c->runs[i].len;
		memset(pkt, 0, dgram_max);
		if (c->flags & CB_FRAG) {
			/* The data ends with the head, the frag data starts there, a page of it */
			if (c->data_len)
				memcpy(pkt + len - 0x40, c->data, c->data_len);
			memcpy(pkt + len, c->frag, c->frag_len);
			len += page_size;
		} else if (c->data_len) {
			memcpy(pkt, c->data, c->data_len < len ? c->data_len : len);
		}
		if (c->flags & CB_IFINDEX)
			result = net.v1;
		if (c->flags & CB_DSTMAC)
			memcpy(pkt, net.v1_mac, ETH_ALEN);
		memcpy(insns, orig, cnt * sizeof(*insns));
		nr = c->flags & CB_RAW ? cnt : rewrite_returns(insns, cnt, result);
		snprintf(desc, sizeof(desc), "%s len=%d", c->descr, len);
		if (c->flags & CB_PKT) {
			if (len < ETH_HLEN)
				len = ETH_HLEN;
			n = run_packet(insns, nr, pkt, len, buf, desc);
			/* The stack pulled the four bytes of the tag out */
			seen = len - (c->flags & CB_VLAN ? 4 : 0);
		} else {
			n = run_unix(insns, nr, pkt, len, buf, desc);
			seen = len;
		}
		if (n == -2)
			return;
		want = !result ? -1 : result < seen ? (int)result : seen;
		ASSERT_EQ(n, want, desc);
	}
}

/*
 * Loads of every width at every offset around the end of the head of a
 * four page datagram: short of it they read the head, past it the frag
 * data and in between they straddle the two. The same through an index.
 */
static void sweep_boundary(struct sock_filter *insns, __u8 *pkt, __u8 *buf)
{
	static const int sizes[] = { BPF_B, BPF_H, BPF_W };
	int s, ind, off, n, len = 4 * page_size, head = 3 * page_size;
	char desc[64];

	/* Odd bytes, so that no load reads zero, which is a drop */
	for (off = 0; off < len; off++)
		pkt[off] = ((off * 7 + 3) ^ (off >> 8)) | 1;
	for (s = 0; s < ARRAY_SIZE(sizes); s++) {
		int width = 1 << s;

		for (off = head - SWEEP_SPAN; off + width <= head + SWEEP_SPAN; off++) {
			__u32 v = 0;
			int b;

			for (b = 0; b < width; b++)
				v = v << 8 | pkt[off + b];
			for (ind = 0; ind < 2; ind++) {
				n = 0;
				if (ind) {
					insns[n++] = STMT(BPF_LDX | BPF_IMM, head);
					insns[n++] = STMT(BPF_LD | BPF_IND | sizes[s], off - head);
				} else {
					insns[n++] = STMT(BPF_LD | BPF_ABS | sizes[s], off);
				}
				insns[n++] = STMT(BPF_RET | BPF_A, 0);
				snprintf(desc, sizeof(desc), "boundary %s width=%d off=%d",
					 ind ? "ind" : "abs", width, off - head);
				n = rewrite_returns(insns, n, v);
				n = run_unix(insns, n, pkt, len, buf, desc);
				ASSERT_EQ(n, v < (__u32)len ? (int)v : len, desc);
			}
		}
	}
}

/* What the forms return when taken and not: the true target, the next insn, the false target */
static __u32 jump_result(int form, bool taken)
{
	if (form == 0)
		return taken ? 2 : 1;
	if (form == 1)
		return taken ? 1 : 3;
	return taken ? 2 : 3;
}

static bool cmp32(int op, __u32 a, __u32 k)
{
	switch (op) {
	case BPF_JEQ:
		return a == k;
	case BPF_JGT:
		return a > k;
	case BPF_JGE:
		return a >= k;
	default:
		return a & k;
	}
}

/*
 * The conditional jumps in their three forms, which the conversion emits
 * differently: only a true target, only a false one, which inverts the
 * condition, and both. The immediates with the sign bit go through a
 * register, as the accumulator compares unsigned in 32 bits.
 */
static void sweep_jumps(struct sock_filter *insns, __u8 *pkt, __u8 *buf)
{
	static const int ops[] = { BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JSET };
	static const __u32 vals[] = { 0, 1, 0x7fffffff, 0x80000000, 0x80000001, 0xffffffff };
	int o, src, form, a, k, n;
	char desc[80];

	for (o = 0; o < ARRAY_SIZE(ops); o++) {
		for (src = 0; src < 2; src++) {
			for (form = 0; form < 3; form++) {
				for (a = 0; a < ARRAY_SIZE(vals); a++) {
					for (k = 0; k < ARRAY_SIZE(vals); k++) {
						bool taken = cmp32(ops[o], vals[a], vals[k]);
						__u32 result = jump_result(form, taken);

						insns[0] = STMT(BPF_LD | BPF_IMM, vals[a]);
						insns[1] = STMT(BPF_LDX | BPF_IMM, vals[k]);
						insns[2] = JUMP(BPF_JMP | ops[o] |
								    (src ? BPF_X : BPF_K),
								    src ? 0 : vals[k],
								    form == 1 ? 0 : 1,
								    form == 0 ? 0 : 2);
						insns[3] = STMT(BPF_RET | BPF_K, 1);
						insns[4] = STMT(BPF_RET | BPF_K, 2);
						insns[5] = STMT(BPF_RET | BPF_K, 3);
						snprintf(desc, sizeof(desc),
							 "jump op=0x%x %c a=0x%x k=0x%x form=%d",
							 ops[o], src ? 'x' : 'k', vals[a], vals[k],
							 form);
						n = rewrite_returns(insns, 6, result);
						n = run_unix(insns, n, pkt, 4, buf, desc);
						ASSERT_EQ(n, (int)result, desc);
					}
				}
			}
		}
	}
}

static __u32 alu32(int op, __u32 a, __u32 k)
{
	switch (op) {
	case BPF_ADD:
		return a + k;
	case BPF_SUB:
		return a - k;
	case BPF_MUL:
		return a * k;
	case BPF_DIV:
		return k ? a / k : 0;
	case BPF_OR:
		return a | k;
	case BPF_AND:
		return a & k;
	case BPF_LSH:
		return a << (k & 31);
	case BPF_RSH:
		return a >> (k & 31);
	case BPF_XOR:
		return a ^ k;
	default:
		return k ? a % k : 0;
	}
}

/*
 * The arithmetic on operands with the sign bit, 32 bits wide and unsigned
 * whatever the immediate looks like, and the counts a shift masks.
 */
static void sweep_alu(struct sock_filter *insns, __u8 *pkt, __u8 *buf)
{
	static const int ops[] = {
		BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_OR, BPF_AND, BPF_LSH, BPF_RSH, BPF_XOR,
		BPF_MOD,
	};
	static const __u32 vals[] = { 0, 1, 31, 32, 33, 0x7fffffff, 0x80000000, 0xffffffff };
	int o, src, a, k, n;
	char desc[80];

	for (o = 0; o < ARRAY_SIZE(ops); o++) {
		bool shift = ops[o] == BPF_LSH || ops[o] == BPF_RSH;
		bool div = ops[o] == BPF_DIV || ops[o] == BPF_MOD;

		for (src = 0; src < 2; src++) {
			for (a = 0; a < ARRAY_SIZE(vals); a++) {
				for (k = 0; k < ARRAY_SIZE(vals); k++) {
					__u32 result = alu32(ops[o], vals[a], vals[k]);

					/* The checker rejects these immediates */
					if (!src && ((shift && vals[k] >= 32) || (div && !vals[k])))
						continue;
					insns[0] = STMT(BPF_LD | BPF_IMM, vals[a]);
					insns[1] = STMT(BPF_LDX | BPF_IMM, vals[k]);
					insns[2] = STMT(BPF_ALU | ops[o] | (src ? BPF_X : BPF_K),
							src ? 0 : vals[k]);
					insns[3] = STMT(BPF_RET | BPF_A, 0);
					snprintf(desc, sizeof(desc), "alu op=0x%x %c a=0x%x k=0x%x",
						 ops[o], src ? 'x' : 'k', vals[a], vals[k]);
					n = rewrite_returns(insns, 4, result);
					n = run_unix(insns, n, pkt, 4, buf, desc);
					ASSERT_EQ(n, !result ? -1 : result < 4 ? (int)result : 4,
						  desc);
				}
			}
		}
	}
	for (a = 0; a < ARRAY_SIZE(vals); a++) {
		insns[0] = STMT(BPF_LD | BPF_IMM, vals[a]);
		insns[1] = STMT(BPF_ALU | BPF_NEG, 0);
		insns[2] = STMT(BPF_RET | BPF_A, 0);
		snprintf(desc, sizeof(desc), "alu neg a=0x%x", vals[a]);
		n = rewrite_returns(insns, 3, -vals[a]);
		n = run_unix(insns, n, pkt, 4, buf, desc);
		ASSERT_EQ(n, !vals[a] ? -1 : -vals[a] < 4 ? (int)-vals[a] : 4, desc);
	}
}

/* Every M[] slot written from A and X and read back into A and X, summed up */
static void sweep_mem(struct sock_filter *insns, __u8 *pkt, __u8 *buf)
{
	__u32 sum = 0;
	int k, n = 0;

	for (k = 0; k < BPF_MEMWORDS; k++) {
		__u32 v = 0x01010101 * (k + 1);

		insns[n++] = STMT(BPF_LD | BPF_IMM, v);
		if (k & 1) {
			insns[n++] = STMT(BPF_MISC | BPF_TAX, 0);
			insns[n++] = STMT(BPF_STX, k);
		} else {
			insns[n++] = STMT(BPF_ST, k);
		}
		sum += v;
	}
	insns[n++] = STMT(BPF_LD | BPF_IMM, 0);
	for (k = 0; k < BPF_MEMWORDS; k++) {
		if (k & 1) {
			insns[n++] = STMT(BPF_LDX | BPF_MEM, k);
			insns[n++] = STMT(BPF_ALU | BPF_ADD | BPF_X, 0);
		} else {
			insns[n++] = STMT(BPF_MISC | BPF_TAX, 0);
			insns[n++] = STMT(BPF_LD | BPF_MEM, k);
			insns[n++] = STMT(BPF_ALU | BPF_ADD | BPF_X, 0);
		}
	}
	insns[n++] = STMT(BPF_RET | BPF_A, 0);
	n = rewrite_returns(insns, n, sum);
	n = run_unix(insns, n, pkt, 4, buf, "M[] slots");
	ASSERT_EQ(n, 4, "M[] slots");
}

static bool blinded;

static void run_group(unsigned int group, struct sock_filter *orig, struct sock_filter *insns,
		      __u8 *pkt, __u8 *buf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++)
		if ((cases[i].flags & (CB_FAIL | CB_PKT | CB_FRAG)) == group &&
		    !(blinded && cases[i].flags & CB_NOBLIND))
			run_case(&cases[i], orig, insns, pkt, buf);
}

static void run_unix_groups(struct sock_filter *orig, struct sock_filter *insns, __u8 *pkt,
			    __u8 *buf)
{
	run_group(0, orig, insns, pkt, buf);
	sweep_jumps(insns, pkt, buf);
	sweep_alu(insns, pkt, buf);
	sweep_mem(insns, pkt, buf);
}

void serial_test_jit_insns_cbpf(void)
{
	const char *harden = "/proc/sys/net/core/bpf_jit_harden";
	const char *optmem = "/proc/sys/net/core/optmem_max";
	char old[16] = {}, old_optmem[16] = {};
	struct sock_filter *orig, *insns;
	__u8 *pkt, *buf;

	page_size = getpagesize();
	dgram_max = 4 * page_size;
	orig = calloc(BPF_MAXINSNS + 4, sizeof(*orig));
	insns = calloc(BPF_MAXINSNS + 4, sizeof(*insns));
	pkt = calloc(1, dgram_max);
	buf = calloc(1, dgram_max);
	if (!ASSERT_OK_PTR(orig, "orig") || !ASSERT_OK_PTR(insns, "insns") ||
	    !ASSERT_OK_PTR(pkt, "pkt") || !ASSERT_OK_PTR(buf, "buf"))
		goto out;
	/* The longest programs convert to over half a megabyte */
	if (sysctl_set_or_fail(optmem, old_optmem, "4194304"))
		goto out;
	if (test__start_subtest("classic"))
		run_unix_groups(orig, insns, pkt, buf);
	if (test__start_subtest("checker"))
		run_group(CB_FAIL, orig, insns, pkt, buf);
	if (test__start_subtest("frags")) {
		run_group(CB_FRAG, orig, insns, pkt, buf);
		sweep_boundary(insns, pkt, buf);
	}
	if (test__start_subtest("packets")) {
		if (!net_setup())
			run_group(CB_PKT, orig, insns, pkt, buf);
		net_teardown();
	}
	/* The constants of the conversion blinded, which takes a JIT */
	if (test__start_subtest("blinded")) {
		if (!is_jit_enabled()) {
			test__skip();
		} else if (!sysctl_set_or_fail(harden, old, "2")) {
			blinded = true;
			run_unix_groups(orig, insns, pkt, buf);
			run_group(CB_FRAG, orig, insns, pkt, buf);
			blinded = false;
			sysctl_set_or_fail(harden, NULL, old);
		}
	}
	sysctl_set_or_fail(optmem, NULL, old_optmem);
out:
	free(buf);
	free(pkt);
	free(insns);
	free(orig);
}
