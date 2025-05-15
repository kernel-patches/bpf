#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <linux/icmpv6.h>
#include <linux/in.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

union macaddr {
	struct {
		__u32 p1;
		__u16 p2;
	};
	__u8 addr[6];
};

union v6addr {
	struct {
		__u32 p1;
		__u32 p2;
		__u32 p3;
		__u32 p4;
	};
	struct {
		__u64 d1;
		__u64 d2;
	};
	__u8 addr[16];
};

/* Number of extension headers that can be skipped */
#define IPV6_MAX_HEADERS 4

#define NEXTHDR_HOP             0       /* Hop-by-hop option header. */
#define NEXTHDR_TCP             6       /* TCP segment. */
#define NEXTHDR_UDP             17      /* UDP message. */
#define NEXTHDR_IPV6            41      /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING         43      /* Routing header. */
#define NEXTHDR_FRAGMENT        44      /* Fragmentation/reassembly header. */
#define NEXTHDR_GRE             47      /* GRE header. */
#define NEXTHDR_ESP             50      /* Encapsulating security payload. */
#define NEXTHDR_AUTH            51      /* Authentication header. */
#define NEXTHDR_ICMP            58      /* ICMP for IPv6. */
#define NEXTHDR_NONE            59      /* No next header */
#define NEXTHDR_DEST            60      /* Destination options header. */
#define NEXTHDR_SCTP            132     /* SCTP message. */
#define NEXTHDR_MOBILITY        135     /* Mobility header. */

#define NEXTHDR_MAX             255

#define IPV6_SADDR_OFF		offsetof(struct ipv6hdr, saddr)
#define IPV6_DADDR_OFF		offsetof(struct ipv6hdr, daddr)

#define NEXTHDR_ICMP 58
#define ICMP6_NS_MSG_TYPE		135

#define DROP_INVALID		-134
#define DROP_INVALID_EXTHDR	-156
#define DROP_FRAG_NOSUPPORT	-157

#define ctx_load_bytes		skb_load_bytes

#define DEFINE_FUNC_CTX_POINTER(FIELD)						\
static __always_inline void *							\
ctx_ ## FIELD(const struct __sk_buff *ctx)					\
{										\
	void *ptr;								\
										\
	/* LLVM may generate u32 assignments of ctx->{data,data_end,data_meta}.	\
	 * With this inline asm, LLVM loses track of the fact this field is on	\
	 * 32 bits.								\
	 */									\
	asm volatile("%0 = *(u32 *)(%1 + %2)"					\
		     : "=r"(ptr)						\
		     : "r"(ctx), "i"(offsetof(struct __sk_buff, FIELD)));	\
	return ptr;								\
}
/* This defines ctx_data(). */
DEFINE_FUNC_CTX_POINTER(data)
#undef DEFINE_FUNC_CTX_POINTER


static __always_inline int ipv6_optlen(const struct ipv6_opt_hdr *opthdr)
{
	return (opthdr->hdrlen + 1) << 3;
}

static __always_inline int ipv6_authlen(const struct ipv6_opt_hdr *opthdr)
{
	return (opthdr->hdrlen + 2) << 2;
}

static __always_inline int ipv6_hdrlen_offset(struct __sk_buff *ctx,
					      __u8 *nexthdr, int l3_off)
{
	int i, len = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr opthdr __attribute__((aligned(8)));
	__u8 nh = *nexthdr;

#pragma unroll
	for (i = 0; i < IPV6_MAX_HEADERS; i++) {
		switch (nh) {
		case NEXTHDR_NONE:
			return DROP_INVALID_EXTHDR;

		case NEXTHDR_FRAGMENT:
			return DROP_FRAG_NOSUPPORT;

		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_AUTH:
		case NEXTHDR_DEST:
			if (bpf_skb_load_bytes(ctx, l3_off + len, &opthdr,
					   sizeof(opthdr)) < 0)
				return DROP_INVALID;

			if (nh == NEXTHDR_AUTH)
				len += ipv6_authlen(&opthdr);
			else
				len += ipv6_optlen(&opthdr);

			nh = opthdr.nexthdr;
			break;

		default:
			bpf_printk("OKOK %d, len: %d", *nexthdr, len);
			*nexthdr = nh;
			return len;
		}
	}

	bpf_printk("KO INVALID EXTHDR");

	/* Reached limit of supported extension headers */
	return DROP_INVALID_EXTHDR;
}
static __always_inline
bool icmp6_ndisc_validate(struct __sk_buff *ctx, struct ipv6hdr *ip6,
			  union macaddr *mac, union macaddr *smac,
			  union v6addr *sip, union v6addr *tip)
{
	__u8 nexthdr;
	struct icmp6hdr *icmp;
	int l3_off, l4_off;

	l3_off = (__u8 *)ip6 - (__u8 *)ctx_data(ctx);
	bpf_printk("pre ipv6_hdrlen_offset");
	l4_off = ipv6_hdrlen_offset(ctx, &nexthdr, l3_off);
	bpf_printk("post ipv6_hdrlen_offset");

	if (l4_off < 0 || nexthdr != NEXTHDR_ICMP) {
		bpf_printk("KO 1");
		return false;
	}

	icmp = (struct icmp6hdr *)((__u8 *)ctx_data(ctx) + l4_off);
	if (icmp->icmp6_type != ICMP6_NS_MSG_TYPE) {
		bpf_printk("KO 2");
		return false;
	}

	/* Extract fields */
#if 0
	eth_load_saddr(ctx, &smac->addr[0], 0);
	eth_load_daddr(ctx, &mac->addr[0], 0);
	ipv6_load_saddr(ctx, l3_off, sip);
	ipv6_load_daddr(ctx, l3_off, tip);
#endif
	bpf_printk("ACK ");

	return true;
}

SEC("classifier")
__description("agressive optimization due to uninitialized variable")
#if __clang_major__ >= 21
__failure __msg("last insn is bpf_unreachable, due to uninitialized var")
#else
__failure __msg("last insn is not an exit or jmp")
#endif
int classifier_uninit_var(struct __sk_buff *skb)
{
	struct ipv6hdr *ip6 = NULL;
	union macaddr mac, smac;
	union v6addr sip, tip;

	bpf_printk("Start");
	icmp6_ndisc_validate(skb, ip6, &mac, &smac, &sip, &tip);
	bpf_printk("End");

	return 0;
}

extern void bpf_unreachable(void) __weak __ksym;

SEC("socket")
__description("bpf_unreachable as the last func insn")
__failure __msg("last insn is bpf_unreachable, due to uninitialized var")
__naked void bpf_unreachable_at_func_end(void)
{
	asm volatile (
	"r0 = 0;"
	"call %[bpf_unreachable];"
	:
	: __imm(bpf_unreachable)
	: __clobber_all);
}

SEC("socket")
__description("dead code bpf_unreachable in the middle of code")
__success
__naked void dead_bpf_unreachable_in_middle(void)
{
	asm volatile (
	"r0 = 0;"
	"if r0 == 0 goto +1;"
	"call %[bpf_unreachable];"
	"exit;"
	:
	: __imm(bpf_unreachable)
	: __clobber_all);
}

SEC("socket")
__description("reachable bpf_unreachable in the middle of code")
__failure __msg("unexpected hit bpf_unreachable, due to uninit var or incorrect verification?")
__naked void live_bpf_unreachable_in_middle(void)
{
	asm volatile (
	"r0 = 0;"
	"if r0 == 1 goto +1;"
	"call %[bpf_unreachable];"
	"exit;"
	:
	: __imm(bpf_unreachable)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
