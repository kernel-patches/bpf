// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#if (defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86) || \
	(defined(__TARGET_ARCH_riscv) && __riscv_xlen == 64) || \
	defined(__TARGET_ARCH_arm) || defined(__TARGET_ARCH_s390) || \
	defined(__TARGET_ARCH_loongarch)) && \
	__clang_major__ >= 18

SEC("socket")
__description("BSWAP, 16")
__success __success_unpriv __retval(0x23ff)
__naked void bswap_16(void)
{
	asm volatile ("					\
	r0 = 0xff23;					\
	r0 = bswap16 r0;				\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("BSWAP, 32")
__success __success_unpriv __retval(0x23ff0000)
__naked void bswap_32(void)
{
	asm volatile ("					\
	r0 = 0xff23;					\
	r0 = bswap32 r0;				\
	exit;						\
"	::: __clobber_all);
}

SEC("socket")
__description("BSWAP, 64")
__success __success_unpriv __retval(0x34ff12ff)
__naked void bswap_64(void)
{
	asm volatile ("					\
	r0 = %[u64_val] ll;					\
	r0 = bswap64 r0;				\
	exit;						\
"	:
	: [u64_val]"i"(0xff12ff34ff56ff78ull)
	: __clobber_all);
}

SEC("socket")
__description("BSWAP16 network - port number routing with tnum")
__success __log_level(2)
__msg("w0 &= 16128 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))") __msg("r0 = bswap16 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=63,var_off=(0x0; 0x3f))")
__naked void bswap16_port_routing(void)
{
	asm volatile ("					\
	/* Simulate reading port number from network packet */	\
	call %[bpf_get_prandom_u32];			\
	/* Extract byte range 0x0000-0x3f00 */		\
	w0 &= 0x3f00;					\
	/* Convert network byte order to host order */	\
	r0 = bswap16 r0;				\
	/* Verify range - if tnum works correctly, trap path is dead code */	\
	if r0 > 0x3f goto trap_%=;			\
	r0 = 0;						\
	exit;						\
trap_%=:	/* Should never reach - r0 must be in [0, 0x3f] */	\
	r1 = 42;	/* r1 = scalar for trap */	\
	r0 = *(u64 *)(r1 + 0);	/* Invalid: scalar dereference */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("BSWAP32 network - IPv4 subnet routing with tnum")
__success __log_level(2)
__msg("w0 &= 16128 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))") __msg("r0 = bswap32 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=0x3f0000,var_off=(0x0; 0x3f0000))")
__naked void bswap32_ipv4_subnet_routing(void)
{
	asm volatile ("					\
	/* Simulate reading IPv4 from network packet */	\
	call %[bpf_get_prandom_u32];			\
	/* Extract second byte (subnet ID) 0x0000-0x3f00 */	\
	w0 &= 0x3f00;					\
	/* Convert network byte order to host order */	\
	r0 = bswap32 r0;				\
	/* Verify bswap32 result - if tnum works correctly, trap path is dead code */	\
	if r0 > 0x3f0000 goto trap_%=;			\
	r0 = 0;						\
	exit;						\
trap_%=:	/* Should never reach - r0 must be in [0, 0x3f0000] */	\
	r1 = 42;	/* r1 = scalar for trap */	\
	r0 = *(u64 *)(r1 + 0);	/* Invalid: scalar dereference */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("BSWAP64 network - IPv6 subnet routing with tnum")
__success __log_level(2)
__msg("r0 &= 16128 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))") __msg("r0 = bswap64 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=0x3f000000000000,smax32=umax32=0,var_off=(0x0; 0x3f000000000000))")
__naked void bswap64_ipv6_subnet_routing(void)
{
	asm volatile ("					\
	/* Simulate reading IPv6 from network packet */	\
	call %[bpf_get_prandom_u32];			\
	/* Extract second byte (subnet ID) 0x0000-0x3f00 */	\
	r0 &= 0x3f00;					\
	/* Convert network byte order to host order */	\
	r0 = bswap64 r0;				\
	/* Verify bswap64 result - if tnum works correctly, trap path is dead code */	\
	r2 = 0x3f000000000000 ll;	/* Load 64-bit constant */	\
	if r0 > r2 goto trap_%=;			\
	r0 = 0;						\
	exit;						\
trap_%=:	/* Should never reach - r0 must be in [0, 0x3f000000000000] */	\
	r1 = 42;	/* r1 = scalar for trap */	\
	r0 = *(u64 *)(r1 + 0);	/* Invalid: scalar dereference */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("BE16 (to big endian) network - endian conversion with tnum")
__success __log_level(2)
__msg("w0 &= 16128 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
/* Little endian: be16 = bswap16 */
__msg("r0 = be16 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=63,var_off=(0x0; 0x3f))")
#else
/* Big endian: be16 = _to_u16 (truncation) */
__msg("r0 = be16 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#endif
__naked void be16_network(void)
{
	asm volatile ("					\
	/* Simulate reading from network packet */	\
	call %[bpf_get_prandom_u32];			\
	/* Extract byte range 0x0000-0x3f00 */		\
	w0 &= 0x3f00;					\
	/* Convert to big endian */			\
	r0 = be16 r0;					\
	/* Verify range - if tnum works correctly, trap path is dead code */	\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	"if r0 > 0x3f goto trap_%=;			\
"
#else
	"if r0 > 0x3f00 goto trap_%=;			\
"
#endif
	"r0 = 0;					\
	exit;						\
trap_%=:	/* Should never reach */		\
	r1 = 42;	/* r1 = scalar for trap */	\
	r0 = *(u64 *)(r1 + 0);	/* Invalid: scalar dereference */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("BE32 (to big endian) network - endian conversion with tnum")
__success __log_level(2)
__msg("w0 &= 16128 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
/* Little endian: be32 = bswap32 */
__msg("r0 = be32 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=0x3f0000,var_off=(0x0; 0x3f0000))")
#else
/* Big endian: be32 = _to_u32 (truncation) */
__msg("r0 = be32 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#endif
__naked void be32_network(void)
{
	asm volatile ("					\
	/* Simulate reading from network packet */	\
	call %[bpf_get_prandom_u32];			\
	/* Extract byte range 0x0000-0x3f00 */		\
	w0 &= 0x3f00;					\
	/* Convert to big endian */			\
	r0 = be32 r0;					\
	/* Verify range - if tnum works correctly, trap path is dead code */	\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	"if r0 > 0x3f0000 goto trap_%=;			\
"
#else
	"if r0 > 0x3f00 goto trap_%=;			\
"
#endif
	"r0 = 0;					\
	exit;						\
trap_%=:	/* Should never reach */		\
	r1 = 42;	/* r1 = scalar for trap */	\
	r0 = *(u64 *)(r1 + 0);	/* Invalid: scalar dereference */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("BE64 (to big endian) network - endian conversion with tnum")
__success __log_level(2)
__msg("r0 &= 16128 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
/* Little endian: be64 = bswap64 */
__msg("r0 = be64 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=0x3f000000000000,smax32=umax32=0,var_off=(0x0; 0x3f000000000000))")
#else
/* Big endian: be64 = no-op */
__msg("r0 = be64 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#endif
__naked void be64_network(void)
{
	asm volatile ("					\
	/* Simulate reading from network packet */	\
	call %[bpf_get_prandom_u32];			\
	/* Extract byte range 0x0000-0x3f00 */		\
	r0 &= 0x3f00;					\
	/* Convert to big endian */			\
	r0 = be64 r0;					\
	/* Verify range - if tnum works correctly, trap path is dead code */	\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	"r2 = 0x3f000000000000 ll;	/* Load 64-bit constant */	\
	if r0 > r2 goto trap_%=;			\
"
#else
	"if r0 > 0x3f00 goto trap_%=;			\
"
#endif
	"r0 = 0;					\
	exit;						\
trap_%=:	/* Should never reach */		\
	r1 = 42;	/* r1 = scalar for trap */	\
	r0 = *(u64 *)(r1 + 0);	/* Invalid: scalar dereference */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("LE16 (to little endian) network - endian conversion with tnum")
__success __log_level(2)
__msg("w0 &= 16128 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
/* Little endian: le16 = _to_u16 (truncation) */
__msg("r0 = le16 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#else
/* Big endian: le16 = bswap16 */
__msg("r0 = le16 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=63,var_off=(0x0; 0x3f))")
#endif
__naked void le16_network(void)
{
	asm volatile ("					\
	/* Simulate reading from network packet */	\
	call %[bpf_get_prandom_u32];			\
	/* Extract byte range 0x0000-0x3f00 */		\
	w0 &= 0x3f00;					\
	/* Convert to little endian */			\
	r0 = le16 r0;					\
	/* Verify range - if tnum works correctly, trap path is dead code */	\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	"if r0 > 0x3f00 goto trap_%=;			\
"
#else
	"if r0 > 0x3f goto trap_%=;			\
"
#endif
	"r0 = 0;					\
	exit;						\
trap_%=:	/* Should never reach */		\
	r1 = 42;	/* r1 = scalar for trap */	\
	r0 = *(u64 *)(r1 + 0);	/* Invalid: scalar dereference */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("LE32 (to little endian) network - endian conversion with tnum")
__success __log_level(2)
__msg("w0 &= 16128 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
/* Little endian: le32 = _to_u32 (truncation) */
__msg("r0 = le32 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#else
/* Big endian: le32 = bswap32 */
__msg("r0 = le32 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=0x3f0000,var_off=(0x0; 0x3f0000))")
#endif
__naked void le32_network(void)
{
	asm volatile ("					\
	/* Simulate reading from network packet */	\
	call %[bpf_get_prandom_u32];			\
	/* Extract byte range 0x0000-0x3f00 */		\
	w0 &= 0x3f00;					\
	/* Convert to little endian */			\
	r0 = le32 r0;					\
	/* Verify range - if tnum works correctly, trap path is dead code */	\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	"if r0 > 0x3f00 goto trap_%=;			\
"
#else
	"if r0 > 0x3f0000 goto trap_%=;			\
"
#endif
	"r0 = 0;					\
	exit;						\
trap_%=:	/* Should never reach */		\
	r1 = 42;	/* r1 = scalar for trap */	\
	r0 = *(u64 *)(r1 + 0);	/* Invalid: scalar dereference */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__description("LE64 (to little endian) network - endian conversion with tnum")
__success __log_level(2)
__msg("r0 &= 16128 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
/* Little endian: le64 = no-op */
__msg("r0 = le64 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=16128,var_off=(0x0; 0x3f00))")
#else
/* Big endian: le64 = bswap64 */
__msg("r0 = le64 r0 {{.*}}; R0=scalar(smin=smin32=0,smax=umax=0x3f000000000000,smax32=umax32=0,var_off=(0x0; 0x3f000000000000))")
#endif
__naked void le64_network(void)
{
	asm volatile ("					\
	/* Simulate reading from network packet */	\
	call %[bpf_get_prandom_u32];			\
	/* Extract byte range 0x0000-0x3f00 */		\
	r0 &= 0x3f00;					\
	/* Convert to little endian */			\
	r0 = le64 r0;					\
	/* Verify range - if tnum works correctly, trap path is dead code */	\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	"if r0 > 0x3f00 goto trap_%=;			\
"
#else
	"r2 = 0x3f000000000000 ll;	/* Load 64-bit constant */	\
	if r0 > r2 goto trap_%=;			\
"
#endif
	"r0 = 0;					\
	exit;						\
trap_%=:	/* Should never reach */		\
	r1 = 42;	/* r1 = scalar for trap */	\
	r0 = *(u64 *)(r1 + 0);	/* Invalid: scalar dereference */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

#else

SEC("socket")
__description("cpuv4 is not supported by compiler or jit, use a dummy test")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
