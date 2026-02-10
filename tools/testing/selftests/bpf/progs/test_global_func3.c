// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2020 Facebook */
#include <stddef.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

__attribute__ ((noinline))
int f1(struct __sk_buff *skb)
{
	return skb->len;
}

__attribute__ ((noinline))
int f2(int val, struct __sk_buff *skb)
{
	return f1(skb) + val;
}

__attribute__ ((noinline))
int f3(int val, struct __sk_buff *skb, int var)
{
	return f2(var, skb) + val;
}

__attribute__ ((noinline))
int f4(struct __sk_buff *skb)
{
	return f3(1, skb, 2);
}

__attribute__ ((noinline))
int f5(struct __sk_buff *skb)
{
	return f4(skb);
}

__attribute__ ((noinline))
int f6(struct __sk_buff *skb)
{
	return f5(skb);
}

__attribute__ ((noinline))
int f7(struct __sk_buff *skb)
{
	return f6(skb);
}

__attribute__ ((noinline))
int f8(struct __sk_buff *skb)
{
	return f7(skb);
}

__attribute__ ((noinline))
int f9(struct __sk_buff *skb)
{
	return f8(skb);
}

__attribute__ ((noinline))
int f10(struct __sk_buff *skb)
{
	return f9(skb);
}

__attribute__ ((noinline))
int f11(struct __sk_buff *skb)
{
	return f10(skb);
}

__attribute__ ((noinline))
int f12(struct __sk_buff *skb)
{
	return f11(skb);
}

__attribute__ ((noinline))
int f13(struct __sk_buff *skb)
{
	return f12(skb);
}

__attribute__ ((noinline))
int f14(struct __sk_buff *skb)
{
	return f13(skb);
}

__attribute__ ((noinline))
int f15(struct __sk_buff *skb)
{
	return f14(skb);
}

__attribute__ ((noinline))
int f16(struct __sk_buff *skb)
{
	return f15(skb);
}

SEC("tc")
__failure __msg("total call depth is 16 frames, too deep")
int global_func3(struct __sk_buff *skb)
{
	return f16(skb);
}
