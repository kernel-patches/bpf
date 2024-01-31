// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <linux/bpf.h>

#include "libbpf.h"
#include "libbpf_internal.h"

/* sdt.h warns if __STDC_VERSION__ is not set. */
#ifndef __STDC_VERSION__
#define __STDC_VERSION__	199901L
#endif

#include "sdt.h"

/*
 * User-space Runtime-Defined Tracing - URDT.
 */

/*
 * URDT allows a program to define runtime probes in a similar
 * manner to the compile-time USDT.
 *
 * A probe can be fired by calling the BPF_URDT_PROBE[N]() function,
 * where N is the number of arguments; for example
 *
 * BPF_URDT_PROBE2("myprovider", "myprobe", 1, "helloworld");
 *
 * This will trigger firing of the USDT probe urdt:probe2
 * within libbpf itself.  Once this probe fires, a BPF program
 * attached to it will fire.  URDT probes use the high-order
 * 32 bits of the USDT cookie to identify the provider/probe
 * by hashing the provider/probe name - see urdt.bpf.h for
 * details.  If the upper 32 bits of the cookie match the
 * hash passed into the probe, we know the probe firing is
 * for us.
 */
static unsigned int hash_combine(unsigned int hash, const char *str)
{
	const char *s;

	if (!str)
		return hash;

	for (s = str; *s != '\0'; s++)
		hash = hash * 31 + *s;
	return hash;
}

unsigned int urdt_probe_hash(const char *provider, const char *probe)
{
	unsigned int hash = 0;

	hash = hash_combine(hash, provider);
	return hash_combine(hash, probe);
}

void bpf_urdt__probe0(const char *provider, const char *probe)
{
	STAP_PROBE1(urdt, probe0, urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe1(const char *provider, const char *probe, long arg1)
{
	STAP_PROBE2(urdt, probe1, arg1, urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe2(const char *provider, const char *probe, long arg1, long arg2)
{
	STAP_PROBE3(urdt, probe2, arg1, arg2, urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe3(const char *provider, const char *probe, long arg1, long arg2, long arg3)
{
	STAP_PROBE4(urdt, probe3, arg1, arg2, arg3, urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe4(const char *provider, const char *probe, long arg1, long arg2, long arg3,
		      long arg4)
{
	STAP_PROBE5(urdt, probe4, arg1, arg2, arg3, arg4, urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe5(const char *provider, const char *probe, long arg1, long arg2, long arg3,
		      long arg4, long arg5)
{
	STAP_PROBE6(urdt, probe5, arg1, arg2, arg3, arg4, arg5,
		    urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe6(const char *provider, const char *probe, long arg1, long arg2, long arg3,
		      long arg4, long arg5, long arg6)
{
	STAP_PROBE7(urdt, probe6, arg1, arg2, arg3, arg4, arg5, arg6,
		    urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe7(const char *provider, const char *probe, long arg1, long arg2, long arg3,
		      long arg4, long arg5, long arg6, long arg7)
{
	STAP_PROBE8(urdt, probe7, arg1, arg2, arg3, arg4, arg5, arg6, arg7,
		    urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe8(const char *provider, const char *probe, long arg1, long arg2, long arg3,
		      long arg4, long arg5, long arg6, long arg7, long arg8)
{
	STAP_PROBE9(urdt, probe8, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8,
		    urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe9(const char *provider, const char *probe, long arg1, long arg2, long arg3,
		      long arg4, long arg5, long arg6, long arg7, long arg8, long arg9)
{
	STAP_PROBE10(urdt, probe9, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9,
		     urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe10(const char *provider, const char *probe, long arg1, long arg2, long arg3,
		       long arg4, long arg5, long arg6, long arg7, long arg8, long arg9,
		       long arg10)
{
	STAP_PROBE11(urdt, probe10, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9,
		     arg10, urdt_probe_hash(provider, probe));
}

void bpf_urdt__probe11(const char *provider, const char *probe, long arg1, long arg2, long arg3,
		       long arg4, long arg5, long arg6, long arg7, long arg8, long arg9,
		       long arg10, long arg11)
{
	STAP_PROBE12(urdt, probe11, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9,
		     arg10, arg11, urdt_probe_hash(provider, probe));
}


