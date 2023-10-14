/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SOCK_ADDR_HELPERS_H
#define __SOCK_ADDR_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define CONNECT4_PROG_PATH	"./connect4_prog.bpf.o"
#define CONNECT6_PROG_PATH	"./connect6_prog.bpf.o"
#define SENDMSG4_PROG_PATH	"./sendmsg4_prog.bpf.o"
#define SENDMSG6_PROG_PATH	"./sendmsg6_prog.bpf.o"
#define RECVMSG4_PROG_PATH	"./recvmsg4_prog.bpf.o"
#define RECVMSG6_PROG_PATH	"./recvmsg6_prog.bpf.o"
#define BIND4_PROG_PATH		"./bind4_prog.bpf.o"
#define BIND6_PROG_PATH		"./bind6_prog.bpf.o"

#define SERV4_IP		"192.168.1.254"
#define SERV4_REWRITE_IP	"127.0.0.1"
#define SRC4_IP			"172.16.0.1"
#define SRC4_REWRITE_IP		"127.0.0.4"
#define SERV4_PORT		4040
#define SERV4_REWRITE_PORT	4444

#define SERV6_IP		"face:b00c:1234:5678::abcd"
#define SERV6_REWRITE_IP	"::1"
#define SERV6_V4MAPPED_IP	"::ffff:192.168.0.4"
#define SRC6_IP			"::1"
#define SRC6_REWRITE_IP		"::6"
#define WILDCARD6_IP		"::"
#define SERV6_PORT		6060
#define SERV6_REWRITE_PORT	6666

int load_path(const char *path, enum bpf_attach_type attach_type,
	      bool expected_reject);

#endif
