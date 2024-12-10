#!/bin/bash

cat ../../../../kernel/bpf/btf.c  | grep RAW_TP_NULL_ARGS | grep -v "define RAW_TP" | ./gen_raw_tp_null.py | tee progs/raw_tp_null.c
