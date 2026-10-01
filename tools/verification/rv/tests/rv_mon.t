#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
source ../tests/engine.sh
test_begin

set_timeout 30s

RVDIR=/sys/kernel/tracing/rv/
RVTOOL=$(dirname "$RV")

# Help and basic tests
check "verify mon subcommand help" \
	"$RV mon --help" 0 "run a monitor"

# Error handling tests
check "mon without monitor name" \
	"$RV mon" 1 "usage: rv mon"

check "invalid monitor name" \
	"$RV mon invalid" 1 "monitor invalid does not exist"

if [ -d $RVDIR/monitors/wwnr ]; then

check "invalid reactor name" \
	"$RV mon wwnr -r invalid" 1 "failed to set invalid reactor, is it available?"

check "invalid BPF reactor name" \
	"$RV mon nohz -r invalid" 1 "failed to set invalid reactor, is it available?"

check "invalid BPF reactor name check available" \
	"$RV mon nohz -r invalid" 1 "available BPF reactors: nop [a-z]\+" \
	"available reactors:"

check "monitor name is substring of another monitor" \
	"$RV mon nr" 1 "monitor nr does not exist"

check "already enabled monitor returns error" \
	"echo 1 > $RVDIR/monitors/wwnr/enable; $RV mon wwnr" 1 \
	"monitor wwnr (in-kernel) is already enabled"
[ -n "$TEST_COUNT" ] && echo 0 > $RVDIR/monitors/wwnr/enable

fi

if [ -f "$RVTOOL/bpf_monitors/tqueue.o" ]; then

[ -n "$TEST_COUNT" ] && { $RV mon tqueue & disown ; tmp=$! ; sleep 1 ; }
check "already enabled BPF monitor returns error" \
	"$RV mon tqueue" 1 "monitor tqueue (BPF) is already enabled"

[ -n "$TEST_COUNT" ] && { kill -9 "$tmp" && sleep 1 ; }
set_expected_timeout 1s

check "crashed BPF monitor does not leak resources" \
	"$RV mon tqueue" 0 "" "monitor tqueue (BPF) is already enabled"

fi

# rv mon runs until terminated
set_expected_timeout 2s

# Run monitors with different configurations
check_if_exists "run the monitor without parameters" \
	"$RV mon wwnr" "$RVDIR/monitors/wwnr" "" "."

check_if_exists "run a BPF monitor without parameters" \
	"$RV mon nohz" "$RVTOOL/bpf_monitors/nohz.o" "" "."

check_if_exists "run a per-task BPF monitor without parameters" \
	"$RV mon tqueue" "$RVTOOL/bpf_monitors/tqueue.o" "" "."

check_if_exists "run the monitor as verbose" \
	"$RV mon wwnr -v" "$RVDIR/monitors/wwnr" \
	"my pid is \$pid" "\(event\|error\)"

check_if_exists "run the monitor with a reactor" \
	"$RV mon wwnr -r printk & sleep .5 && cat $RVDIR/monitors/wwnr/reactors && wait" \
	"$RVDIR/monitors/wwnr/reactors" "\[printk\]"

check_if_exists "reactor is restored after exit" \
	"cat $RVDIR/monitors/wwnr/reactors" \
	"$RVDIR/monitors/wwnr/reactors" "\[nop\]"

check_if_exists "run a nested monitor with a reactor" \
	"$RV mon snroc -r printk & sleep .5 && cat $RVDIR/monitors/sched/snroc/reactors && wait" \
	"$RVDIR/monitors/sched/snroc/reactors" "\[printk\]"

check_if_exists "run an explicitly nested monitor with a reactor" \
	"$RV mon sched:sssw -r printk & sleep .5 && cat $RVDIR/monitors/sched/sssw/reactors && wait" \
	"$RVDIR/monitors/sched/sssw/reactors" "\[printk\]"

TRACE=/sys/kernel/tracing/trace

[ -n "$TEST_COUNT" ] && echo -n > $TRACE
check_if_exists "run a BPF monitor with a reactor" \
	"$RV mon nohz -r printk && cat $TRACE" "$RVTOOL/bpf_monitors/nohz.o" \
	"rv: monitor nohz does not allow event [a-z_]\+ on state [a-z_]\+"

# Give some time for maps from previous run to be cleaned up
[ -n "$TEST_COUNT" ] && sleep 1
[ -n "$TEST_COUNT" ] && echo -n > $TRACE
check_if_exists "run BPF monitors with nop reactor" \
	"$RV mon nohz -r nop && cat $TRACE" "$RVTOOL/bpf_monitors/nohz.o" \
	"" "rv: monitor nohz does not allow event"

check_if_exists "run container monitor" \
	"$RV mon sched & sleep .5 && cat $RVDIR/monitors/sched/{sssw,sco}/enable && wait" \
	"$RVDIR/monitors/sched" "1" "0" "^1$"

# Regexes for the trace
header="^[[:space:]]\+\(\([][A-Z_x<>-]\+\||\)[[:space:]]*\)\+$"
type="\(event\|error\)[[:space:]]\+"
genpid="[0-9]\+[[:space:]]\+"
selfpid="\$pid[[:space:]]\+"
cpu="\[[0-9]\{3\}\][[:space:]]\+"
state="[a-z_]\+ "
trace_task="${genpid}${cpu}${type}${genpid}${state}"
trace_task_self="${genpid}${cpu}${type}${selfpid}${state}"
trace_cpu="${genpid}${cpu}${type}${state}"
trace_cpu_self="${selfpid}${cpu}${type}${state}"

check_if_exists "run per-task monitor with tracing" \
	"$RV mon sssw -t" "$RVDIR/monitors/sched/sssw" \
	"$header" "$trace_task_self" "\($header\|$trace_task\)"

check_if_exists "run per-task monitor tracing also self" \
	"$RV mon sched:sssw -t -s" "$RVDIR/monitors/sched/sssw" \
	"$trace_task_self" "" "\($header\|$trace_task\)"

check_if_exists "run per-cpu monitor with tracing" \
	"$RV mon sched:sco -t" "$RVDIR/monitors/sched/sco" \
	"$header" "$trace_cpu_self" "\($header\|$trace_cpu\)"

check_if_exists "run per-cpu monitor tracing also self" \
	"$RV mon sco -t -s" "$RVDIR/monitors/sched/sco" \
	"$trace_cpu_self" "" "\($header\|$trace_cpu\)"

check_if_exists "run per-task BPF monitor with tracing" \
	"$RV mon tqueue -t" "$RVTOOL/bpf_monitors/tqueue.o" \
	"$header" "$trace_task_self" "\($header\|$trace_task\)"

check_if_exists "run per-task BPF monitor tracing also self" \
	"$RV mon tqueue -t -s" "$RVTOOL/bpf_monitors/tqueue.o" \
	"$trace_task_self" "" "\($header\|$trace_task\)"

check_if_exists "run per-cpu BPF monitor with tracing" \
	"$RV mon nohz -t" "$RVTOOL/bpf_monitors/nohz.o" \
	"$header" "$trace_cpu_self" "\($header\|$trace_cpu\)"

# This is unstable, we may never see events from self
#check_if_exists "run per-cpu BPF monitor tracing also self" \
#	"$RV mon nohz -t -s" "$RVTOOL/bpf_monitors/nohz.o" \
#	"$trace_cpu_self" "" "\($header\|$trace_cpu\)"

test_end
