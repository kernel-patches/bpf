#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

summarize "no-private-stack: " "$($RUN_BENCH --disable-private-stack 1 no-private-stack)"
summarize "private-stack: " "$($RUN_BENCH private-stack)"
