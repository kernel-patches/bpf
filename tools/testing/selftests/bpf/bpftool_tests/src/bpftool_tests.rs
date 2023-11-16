// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
mod bpftool_tests_skel {
    include!(concat!(env!("OUT_DIR"), "/bpftool_tests.skel.rs"));
}

use std::process::Command;

const BPFTOOL_PATH_ENV: &str = "BPFTOOL_PATH";
const BPFTOOL_PATH: &str = "/usr/sbin/bpftool";

/// Run a bpftool command and returns the output
fn run_bpftool_command(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(std::env::var(BPFTOOL_PATH_ENV).unwrap_or(BPFTOOL_PATH.to_string()));
    cmd.args(args);
    println!("Running command {:?}", cmd);
    cmd.output().expect("failed to execute process")
}

/// Simple test to make sure we can run bpftool
#[test]
fn run_bpftool() {
    let output = run_bpftool_command(&["version"]);
    assert!(output.status.success());
}
