// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
mod bpftool_tests_skel {
    include!(concat!(env!("OUT_DIR"), "/bpftool_tests.skel.rs"));
}

use anyhow::Result;
use bpftool_tests_skel::BpftoolTestsSkel;
use bpftool_tests_skel::BpftoolTestsSkelBuilder;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use serde::Deserialize;
use serde::Serialize;

use std::process::Command;

const BPFTOOL_PATH_ENV: &str = "BPFTOOL_PATH";
const BPFTOOL_PATH: &str = "/usr/sbin/bpftool";

/// A struct representing a pid entry from map/prog dump
#[derive(Serialize, Deserialize, Debug)]
struct Pid {
    comm: String,
    pid: u64,
}

/// A struct representing a map entry from `bpftool map list -j`
#[derive(Serialize, Deserialize, Debug)]
struct Map {
    name: Option<String>,
    id: u64,
    r#type: String,
    #[serde(default)]
    pids: Vec<Pid>,
}

/// Setup our bpftool_tests.bpf.c program.
/// Open and load and return an opened object.
fn setup() -> Result<BpftoolTestsSkel<'static>> {
    let mut skel_builder = BpftoolTestsSkelBuilder::default();
    skel_builder.obj_builder.debug(false);

    let open_skel = skel_builder.open()?;

    let skel = open_skel.load()?;

    Ok(skel)
}

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

/// A test to validate that we can list maps using bpftool
#[test]
fn run_bpftool_map_list() {
    let _skel = setup().expect("Failed to set up BPF program");
    let output = run_bpftool_command(&["map", "list", "--json"]);

    let maps = serde_json::from_slice::<Vec<Map>>(&output.stdout).expect("Failed to parse JSON");

    assert!(output.status.success(), "bpftool returned an error.");
    assert!(!maps.is_empty(), "No maps were listed");
}

/// A test to validate that we can find PIDs associated with a map
#[test]
fn run_bpftool_map_pids() {
    let map_name = "pid_write_calls";

    let _skel = setup().expect("Failed to set up BPF program");
    let output = run_bpftool_command(&["map", "list", "--json"]);

    let maps = serde_json::from_slice::<Vec<Map>>(&output.stdout).expect("Failed to parse JSON");

    assert!(output.status.success(), "bpftool returned an error.");

    // `pid_write_calls` is a map our bpftool_tests.bpf.c uses. It should have at least
    // one entry for our current process.
    let map = maps
        .iter()
        .find(|m| m.name.is_some() && m.name.as_ref().unwrap() == map_name)
        .unwrap_or_else(|| panic!("Did not find {} map", map_name));

    let mypid = std::process::id() as u64;
    assert!(
        map.pids.iter().any(|p| p.pid == mypid),
        "Did not find test runner pid ({}) in pids list associated with map *{}*: {:?}",
        mypid,
        map_name,
        map.pids
    );
}
