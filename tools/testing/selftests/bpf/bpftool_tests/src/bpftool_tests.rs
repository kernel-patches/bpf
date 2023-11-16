// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
mod bpftool_tests_skel {
    include!(concat!(env!("OUT_DIR"), "/bpftool_tests.skel.rs"));
}

use anyhow::Result;
use bpftool_tests_skel::BpftoolTestsSkel;
use bpftool_tests_skel::BpftoolTestsSkelBuilder;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Program;
use serde::Deserialize;
use serde::Serialize;
use std::os::fd::AsFd;
use std::process::Command;

const BPFTOOL_PATH_ENV: &str = "BPFTOOL_PATH";
const BPFTOOL_PATH: &str = "/usr/sbin/bpftool";

/// A struct representing a pid entry from map/prog dump
#[derive(Serialize, Deserialize, Debug)]
struct Pid {
    comm: String,
    pid: u64,
}

/// A struct representing a prog entry from `bpftool prog list -j`
#[derive(Serialize, Deserialize, Debug)]
struct Prog {
    name: Option<String>,
    id: u32,
    r#type: String,
    tag: String,
    #[serde(default)]
    pids: Vec<Pid>,
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

/// A struct representing a formatted map entry from `bpftool map dump -j`
#[derive(Serialize, Deserialize, Debug)]
struct FormattedMapItem {
    key: String,
    value: String,
}

type MapVecString = Vec<String>;

/// A struct representing a map entry from `bpftool map dump -j`
#[derive(Serialize, Deserialize, Debug)]
struct MapItem {
    key: MapVecString,
    value: MapVecString,
    formatted: Option<FormattedMapItem>,
}

/// A helper function to convert a vector of strings as returned by bpftool
/// into a vector of bytes.
/// bpftool returns key/value in the form of a sequence of strings
/// hexadecimal numbers. We need to convert them back to bytes.
/// for instance, the value of the key "key" is represented as ["0x6b","0x65","0x79"]
fn to_vec_u8(m: &MapVecString) -> Vec<u8> {
    m.iter()
        .map(|s| {
            u8::from_str_radix(s.trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| panic!("Failed to parse {:?}", s))
        })
        .collect()
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

/// A test to validate that we can run `bpftool map dump <id>`
/// and extract the expected information.
/// The test adds a key, value pair to the map and then dumps it.
/// The test validates that the dumped data matches what was added.
/// It also validate that bpftool was able to format the key/value pairs.
#[test]
fn run_bpftool_map_dump_id() {
    // By having key/value null terminated, we can check that bpftool also returns the
    // formatted content.
    let key = b"key\0\0\0";
    let value = b"value\0";
    let skel = setup().expect("Failed to set up BPF program");
    let binding = skel.maps();
    let bpftool_test_map_map = binding.bpftool_test_map();
    bpftool_test_map_map
        .update(key, value, libbpf_rs::MapFlags::NO_EXIST)
        .expect("Failed to update map");
    let map_id = bpftool_test_map_map
        .info()
        .expect("Failed to get map info")
        .info
        .id;

    let output = run_bpftool_command(&["map", "dump", "id", &map_id.to_string(), "--json"]);
    assert!(output.status.success(), "bpftool returned an error.");

    let items =
        serde_json::from_slice::<Vec<MapItem>>(&output.stdout).expect("Failed to parse JSON");

    assert_eq!(items.len(), 1);

    let item = items.first().expect("Expected a map item");
    assert_eq!(to_vec_u8(&item.key), key);
    assert_eq!(to_vec_u8(&item.value), value);

    // Validate "formatted" values.
    // The keys and values are null terminated so we need to trim them before comparing.
    let formatted = item
        .formatted
        .as_ref()
        .expect("Formatted values are missing");
    assert_eq!(
        formatted.key,
        std::str::from_utf8(key)
            .expect("Invalid UTF-8")
            .trim_end_matches('\0'),
    );
    assert_eq!(
        formatted.value,
        std::str::from_utf8(value)
            .expect("Invalid UTF-8")
            .trim_end_matches('\0'),
    );
}

/// A test to validate that we can list programs using bpftool
#[test]
fn run_bpftool_prog_list() {
    let _skel = setup().expect("Failed to set up BPF program");
    let output = run_bpftool_command(&["prog", "list", "--json"]);

    let progs = serde_json::from_slice::<Vec<Prog>>(&output.stdout).expect("Failed to parse JSON");

    assert!(output.status.success());
    assert!(!progs.is_empty(), "No programs were listed");
}

/// A test to validate that we can find PIDs associated with a program
#[test]
fn run_bpftool_prog_pids() {
    let hook_name = "handle_tp_sys_enter_write";

    let _skel = setup().expect("Failed to set up BPF program");
    let output = run_bpftool_command(&["prog", "list", "--json"]);

    let progs = serde_json::from_slice::<Vec<Prog>>(&output.stdout).expect("Failed to parse JSON");
    assert!(output.status.success(), "bpftool returned an error.");

    // `handle_tp_sys_enter_write` is a hook our bpftool_tests.bpf.c attaches
    // to (tp/syscalls/sys_enter_write).
    // It should have at least one entry for our current process.
    let prog = progs
        .iter()
        .find(|m| m.name.is_some() && m.name.as_ref().unwrap() == hook_name)
        .unwrap_or_else(|| panic!("Did not find {} prog", hook_name));

    let mypid = std::process::id() as u64;
    assert!(
        prog.pids.iter().any(|p| p.pid == mypid),
        "Did not find test runner pid ({}) in pids list associated with prog *{}*: {:?}",
        mypid,
        hook_name,
        prog.pids
    );
}

/// A test to validate that we can run `bpftool prog show <id>`
/// an extract the expected information.
#[test]
fn run_bpftool_prog_show_id() {
    let skel = setup().expect("Failed to set up BPF program");
    let binding = skel.progs();
    let handle_tp_sys_enter_write = binding.handle_tp_sys_enter_write();
    let prog_id =
        Program::get_id_by_fd(handle_tp_sys_enter_write.as_fd()).expect("Failed to get prog ID");

    let output = run_bpftool_command(&["prog", "show", "id", &prog_id.to_string(), "--json"]);
    assert!(output.status.success(), "bpftool returned an error.");

    let prog = serde_json::from_slice::<Prog>(&output.stdout).expect("Failed to parse JSON");

    assert_eq!(prog_id, prog.id);
    assert_eq!(
        handle_tp_sys_enter_write.name(),
        prog.name
            .expect("Program handle_tp_sys_enter_write has no name")
    );
    assert_eq!("tracepoint", prog.r#type);
}
