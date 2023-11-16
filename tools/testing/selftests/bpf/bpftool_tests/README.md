## About the testing Framework

The testing framework uses [RUST's testing framework](https://doc.rust-lang.org/rustc/tests/index.html)
and [libbpf-rs](https://docs.rs/libbpf-rs/latest/libbpf_rs/).

The former takes care of scheduling tests and reporting their successes/failures.
The latter is used to load bpf programs, maps, and possibly interact with them
programatically through libbpf API.
This allows us to set the environment we want to test and check that `bpftool`
does what we expect.

This document assumes you have [`cargo` and `rust` installed](https://doc.rust-lang.org/cargo/getting-started/installation.html).

## Testing bpftool

This should be no different than typical [`cargo test`](https://doc.rust-lang.org/cargo/commands/cargo-test.html)
but there is a few subtleties to consider when running `bpftool` tests:

1. bpftool needs to run with root privileges for the most part. So the runner needs to run as root.
1. each tests load a program, possibly modify it, and check expectations. In order to be deterministic, tests need to run serially.

### Environment variable

A few environment variable can be used to control the behaviour of the tests:
- `RUST_TEST_THREADS`: This should be set to 1 to run one test at a time and avoid tests to step onto each others.
- `BPFTOOL_PATH`: Allow passing an alternate location for `bpftool`. Default: `/usr/sbin/bpftool`

### Running the test suite

Here are a few options to make this happen:

```
# build the test binary, extract the test executable location
# and run it with sudo, 1 test at a time.
eval sudo BPFTOOL_PATH=$(pwd)/../bpftool RUST_TEST_THREADS=1 \
    $(cargo test --no-run \
        --message-format=json | jq '. | select(.executable != null ).executable' \
    )
```

or alternatively, one can use the [`CARGO_TARGET_<triple>_RUNNER` environment variable](https://doc.rust-lang.org/cargo/reference/environment-variables.html#:~:text=CARGO_TARGET_%3Ctriple%3E_RUNNER).

The benefit of that approach is that compilation errors will show directly in the terminal.

```
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="sudo -E" \
    BPFTOOL_PATH=$(pwd)/../bpftool \
    RUST_TEST_THREADS=1 \
    cargo test
```

### Running tests against built kernel/bpftool

Using [vmtest](https://github.com/danobi/vmtest):

```
$ KERNEL_REPO=~/devel/bpf-next/
$ vmtest -k $KERNEL_REPO/arch/x86_64/boot/bzImage "BPFTOOL_PATH=$KERNEL_REPO/tools/bpf/bpftool/bpftool RUST_TEST_THREADS=1 cargo test"
=> bzImage
===> Booting
===> Setting up VM
===> Running command
    Finished test [unoptimized + debuginfo] target(s) in 2.06s
     Running unittests src/main.rs (target/debug/deps/bpftool_tests-afa5a7eef3cdeafb)

running 11 tests
test bpftool_tests::run_bpftool ... ok
test bpftool_tests::run_bpftool_map_dump_id ... ok
test bpftool_tests::run_bpftool_map_list ... ok
test bpftool_tests::run_bpftool_map_pids ... ok
test bpftool_tests::run_bpftool_prog_list ... ok
test bpftool_tests::run_bpftool_prog_pids ... ok
test bpftool_tests::run_bpftool_prog_show_id ... ok
test bpftool_tests::run_bpftool_struct_ops_can_unregister_id ... ok
test bpftool_tests::run_bpftool_struct_ops_can_unregister_name ... ok
test bpftool_tests::run_bpftool_struct_ops_dump_name ... ok
test bpftool_tests::run_bpftool_struct_ops_list ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.88s
```

the return code will be 0 on success, non-zero otherwise.


## Caveat

Currently, libbpf-sys crate either uses a vendored libbpf, or the system one.
This could possibly limit tests against features that are being introduced.

That being said, this is not a blocker now, and can be fixed upstream.
https://github.com/libbpf/libbpf-sys/issues/70 tracks this on libbpf-sys side.
