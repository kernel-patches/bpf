# Veristat

`run_veristat.py` measures prepared BPF corpora against the running kernel.
It requires Python 3 and a veristat executable. The caller prepares the objects,
boots the kernel, and handles baselines and publication.

The runner, manifest helper, guest entrypoint, and their tests do not depend
on BPF CI corpora, workflows, or result policy, so they can move into a shared
action if another project needs them. BPF CI inputs and baseline comparison
are described [below](#bpf-ci).

```sh
python3 run_veristat.py --veristat /tools/veristat \
    --manifest /inputs/manifest.json --output /results/current
```

The manifest selects exact objects and optional veristat filter files. Paths
are relative to the manifest directory; corpus names must be unique directory
names and object basenames must be unique within each corpus.

```json
{
  "version": 1,
  "corpora": [
    {
      "name": "kernel",
      "objects": {"kernel/example.bpf.o": "<sha256>"},
      "filter": "kernel/veristat.cfg"
    }
  ]
}
```

The output directory must be new. The runner checks object SHA256s and runs
one veristat process per corpus with `-o csv -q -e file,prog,verdict,states`.
Each corpus gets `results.csv`, `stderr.log`, and an atomic `status.json`.
Status is `running`, `measured`, or `error`; a missing status means the corpus
was not started. Interrupted and partial results must not be cached as measured.

`measured` requires a zero tool exit status and nonempty, valid program records.
Rejected programs remain CSV data for the caller's comparison policy.
The runner continues after a corpus error and returns nonzero if any corpus
could not be measured. The VM launcher handles VM failure and timeouts.

After measuring a corpus with rejected programs, the runner reruns veristat
with `-v` for them on the same objects and kernel. Their verifier logs go to
`failures.log`, and the program filter to `failures.cfg`. These are diagnostics;
they do not change the measurement status.

Status includes the corpus digest: SHA256 of the sorted SHA256SUMS-style
`<sha256>  <basename>\n` listing. Source/build details and directory locations
do not participate in object identity.

Diagnostics go to stderr: run inputs, corpus progress, and completion or failure
details. Messages are flushed so an interrupted run retains its last operation.
Tool output stays in files. The caller controls visibility of the result files
and VM console.

## Prepare a manifest

`create_manifest.py` selects local files by glob and records their checksums.
Its config lists one selection per corpus; directories and filters are relative
to the current directory:

```json
[
  {
    "name": "kernel",
    "directory": "selftests/bpf",
    "pattern": "*.bpf.o",
    "filter": "selftests/bpf/veristat.cfg"
  }
]
```

```sh
python3 create_manifest.py --config selection.json --output manifest.json
```

`filter` is optional. A selection matching no files remains in the manifest,
so the runner reports it as an error. Downloads and builds belong to the caller.

## Run with run-vmtest

`run-veristat.sh` is a guest entrypoint for `libbpf/ci/run-vmtest`. Select it
through `VMTEST_SCRIPT` and pass the runner arguments in the environment:

```sh
VMTEST_SCRIPT=$PWD/ci/veristat/run-veristat.sh
VERISTAT_BINARY=$PWD/selftests/bpf/veristat
VERISTAT_MANIFEST=$PWD/manifest.json
VERISTAT_RESULTS=$PWD/veristat-results
```

The guest uses the host root filesystem and environment, so host paths work
unchanged. The entrypoint records `veristat:<exitcode>` in the run-vmtest
status file; the host fails the action on a nonzero status. Per-corpus outcomes
remain in the result status files.

## BPF CI

Selection configs for `create_manifest.py`:

| File | Corpora |
|---|---|
| `oss.json` | Kernel, Cilium, SCX |
| `meta.json` | Meta |

After downloading/building the selected inputs, the workflows generate
`manifest.json` from the workspace root:

```sh
python3 ci/veristat/create_manifest.py --config ci/veristat/oss.json \
    --output manifest.json
```

`compare-veristat-results.sh` compares a corpus CSV with its cached baseline
through `veristat --compare` and `veristat_compare.py`. It fails only when a
program that passed in the baseline now fails. Without a baseline, it prints
the results and passes.

Each caller controls publication: OSS can share its debug bundle; Meta objects
and raw logs must remain private. The OSS workflow uploads the whole results
directory, including verifier logs; the Meta workflow uploads only the CSV.
