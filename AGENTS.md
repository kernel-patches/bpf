# BPF CI workflows (vmtest)

Repository context and expectations for changes to workflows, scripts and CI policy.
[README.md](README.md) provides the overview and validation entry points.
KPD also copies these files into kernel mirrors; this guidance covers the CI files,
while kernel changes follow the kernel's contribution rules.

## What this repository owns

This repository orchestrates BPF CI. KPD copies `.github` and top-level CI files
into kernel mirrors such as `kernel-patches/bpf`, where patch-series PRs and base
pushes run them. The default branch of `kernel-patches/vmtest` is `master`.

| Path | Role |
|---|---|
| `.github/workflows/test.yml` | Entry point; matrix, build/test gates and concurrency |
| `.github/scripts/matrix.py` | Architectures, toolchains, runners and enabled workloads |
| `.github/workflows/kernel-{build,test,build-test}.yml` | Kernel/selftest artifacts, VM execution and workload fan-out |
| `.github/workflows/veristat-*.yml` | Corpus preparation, measurements, baselines and publication |
| `ci/veristat/` | Manifest/measurement/report CLIs and tests; see its README |
| `ci/vmtest/configs/` | Kernel configs, selftest filters and kernel-splat policy |
| `ci/diffs/` | Kernel patches applied before building; review applicability |
| `.github/workflows/linux-next-sync.yml` | Build linux-next from bpf_base plus upstream linux-next |
| `.github/workflows/ai-code-review.yml`, `ai-agent.yml`, `ci/claude/` | Automated review/investigation and publication |

`libbpf/ci` owns reusable build actions and VM machinery. This repository owns
BPF CI corpus providers, filters, reporting/baseline policy and infrastructure
assumptions. Use action, command and file interfaces across repositories; do not
introduce a shared Python library for these scripts. Helpers stay within their component.

## Easy to get wrong

- **Caller context.** Reusable/injected workflows execute in other repositories.
  `github.repository`, refs, permissions, secrets and workspace paths belong to the
  run. Check caller and callee when changing inputs or conditions.
- **Validation paths.** A PR here downloads a kernel tree; production tests a kernel
  mirror's revision. Some lint/agent jobs have repository-specific gates. Feature
  pushes do not exercise the same paths as PRs or base pushes.
- **Independent gates.** Builds, selftests and veristat are separate workloads. Base
  pushes can skip selftests while still measuring veristat and saving baselines.
  Read the matrix and job/step conclusions; an overall failed run may have healthy
  veristat jobs. A skipped job provides no coverage.
- **Artifact identity.** Match architecture/toolchain, kernel image, selftests and
  modules across build/runtime jobs. Do not hardcode a lane accepted as an input.
- **Action versions.** `libbpf/ci@v4` is a moving tag; the downloaded SHA in a run log
  is authoritative. Merging here propagates CI files through KPD. Updating an action
  tag is a separate change affecting its callers.
- **linux-next.** Its separate sync starts from bpf_base and merges upstream linux-next.
  Successful KPD base updates do not prove linux-next has synced.
- **Guest status.** `VMTEST_SCRIPT` selects a guest entrypoint. Preserve the action's
  exitstatus-file contract so the host collects failures and artifacts. Inspect the
  action before assuming guest paths, inherited environment or VM isolation.
- **Filters and splats.** Selftest deny lists, veristat filters and kernel-splat allow/
  deny lists serve different purposes. An allowed splat does not imply a test passed.
  Explain exclusions and remove temporary workarounds once the underlying fix is available.

## Veristat contracts

Veristat tests various corpora of BPF programs through a shared measurement
and reporting pipeline.

- Selection configs such as `oss.json` describe providers/globs/filters. Reserve
  `manifest` for generated object paths and SHA256s. Object bytes define corpus
  identity; source/compiler details are provenance. Corpus names must be unique in
  a manifest and object basenames within a corpus; file/program keys are not globally unique.
- The worker writes source CSVs, shared diagnostics and an atomic source-status map.
  `measured` means successful execution with valid nonempty results, not that every
  program loaded. Missing/running receipts are unfinished; never cache partial output.
- Load failures are data and can mean verifier rejection, missing attach targets,
  CO-RE or resource setup. Diagnose inputs/logs before blaming a kernel patch; zero
  verifier states can indicate failure before verification.
- Current policy fails on matched `success -> failure`, reports state changes and
  ignores wholly new/removed programs. Missing baselines pass with an explicit label.
  Green does not prove every program was compared. Baseline selection currently uses
  branch cache prefixes, not exact kernel/object matching; check provenance.
- Keep source errors visible when others succeed, retain regressions across later
  comparisons, and stage baselines only for completed sources.
- Avoid manual source pins as a substitute for baseline correctness. Record actual
  inputs and compare the same object bytes when attributing a regression.

## Keep changes easy to understand

Judge the whole flow the next maintainer must understand. Hidden assumptions, multiple
state writers, duplicated decisions, flags, fallbacks and aliases all add cost. Keep
ownership clear and derive values instead of maintaining parallel versions. Prefer
deletion and the smallest solution to the current requirement. A refactor must remove
an identifiable burden; moving code into helpers alone is not simplification.

Keep control flow readable and outcomes distinct. Comments explain durable contracts
and non-obvious constraints at their source; verify claims and remove narration.
Diagnostics should identify the input/operation, cause and detailed evidence location
with few messages.

## Tests and validation

- Add script tests for plausible silent failures: green CI with missing, incorrect or
  misreported results/artifacts. Protect output retention, not cosmetic console wording.
  Let CI catch obvious command/syntax failures rather than build a large test harness.
- Prefer existing fixtures/tables and tests of CLIs, files, status and return codes.
  Regression tests should fail without the fix. Pure refactors adapt existing tests;
  avoid adding tests of private helpers.
- Validation evidence should cover the changed contract. Local VM checks can establish
  execution behavior; GitHub runs cover workflow, permission, cache, artifact and backend
  integration. Baseline bootstrap and failed-case propagation need evidence; passing
  runs alone are insufficient.
- Validation results must correspond to the stated inputs, with matching kernel images,
  modules, tools and objects. Record revisions, commands, scope and remaining limitations.

`.github/workflows/lint.yml` defines the checks. These commands reproduce them
from a vmtest checkout; in a kernel mirror, checks apply to CI-owned files.

```bash
python3 -m unittest ci/veristat/tests/*.py
black --check .
```

Changed scripts should pass `bash -n` and ShellCheck; CI uses
`--severity=warning --exclude=SC1091`. Workflow validation includes Actions expressions
and input-output wiring; YAML parsing alone is insufficient. Black follows `stable`,
so formatting checks need the same version when reproducing CI failures.

## Reviewable changes

- Prefer small commits with one logical change. Prerequisites should precede their
  consumers, and renames/formatting should be separate from unrelated behavior changes.
  Every prefix of a series should build and remain usable. Make cross-repository
  dependencies and release requirements explicit.
- Commit messages should be concise, self-contained and explain the problem and rationale.
  Follow existing component prefixes (e.g. `veristat:`, `ci:`, `ci/diffs:`), use imperative
  subjects and wrap bodies for readability. Mark pure refactors `No functional change.`
- Sign-off and review tags represent human certifications and should reflect actual
  authorship or review; do not fabricate them or add unsolicited AI attribution.
- Change descriptions should state what changed, the supporting validation and any
  limitations. Distinguish observations from hypotheses.
