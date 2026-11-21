# BPF CI workflows

This repository contains GitHub Actions workflows, scripts and test policy for
[Linux kernel BPF CI](https://github.com/kernel-patches/bpf/actions/workflows/test.yml).
It orchestrates kernel builds, BPF/sched_ext selftests, bpftool checks and veristat
comparisons. Kernel source and the reusable VM launcher live in other repositories.

Kernel Patches Daemon (KPD) copies these CI files into kernel mirrors such as
`kernel-patches/bpf`, where patch-series PRs and base pushes execute them. PRs in
this repository validate changes using a downloaded kernel tree. The workflow
conditions and matrix determine which tests run in each context.

## Navigate the repository

| Path | Purpose |
|---|---|
| [.github/workflows](.github/workflows) | Entry points and reusable build/test/review workflows |
| [.github/scripts](.github/scripts) | Matrix generation, runner placement and workflow helpers |
| [ci/vmtest/configs](ci/vmtest/configs) | Kernel configs, selftest exclusions and kernel-splat policy |
| [ci/veristat](ci/veristat/README.md) | Corpus preparation, measurement and baseline reporting |
| [ci/diffs](ci/diffs) | Kernel patches applied before CI builds |
| [ci/claude](ci/claude/README.md) | AI review and investigation tooling |

Agents should read [AGENTS.md](AGENTS.md) before editing.

## Validate changes

From the repository root, with Python 3 and Black installed:

```bash
python3 -m unittest ci/veristat/tests/*.py
black --check .
```

Check changed shell scripts with Bash and the ShellCheck options in
[lint.yml](.github/workflows/lint.yml), and validate workflow syntax and wiring.
Changes to workflow execution, artifacts or baselines also need a GitHub Actions
run; feature-branch pushes alone do not exercise all PR/base-push paths.

## BPF CI components

- [kernel-patches/bpf](https://github.com/kernel-patches/bpf): kernel mirror tracking
  [upstream BPF trees](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/).
- [KPD](https://github.com/kernel-patches/kernel-patches-daemon): connects
  [Patchwork](https://patchwork.kernel.org/project/netdevbpf/list/) with GitHub,
  reports CI results and sends notifications.
- [libbpf/ci](https://github.com/libbpf/ci): reusable build/test actions and VM setup.
- [kernel-patches/runner](https://github.com/kernel-patches/runner): runner images and setup.
- [danobi/vmtest](https://github.com/danobi/vmtest): QEMU-based VM launcher.

The tested kernel supplies [BPF selftests and veristat](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf)
and [sched_ext selftests](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/sched_ext).
The [GCC BPF backend](https://gcc.gnu.org/wiki/BPFBackEnd) is tested separately.
