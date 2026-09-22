# BPF CI GitHub Actions worfklows

This repository contains GitHub Actions workflow definitions, scripts and configuration files used by those workflows.

You can check the workflow runs on [kernel-patches/bpf actions page](https://github.com/kernel-patches/bpf/actions/workflows/test.yml). 

**"BPF CI"** refers to a continuous integration testing system targeting [BPF subsystem of the Linux Kernel](https://ebpf.io/what-is-ebpf/).

BPF CI consists of a number of components:
- [kernel-patches/bpf](https://github.com/kernel-patches/bpf) - a copy of Linux Kernel source repository tracking [upstream bpf trees](https://web.git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/)
- [Kernel Patches Daemon](https://github.com/kernel-patches/kernel-patches-daemon) instance - a service connecting [Patchwork](https://patchwork.kernel.org/project/netdevbpf/list/) with the GitHub repository
- [kernel-patches/vmtest](https://github.com/kernel-patches/vmtest) (this repository) - GitHub Actions workflows
- [libbpf/ci](https://github.com/libbpf/ci) - custom reusable GitHub Actions
- [kernel-patches/runner](https://github.com/kernel-patches/runner) - self-hosted GitHub Actions runners

Of course BPF CI also has important dependencies such as:
- [selftests/bpf](https://web.git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf) - the main test suite of BPF CI
- [selftests/sched_ext](https://web.git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/sched_ext) - in-kernel sched_ext test suite
- [veristat](https://web.git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/veristat.c) - used to catch performance and BPF verification regressions on a suite of complex BPF programs
- [vmtest](https://github.com/danobi/vmtest) - a QEMU wrapper, used to execute tests in a VM
- [GCC BPF backend](https://gcc.gnu.org/wiki/BPFBackEnd)
- Above-mentioned [Patchwork](https://patchwork.kernel.org/) instance, maintained by the Linux Foundation
