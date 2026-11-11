---
# SPDX-License-Identifier: GPL-2.0-only
name: stable-tag
description: >-
  Decide whether a Linux kernel fix should be backported to stable kernels
  and return verified Cc: stable tag lines. Use when preparing or reviewing
  bug-fix patches, drafting their commit messages, or checking an existing
  stable tag.
---

# Determine a stable tag

Read Documentation/process/stable-kernel-rules.rst. It says which changes go
to stable and how to write the tag, its prerequisites and its version. Follow
the rules for skills in Documentation/process/coding-assistants.rst.

Judge a change by what it does, not by how its description labels it: a
"cleanup" that releases a resource on an error path fixes a leak. In practice,
the stable trees take:

- Fixes for crashes, oopses, BUG and WARN splats, hangs, lockups, RCU stalls,
  deadlocks, data corruption and security issues.
- Fixes for use-after-free, double free, NULL pointer dereferences,
  out-of-bounds accesses, integer overflows, uninitialized data, reference
  counting errors, and memory or resource leaks.
- Fixes for races, including data races.
- Fixes for incorrect behavior, such as wrong results, wrong hardware
  programming, or endianness and type errors.
- Fixes for problems reported by syzbot, other fuzzers, or the KASAN, KMSAN,
  KCSAN and UBSAN sanitizers.
- New device IDs and quirks for drivers that exist in the stable trees, device
  tree fixes, and device tree additions for hardware that existing drivers
  support.
- Corrections to documentation that is wrong.
- Performance fixes that prevent lockups, stalls or hangs.
- Reverts of commits that are in a released kernel.
- Fixes for bugs introduced by commits that were backported to stable.

They do not take the following, unless a fix that is taken depends on it:

- New features, new user-visible interfaces or behavior, new drivers, and new
  module parameters or sysfs attributes.
- Refactoring, code movement and other preparation patches.
- Optimizations that do not prevent lockups, stalls or hangs.
- Cleanups that do not change behavior, such as style, renames and comment
  changes.

Then work out which releases need the fix:

- Determine the Fixes tags with the find-fixes skill first. A change with no
  introducing commit, such as a new device ID, a quirk or a build fix, or a
  bug older than the available history, affects every release that contains
  the code it changes. Otherwise, if the Fixes tags are unresolved, so is the
  stable decision.
- For each Fixes tag, find the first release that contains the commit, not the
  release it was based on. If no release contains it, check whether the
  commit was itself backported to stable.
- Check that everything the fix uses exists in the oldest affected release.
  If something is missing, list the commit that added it as a prerequisite
  if it is small and fit for stable, or start the tag at the first release
  that has it.
- Give every stable tag in a commit the same version: a tag without a version
  asks for every stable tree and overrides the versions in the other tags.
  The stable tooling reads the first version number in a tag comment as the
  version, so describe what older trees need in the commit message.
- Follow the stable tag policy in the maintainer profiles, the `P:` entries in
  MAINTAINERS, for the changed files.
- Ask the caller whether the fix addresses an unpublished vulnerability, as
  described in Documentation/process/threat-model.rst.

Return the tag lines with the reasons for them, or the reasons for no tag. If
the decision cannot be made, return no tag and say what is missing.
