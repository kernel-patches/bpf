---
# SPDX-License-Identifier: GPL-2.0-only
name: commit-message
description: >-
  Write, rewrite or review the commit message for a Linux kernel change or
  the cover letter for a patch series, and write the signed tag and pull
  request text for a subsystem pull. Use when committing or preparing
  patches, when asked to improve or check a commit message, or when
  preparing a pull request for an upstream maintainer.
---

# Write a commit message

Read "Describe your changes", the sections on tags, "The canonical patch
format" and "Commentary" in Documentation/process/submitting-patches.rst, and
Documentation/process/5.Posting.rst for cover letters. Follow the maintainer
profiles, the `P:` entries in MAINTAINERS, for the changed files; they take
precedence. Follow the rules for skills and for attribution in
Documentation/process/coding-assistants.rst, and
Documentation/process/generated-content.rst when a tool found the problem.
When editing someone else's message, also follow
Documentation/maintainer/modifying-patches.rst.

- State only what the diff and the sources you were given support, such as a
  bug report, a crash log, test results, or the list discussion found with
  `lei q` on lore.kernel.org. If the reason for the change is not known,
  return no message and say what is missing.
- Take the Fixes and stable tags from the find-fixes and stable-tag skills.
  Add other tags only when they were supplied or given on the list. Never add
  a Signed-off-by.
- If a semantic patch found the bug, include it in the message between
  `// <smpl>` and `// </smpl>` lines. For one under scripts/coccinelle/, give
  its path instead.
- Use the imperative mood and keep the message as short as its content
  allows. Leave out markdown, labels such as "Root cause:", intensifiers, a
  restatement of the subject, and the story of the investigation.
- Check the result with `scripts/checkpatch.pl --no-signoff`.

For the signed tag and email of a pull request, follow
Documentation/maintainer/pull-requests.rst,
Documentation/maintainer/rebasing-and-merging.rst and
Documentation/maintainer/messy-diffstat.rst. Summarize what the pull contains
and why from the commit messages in the range, in the same voice, without
repeating the shortlog. Ask the caller for conflict resolutions and testing
that the history does not show.
