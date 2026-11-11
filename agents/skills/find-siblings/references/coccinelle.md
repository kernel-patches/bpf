<!-- SPDX-License-Identifier: GPL-2.0-only -->

# Searching for a bug pattern with Coccinelle

Documentation/dev-tools/coccinelle.rst describes `make coccicheck` and its
options. The semantic patch language is documented at
https://coccinelle.gitlabpages.inria.fr/website/docs/.

1. Look under `scripts/coccinelle/` for a semantic patch that already covers
   the defect. Read its rules rather than its name: `kfree()` of memory from
   `kvmalloc()` is covered by `api/kfree_mismatch.cocci`, while
   `api/kvmalloc.cocci` only flags an open-coded `is_vmalloc_addr()` test.

2. Otherwise, write a semantic patch outside the repository. Match only what
   the defect needs, not names or statements specific to the fixed site. Mark
   the lines of interest with `*`, and declare `virtual context`: coccicheck
   passes `-D context`, and spatch rejects a mode the file does not declare.
   A minimal rule for memory from `kvmalloc()` released with `kfree()`, a
   case that `api/kfree_mismatch.cocci` covers more completely:

       virtual context

       @@
       expression E;
       @@
       E = \(kvmalloc\|kvzalloc\|kvcalloc\|kvmalloc_array\)(...);
       ...
       * kfree(E);

3. Check that it finds the site you fixed. Coccinelle reads the files on
   disk, where the fix is usually already applied, so copy the file as it was
   before the fix to a directory outside the repository and run
   `spatch -D <mode> --very-quiet --sp-file <rule> <copy>`, with a mode the
   rule declares on a `virtual` line, such as `context` or `report`. Without
   `-D`, rules that depend on a mode do not run and nothing is reported. The
   rule must mark the fixed site in that copy, and nothing in the fixed
   version. If it misses the site, correct the rule before searching further.

4. Search the whole tree:

       make coccicheck MODE=context COCCI=<rule> DEBUG_FILE=<new log file>

   - Use a `MODE` the rule declares on a `virtual` line, as in step 3.
   - In context mode the output is a diff, and each line starting with `-`
     is a line the rule marked; report mode prints one warning per site.
     coccicheck searches the files on disk, so a site you already fixed
     there is not marked; step 3 covers it.
   - The kernel's `.cocciconfig` makes spatch skip files that do not contain
     the rule's identifiers, so a whole-tree search is usually quick when the
     rule names distinctive functions. Add `M=<dir>/` only if it is not.
   - Give `COCCI` and `DEBUG_FILE` as absolute paths. With `M=`, coccicheck
     runs from that directory.
   - Read the log. Without `DEBUG_FILE`, spatch errors are discarded and a
     broken rule shows only as "coccicheck failed". coccicheck refuses to
     reuse an existing log file.
   - Header files are searched only with `SPFLAGS=--include-headers`, or with
     a `// Options: --include-headers` line at the top of the rule.

5. Check what was not searched. Coccinelle skips code it cannot parse without
   saying so. Run `spatch --parse-c` on the searched files or directories: a
   nonzero `nb bad` count means part of them was skipped. Search those files
   another way and report the gap.

If the rule marks many sites that turn out to be safe, tighten it, for example
with `when !=` constraints, and run it again rather than discarding candidates
by hand.
