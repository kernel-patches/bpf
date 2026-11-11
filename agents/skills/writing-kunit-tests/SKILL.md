---
# SPDX-License-Identifier: GPL-2.0-only
name: writing-kunit-tests
description: >-
  Design, implement, verify, or review KUnit unit tests for the Linux kernel.
  Use when writing new KUnit tests, expanding existing KUnit test suites,
  adding regression tests with KUnit, or reviewing KUnit test patches.
---

# Write KUnit tests

Before writing or modifying any code, read the relevant kernel documentation:
- **KUnit Framework & Style**:
  `Documentation/dev-tools/kunit/usage.rst`,
  `Documentation/dev-tools/kunit/style.rst`,
  `Documentation/dev-tools/kunit/start.rst`, and
  `Documentation/dev-tools/kunit/api/functionredirection.rst`
- **Kernel Development & Patch Submission**:
  `Documentation/process/development-process.rst`,
  `Documentation/process/coding-style.rst`,
  `Documentation/process/submitting-patches.rst`, and
  `Documentation/process/license-rules.rst`
- **AI Coding Assistants & Tool-Generated Content**:
  `Documentation/process/coding-assistants.rst` and
  `Documentation/process/generated-content.rst`

Also inspect existing KUnit tests in the target subsystem (e.g., `*-test.c` or
`tests/*_kunit.c`) to follow established local conventions for file naming,
symbol visibility, Kconfig, and Makefile integration.

---

## 1. Core Unit Testing Principles

Apply the following software testing best practices to ensure KUnit tests have
high **fidelity** (fail when code is broken), **resilience** (only fail when
actual behavior breaks, not during internal refactoring), **precision**
(pinpoint the exact defect on failure), and **clarity** (serve as executable
documentation):

### 1.1 Test Behaviors, Not Functions or Implementation Details
- **Avoid a 1:1 function-to-test mapping**: A single C function often exhibits
  multiple distinct behaviors (e.g., normal insertion, merging with left/right
  neighbors, splitting an existing entry, error handling), and a single logical
  behavior may span multiple functions (e.g., insert followed by lookup and
  removal). Write separate test cases for each distinct behavior.
- **Test public/subsystem APIs over internal details**: Exercise the unit
  through its intended interface rather than testing private helper functions in
  isolation whenever possible. If internal implementation details are
  refactored without changing observable behavior, existing tests should
  continue to pass.
- **Do not write "change-detector" tests**: Never write tests that merely
  mirror the implementation line-by-line or assert an exact sequence of
  internal helper calls without checking the resulting state or output.

### 1.2 Keep Tests Focused
- **One scenario per test case**: Each `static void test_...(struct kunit *test)`
  function should test a single scenario or behavior.
- **Do not chain unrelated scenarios in one test**: Avoid mutating state across
  a long sequence of unrelated scenarios in a single test function where side
  effects from an earlier check can mask bugs or invalidate assumptions in
  later checks.
- **Include the scenario and expected outcome in test names**: Name test
  functions so a developer can tell what scenario is being exercised and what
  should happen from the function name alone (e.g.,
  `test_es_insert_adjacent_same_status_merges_extents` or
  `unpack_u32_with_null_name_fails` rather than just `test_insert` or
  `test_unpack`).

### 1.3 Make Tests DAMP, Not Overly DRY
- **Prioritize readability by inspection (DAMP — Descriptive and Meaningful
  Phrases)**: Because tests do not have their own tests, their correctness must
  be obvious to a human reviewer reading top-to-bottom. Do not over-abstract
  tests just to eliminate a few lines of duplication.
- **Keep cause and effect together**: Set up the specific inputs that drive a
  test's outcome directly inside the test case body right before the call under
  test and its `KUNIT_EXPECT_*` checks. Never hide the critical input values
  that determine an expected output inside a distant `.init` function.
- **Include only relevant details (hide noise)**: Use helper functions to hide
  irrelevant boilerplate setup (such as allocating a dummy `super_block`,
  initializing locks, or zeroing unrelated struct fields), but pass the values
  that actually matter to the test explicitly as arguments at the call site:

  ```c
  /* BAD: Critical values hidden inside helper, or noisy setup inline */
  inode = create_test_inode();
  KUNIT_EXPECT_EQ(test, get_quota_blocks(inode), 42); /* Where did 42 come from? */

  /* GOOD: Helper hides boilerplate; test-relevant value is explicit */
  inode = create_test_inode_with_reserved_blocks(test, 42);
  KUNIT_EXPECT_EQ(test, get_quota_blocks(inode), 42);
  ```

### 1.4 Don't Put Logic in Tests & Prefer Literals/Constants
- **State expected outputs directly**: Never compute expected values in
  assertions using arithmetic, bit shifts, string concatenation, loops, or
  conditionals that duplicate the production algorithm. Computing expectations
  in tests can introduce bugs in the test itself or mask a shared bug in
  production code.
- **Prefer literals or named constants in assertions**: Compare actual results
  against concrete literals or self-explanatory constants rather than dynamic
  expressions derived from the system under test.

### 1.5 Choose Robust Test Values & Think Beyond Line Coverage
- **Test with non-default values**: In the kernel, structs are frequently
  zero-allocated (`kzalloc` / `kunit_kzalloc`). If you test a setter, parser,
  or lookup using `0`, `false`, `NULL`, or enum value `0`, a broken
  implementation that never writes the field will still pass! Always use
  non-zero, non-default test values for positive tests.
- **Use distinct values for each parameter**: When calling a function that
  takes multiple arguments of the same or compatible types (e.g.,
  `ext4_es_insert_extent(inode, lblk, len, pblk, status, ...)`), use clearly
  distinct values (e.g., `lblk = 10`, `len = 5`, `pblk = 1000`) so swapped
  arguments or off-by-one mixups are caught immediately.
- **Think beyond line coverage**:
  - **Branch & Condition coverage**: For compound boolean conditions like
    `if ((a && b) || !c)`, write test cases that exercise each condition
    independently, not just a single path that executes the line.
  - **Boundary & Edge cases**: Test `0`, `1`, exact power-of-two/cluster
    boundaries, maximum legal limits (e.g., `INT_MAX`, `ULONG_MAX`,
    `EXT_MAX_BLOCKS`), overflow/underflow boundaries, empty trees/lists,
    single-element collections, and multi-element spans.
  - **Error paths**: Test invalid inputs, `-EINVAL` / `-ENOMEM` / `-ENOSPC`
    conditions, and verify that error paths leave data structures in a valid,
    uncorrupted state without leaking resources.

### 1.6 Prefer Narrow Assertions & Make Failures Actionable
- **Actionable failure messages**: When a test fails, the test name and KUnit
  failure log alone should be enough to start debugging without adding
  `printk`s and re-running.
- **Use specific KUnit expectation macros**:
  - Use `KUNIT_EXPECT_EQ(test, actual, expected)`, `KUNIT_EXPECT_NE`,
    `KUNIT_EXPECT_LT`, `KUNIT_EXPECT_LE`, `KUNIT_EXPECT_GT`, `KUNIT_EXPECT_GE`
    for integers/enums (instead of `KUNIT_EXPECT_TRUE(test, a == b)`, which
    only prints `Expected true, got false`).
  - Use `KUNIT_EXPECT_PTR_EQ`, `KUNIT_EXPECT_NULL`, `KUNIT_EXPECT_NOT_NULL`,
    `KUNIT_EXPECT_NOT_ERR_OR_NULL` for pointers.
  - Use `KUNIT_EXPECT_STREQ` / `KUNIT_EXPECT_MEMEQ` for strings and buffers.
- **Use `_MSG` variants in loops and helpers**: Whenever an expectation is
  inside a helper function, loop, or table-driven check, use
  `KUNIT_EXPECT_*_MSG(test, ..., "context fmt", ...)` so the failure output
  identifies the exact case or index that failed.
- **Prefer narrow assertions**: Assert only the struct fields or properties
  relevant to the behavior under test, rather than asserting every unrelated
  field of a large struct (which creates brittle tests that break whenever
  unrelated fields change).

### 1.7 Test Isolation, Order Independence, and Zero Flakiness
- **Complete independence between test cases**: Every test case must pass when
  run by itself (`kunit.py run suite.test`), in any order, or repeatedly.
- **Never leak mutable shared state**: Avoid file-scope mutable globals. Prefer
  allocating per-test context in `test->priv` via `kunit_kzalloc(test, ...)` in
  `.init`. If a suite shares a fixture structure, ensure `.init` and `.exit`
  completely reset all trees, lists, flags, and stub counters before and after
  every single test case.
- **No "sleep gambling"**: Never use `msleep()` or arbitrary delays to wait for
  asynchronous work in unit tests. Test synchronous entry points, flush
  workqueues deterministically, or inject synchronous stubs.

### 1.8 High Fidelity & Smart Use of Test Doubles (Real > Fake > Stub > Mock)
- **Prefer real implementations first**: Use real kernel data structures (e.g.,
  `rbtree`, `xarray`, `list_head`, in-memory anonymous `super_block` / `inode`,
  or `kunit_device_register()`) whenever they run fast and deterministically in
  memory.
- **Use fakes or stubs to isolate heavyweight dependencies**: When code under
  test interacts with hardware, disk I/O, journals, block allocators, or global
  kernel state, isolate it using:
  1. **Lightweight in-memory fakes** (e.g., an ops struct backed by a memory
     buffer), or
  2. **KUnit static stubs** (`KUNIT_STATIC_STUB_REDIRECT` and
     `kunit_activate_static_stub`).
- **Avoid overusing mocks / interaction verification**:
  - Prefer **state testing** (verifying return values and resulting data
    structure state) over **interaction testing** (verifying that function X
    was called).
  - Only verify **state-changing** external calls (e.g., verifying that a
    delayed-allocation block reservation was claimed or released), never
    read-only query helpers.
  - When verifying stub calls, only check arguments relevant to the behavior
    being tested.

### 1.9 Parameterize Repetitive Tests Judiciously
- **Use parameterized or table-driven tests for input/output matrices**: When
  testing the same behavior across many input combinations (e.g., extent
  merge/split geometries, timestamp bit-decoding tables, hash test vectors),
  use `KUNIT_ARRAY_PARAM` / `KUNIT_ARRAY_PARAM_DESC` with `KUNIT_CASE_PARAM`
  (or a clean table-driven helper) to avoid copy-pasting identical test
  functions.
- **Do not put conditional logic inside parameterized tests**: If a
  parameterized test requires `if (param->expect_error)` or
  `switch (param->mode)` inside the test function to decide what assertions to
  run, split it into separate parameterized or standalone tests instead.

---

## 2. KUnit Framework Idioms & Mechanics

### 2.1 Expectations vs. Assertions
- **`KUNIT_EXPECT_*`**: Records a test failure and logs diagnostic details, but
  **continues** executing the rest of the test case. Use `KUNIT_EXPECT_*` for
  the behavioral checks in your test.
- **`KUNIT_ASSERT_*`**: Immediately **aborts** the current test case
  (terminating the KUnit kthread) on failure. Use `KUNIT_ASSERT_*` for
  preconditions whose failure makes continuing impossible or unsafe (e.g.,
  `KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr)` after memory allocation or object
  lookup before dereferencing `ptr`).
- **CRITICAL**: **Never** use `KUNIT_ASSERT_*` in `.exit()`, `.suite_exit()`,
  or `kunit_resource` / action cleanup callbacks. Aborting during teardown
  skips subsequent cleanup steps and causes memory or resource leaks in the
  running kernel.

### 2.2 Resource & Memory Management
- **Managed memory**: Always prefer `kunit_kmalloc()`, `kunit_kzalloc()`,
  `kunit_kcalloc()`, `kunit_kmalloc_array()`, and `kunit_kstrdup()` over raw
  `kmalloc`/`kzalloc`. KUnit automatically frees these allocations when the
  test case exits—even if a `KUNIT_ASSERT_*` aborts the test midway.
- **Deferred cleanup actions**: For non-memory resources (e.g., unregistering a
  shrinker, freeing slab cache objects, releasing locks/superblocks, cleaning
  up trees), either clean them up in `.exit` or register a deferred action
  immediately after acquisition using `kunit_add_action_or_reset()`:

  ```c
  KUNIT_DEFINE_ACTION_WRAPPER(my_resource_cleanup, my_resource_cleanup_wrapper,
                              struct my_resource *);
  ...
  ret = kunit_add_action_or_reset(test, my_resource_cleanup_wrapper, res);
  KUNIT_ASSERT_EQ(test, ret, 0);
  ```
  Always use `KUNIT_DEFINE_ACTION_WRAPPER()` rather than casting function
  pointers to `kunit_action_t`, as casting function pointers breaks Control
  Flow Integrity (CFI).
- **Safe `.exit` functions**: Remember that `.exit` and `.suite_exit` run even
  if `.init` or `.suite_init` failed or exited early. Always guard `.exit`
  cleanup against NULL or partially initialized pointers.
- **Fake devices**: When code under test requires a `struct device *` (e.g.,
  for `devm_*` managed APIs), use `kunit_device_register(test, "name")` from
  `<kunit/device.h>`.

### 2.3 Testing Static Functions & Isolating Dependencies
Check how the target subsystem exposes internal functions to KUnit tests and
follow the local convention:

1. **Subsystem export macros** (e.g., `EXPORT_SYMBOL_FOR_EXT4_TEST(fn)` or
   `VISIBLE_IF_KUNIT` / `EXPORT_SYMBOL_IF_KUNIT(fn)` from
   `<kunit/visibility.h>` paired with
   `MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");` in the test file).
2. **Conditionally `#include`ing the test file** at the bottom of the `.c` file
   under `#if IS_ENABLED(CONFIG_<SUBSYSTEM>_KUNIT_TEST)` if the subsystem
   already uses that pattern to test `static` functions directly.
3. **Function Redirection (Static Stubs)**: To intercept calls to external
   functions during a test without refactoring production APIs:
   - In the real function (right after variable declarations):
     ```c
     #include <kunit/static_stub.h>
     ...
     KUNIT_STATIC_STUB_REDIRECT(my_external_fn, arg1, arg2);
     ```
   - In the KUnit test:
     ```c
     kunit_activate_static_stub(test, my_external_fn, my_external_fn_stub);
     ```
   - If the stub needs the current `struct kunit *`, call
     `kunit_get_current_test()` (`#include <kunit/test-bug.h>`).
4. **Suppressing expected warning backtraces**: If a test intentionally
   triggers `WARN()` / `WARN_ON()`, wrap the call in
   `kunit_warning_suppress(test)` and verify with
   `KUNIT_EXPECT_SUPPRESSED_WARNING_COUNT(test, 1)` so intentional warnings do
   not pollute kernel logs.

### 2.4 Suite, File, and Kconfig Nomenclature
Unless the subsystem has an established convention (such as `fs/ext4/*-test.c`
linked into `ext4-test.o`), follow `Documentation/dev-tools/kunit/style.rst`:

- **Subsystem & Suite naming**: Name the suite `<subsystem>_<area>` using
  underscores, without redundant `_kunit` or `_test` suffixes in `.name`
  (unless matching existing suites in that directory).
- **File naming**: Place new standalone test files in `tests/<suite>_kunit.c`
  (or match the subsystem's existing `*-test.c` / `*_kunit.c` pattern).
- **Kconfig**:
  ```kconfig
  config FOO_KUNIT_TEST
  	tristate "KUnit test for foo" if !KUNIT_ALL_TESTS
  	depends on FOO && KUNIT
  	default KUNIT_ALL_TESTS
  	help
  	  This builds unit tests for foo.

  	  For more information on KUnit and unit tests in general,
  	  please refer to the KUnit documentation in
  	  Documentation/dev-tools/kunit/.

  	  If unsure, say N.
  ```

---

## 3. Building, Running, and Verifying Tests

Build and run the KUnit tests before finalizing or committing changes:

1. **Run the test suite with `kunit.py`**:
   ```bash
   ./tools/testing/kunit/kunit.py run <suite_name>
   ```
   (If a `.kunitconfig` exists in the repo root or subsystem directory, pass
   `--kunitconfig=.kunitconfig` or `--kunitconfig=<subdir>/.kunitconfig`, or
   add needed configs via `--kconfig_add CONFIG_...=y`).
2. **Verify zero build warnings**: Ensure the added or modified files compile
   with zero compiler warnings or errors.
3. **Verify test isolation**: Run individual test cases using glob filtering to
   confirm no test depends on state left behind by an earlier test:
   ```bash
   ./tools/testing/kunit/kunit.py run "<suite_name>.<test_case_name>"
   ```
4. **Verify test fidelity**: Confirm that the tests actually exercise the
   intended code paths (e.g., via GCOV/coverage if configured, or by
   verifying that breaking the condition under test causes the KUnit
   expectation to fail).

---

## 4. Coding Style, Licensing, and Commits

Follow `Documentation/process/coding-style.rst`,
`Documentation/process/submitting-patches.rst`,
`Documentation/process/license-rules.rst`, and
`Documentation/process/coding-assistants.rst`:

- **SPDX & Module Macros**:
  - Line 1 of every new `.c` test file must be
    `// SPDX-License-Identifier: GPL-2.0` (or the appropriate
    GPL-2.0-compatible identifier).
  - Include `MODULE_LICENSE("GPL");` and `MODULE_DESCRIPTION("...");` at the
    bottom of the test module.
- **Checkpatch**: Run `./scripts/checkpatch.pl` on the changes and fix all
  reported `ERROR`, `WARNING`, and `CHECK` issues.
- **Commits**: When asked to create a commit, use the `commit-message` skill
  (`agents/skills/commit-message/SKILL.md`). Explain what behaviors and edge
  cases are covered, any minimal production code hooks added (such as
  `KUNIT_STATIC_STUB_REDIRECT` or KUnit symbol exports), and how the tests were
  verified. Never add a `Signed-off-by:` tag.
- **Report verification status**: Clearly state what was built and tested
  (including `kunit.py` and `checkpatch.pl` results), and explicitly note
  anything that could not be built or verified.
