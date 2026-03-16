# Isolation Remediation Plan

> **For agentic workers:** Treat `docs/superpowers/specs/2026-03-16-comprehensive-testing-design.md` and `docs/superpowers/specs/2026-03-16-standards-addendum.md` as authoritative. This file is an implementation plan for closing the current isolation gap in the codebase.

**Date:** 2026-03-16

**Goal:** Make `p11test test` survive PKCS#11 module crashes in real runs without blocking future support for multiple simultaneous sessions, pytest workers, and richer timeout/reporting behavior.

**Primary references:**
- `docs/superpowers/specs/2026-03-16-comprehensive-testing-design.md`
- `docs/superpowers/specs/2026-03-16-standards-addendum.md`

---

## 1. Current Gap

The current implementation does not satisfy the runtime-isolation behavior described in the specs:

- `src/p11test/cli/test_cmd.py` invokes `pytest.main(...)` in-process.
- `src/p11test/fixtures.py` loads the module and opens sessions directly in the normal pytest runtime.
- `src/p11test/plugin.py` probes mechanisms by calling `load_module()` during collection.
- `src/p11test/core/isolation.py` exists, but it is not integrated into the pytest execution path.

This means a real PKCS#11 crash can still kill collection or the whole test run.

---

## 2. Decision

Use a hybrid approach:

1. **Immediate fix:** use `pytest-forked` as the default crash-containment layer for `p11test test` on POSIX.
2. **Required companion fix:** remove all PKCS#11 module access from collection time.
3. **Default runtime model:** keep parallel pytest workers disabled by default until token/slot isolation is implemented.
4. **Future work:** keep `src/p11test/core/isolation.py` as the basis for richer timeout/result semantics if `pytest-forked` becomes insufficient.

This gives a small, practical fix for the current crash-survival problem while preserving a path toward the more ambitious behavior described in the specs.

---

## 3. Why This Approach

### What `pytest-forked` solves

- Segfaults during fixture setup, test execution, or teardown are contained to the forked test process.
- The main pytest runner can continue to the next test.
- This is the shortest path to making `p11test test` materially safer on Linux/macOS.

### What `pytest-forked` does not solve

- It does **not** protect collection if the main process still loads the PKCS#11 module during collection.
- It does **not** provide the richer `crashed` / `timeout` / queue-driven reporting model described in the specs.
- It does **not** solve worker-level interference on shared tokens or slots.
- It is not a Windows story.

### Why not jump straight to a custom pytest isolation plugin

- It is a larger design and test effort.
- The repo already has an immediate practical gap in normal `p11test test` execution.
- A staged approach reduces risk and gets crash containment in place first.

---

## 4. Main Risks Beyond Crash Containment

The larger roadmap includes concurrent sessions, stress tests, and worker-based parallelism. Those concerns are real, but they are different from the immediate crash-survival issue.

### 4.1 Collection-time safety

This is the first blocker. Any collection hook that calls into PKCS#11 defeats per-test isolation.

### 4.2 Shared-token interference across workers

Many tests use fixed labels or rely on token-global state. Running multiple pytest workers against the same token can cause:

- object-label collisions
- login-state races
- token-state contamination
- nondeterministic failures in search and stress tests

### 4.3 Timeout semantics

The specs call for:

- per-test timeout
- per-operation timeout
- crash/timeout recovery validation
- structured outcomes after worker failure

`pytest-forked` helps with containment, but not with the full result model.

---

## 5. Implementation Phases

## Phase 1: Immediate Crash-Survival Fix

- [ ] Add `pytest-forked` as a dependency.
- [ ] Make `p11test test` pass `--forked` by default on POSIX.
- [ ] Keep normal pytest plugin usage unchanged for users who run pytest directly.
- [ ] Document that forked isolation is the default CLI safety mechanism on POSIX.

**Acceptance criteria:**
- A test that segfaults during fixture setup does not kill the whole run.
- A test that segfaults during execution is reported as failed by pytest and the next test still runs.

## Phase 2: Remove Collection-Time PKCS#11 Access

- [ ] Remove `load_module()` from `pytest_collection_modifyitems`.
- [ ] Move mechanism-availability checks out of collection and into runtime-safe logic.
- [ ] Move real interface-version probing out of collection as well.

**Acceptance criteria:**
- `pytest --collect-only` never loads the PKCS#11 module.
- A module that crashes on initialization cannot kill collection.

## Phase 3: Make Parallelism Explicit and Safe

- [ ] Keep worker count at 1 by default for `p11test test`.
- [ ] Design worker-safe isolation before enabling xdist by default.
- [ ] Add worker-aware namespacing for labels and temporary objects.
- [ ] Define whether multi-worker execution requires separate slots, separate tokens, or per-worker token reset.

**Acceptance criteria:**
- Parallel workers are opt-in until token isolation exists.
- Parallel runs on a shared token are either explicitly unsupported or clearly isolated.

## Phase 4: Decide the Long-Term Role of `core/isolation.py`

- [ ] Evaluate whether `pytest-forked` is sufficient once collection is safe.
- [ ] If not sufficient, integrate `core/isolation.py` into pytest for:
  - explicit `crashed` / `timeout` classifications
  - per-operation timeout enforcement
  - global timeout budgeting
  - future Windows-compatible isolation

**Acceptance criteria:**
- The final isolation mechanism matches the reporting and timeout model required by the specs.

---

## 6. Recommended Defaults

Until Phase 3 is complete:

- `p11test test` should default to forked per-test isolation on POSIX.
- xdist workers should stay off by default.
- stress and concurrency tests should remain opt-in.
- destructive tests should remain opt-in.

This keeps the default mode safe and predictable for software tokens and for early hardware testing.

---

## 7. Meta-Tests To Add

- [ ] Crash in fixture setup -> runner survives.
- [ ] Crash in test body -> next test still executes.
- [ ] Hang in test body -> timeout behavior is correct.
- [ ] Collection path does not call `load_module()`.
- [ ] Forked execution is enabled by default in the CLI on POSIX.
- [ ] Parallel worker mode is either disabled by default or clearly gated.

---

## 8. Non-Goals For The Immediate Fix

The immediate remediation should **not** attempt to solve all of the following at once:

- Windows isolation parity
- full per-operation timeout enforcement
- structured severity reporting
- cross-worker shared-token correctness
- all future concurrency/stress design work

Those belong to later phases after the current crash-survival hole is closed.

---

## 9. Recommended Order Of Work

1. Add `pytest-forked` and enable `--forked` in the CLI on POSIX.
2. Remove collection-time PKCS#11 loading.
3. Add crash-survival meta-tests.
4. Stabilize worker/token isolation strategy before enabling xdist by default.
5. Reassess whether custom pytest integration around `core/isolation.py` is still needed.

