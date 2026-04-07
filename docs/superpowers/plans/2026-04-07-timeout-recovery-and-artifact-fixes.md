# Timeout Recovery & Artifact Failure Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix adaptive isolation timeout behavior to use progressive retry instead of full escalation, and fix confirmed pkcs11-check framework bugs found in artifact analysis.

**Architecture:** Modify the timeout handler in `file_runner.py` to mirror the existing crash iterative-deselect pattern. Fix the XTS test vector loader bug. Investigate cross-provider failures to determine if they're framework bugs or correct module findings.

**Tech Stack:** Python 3.13+, pytest, ctypes (pkcs11 raw bindings)

---

## Task 1: Fix `_unit_timeout_seconds` to accept test count

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py:1635-1638`
- Test: `tests/test_file_runner.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_file_runner.py`:

```python
def test_unit_timeout_seconds_with_num_tests() -> None:
    from pkcs11_check.core.file_runner import _unit_timeout_seconds

    # Per-test granularity ignores num_tests
    assert _unit_timeout_seconds(120, "test", num_tests=100) == 180

    # Per-file with num_tests uses scaled formula
    assert _unit_timeout_seconds(120, "file", num_tests=100) == 560  # 100*5+60
    assert _unit_timeout_seconds(120, "file", num_tests=10) == 300   # floor
    assert _unit_timeout_seconds(120, "file", num_tests=30000) == 14400  # cap

    # Per-file without num_tests uses legacy formula
    assert _unit_timeout_seconds(120, "file") == 3600  # 120*30
    assert _unit_timeout_seconds(120, "file", num_tests=0) == 3600  # same as no num_tests
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_file_runner.py::test_unit_timeout_seconds_with_num_tests -v`
Expected: FAIL — `_unit_timeout_seconds` doesn't accept `num_tests`

- [ ] **Step 3: Implement the change**

In `src/pkcs11_check/core/file_runner.py`, replace `_unit_timeout_seconds`:

```python
def _unit_timeout_seconds(
    test_timeout: int,
    granularity: IsolationGranularity,
    *,
    num_tests: int = 0,
) -> int:
    if granularity == "test":
        return max(test_timeout + 60, 120)
    if num_tests > 0:
        # 5s per test + 60s startup overhead, floor 300s, cap 14400s (4h)
        return min(max(num_tests * 5 + 60, 300), 14400)
    return max(test_timeout * 30, 900)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_file_runner.py::test_unit_timeout_seconds_with_num_tests -v`
Expected: PASS

- [ ] **Step 5: Run existing tests to check no regressions**

Run: `uv run pytest tests/test_file_runner.py -x -q`
Expected: All existing tests still pass (the new `num_tests` param is keyword-only with default 0, so all existing call sites are unaffected).

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py tests/test_file_runner.py
git commit -m "feat: _unit_timeout_seconds accepts num_tests for scaled file timeouts"
```

---

## Task 2: Implement progressive timeout retry in `run_isolated_pytest_units`

This is the core change. Replace the timeout→escalation path with a progressive retry loop that mirrors the existing crash iterative-deselect pattern.

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py:2112-2196` (timeout handler block)
- Modify: `src/pkcs11_check/core/file_runner.py:1822-1868` (`_escalate_current_file` — add `exclude_nodeids`)
- Test: `tests/test_file_runner.py`

- [ ] **Step 1: Add `exclude_nodeids` parameter to `_escalate_current_file`**

In `src/pkcs11_check/core/file_runner.py`, modify `_escalate_current_file` (line 1822). Add an `exclude_nodeids` parameter that filters out already-completed tests from the escalated list:

```python
def _escalate_current_file(
    *,
    unit: str,
    units: list[str],
    index: int,
    state: FileRunState,
    pytest_args: list[str],
    env: Mapping[str, str],
    console: Console,
    disabled_nodeids: set[str] | None = None,
    baseline_fingerprint: str | None = None,
    exclude_nodeids: set[str] | None = None,
) -> list[str]:
    try:
        nodeids = discover_pytest_units(
            [unit],
            Path(unit).parent,
            granularity="test",
            pytest_args=pytest_args,
            env=env,
        )
    except ValueError as exc:
        console.print(
            f"[yellow]Adaptive isolation:[/yellow] failed to collect tests for {unit}: {exc}"
        )
        return []

    filtered_nodeids = (
        [nodeid for nodeid in nodeids if nodeid not in disabled_nodeids]
        if disabled_nodeids
        else nodeids
    )
    if exclude_nodeids:
        filtered_nodeids = [n for n in filtered_nodeids if n not in exclude_nodeids]

    additions = _insert_escalated_units(
        state,
        units,
        index,
        filtered_nodeids,
        pytest_args,
        env,
        baseline_fingerprint=baseline_fingerprint,
    )
    if additions:
        console.print(
            f"[yellow]Adaptive isolation:[/yellow] escalating {unit} to per-test isolation "
            f"for the rest of this run ({len(additions)} units)."
        )
    return additions
```

- [ ] **Step 2: Write the failing test for progressive timeout retry**

Add to `tests/test_file_runner.py`:

```python
def test_run_isolated_timeout_progressive_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """After file-level timeout, runner retries with completed tests deselected."""
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"

    call_count = 0

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        nonlocal call_count
        call_count += 1
        env = env or {}

        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                jsonl_path = Path(cmd[i + 1])
                if call_count == 1:
                    # First run: 2 tests complete, then timeout
                    jsonl_path.write_text(
                        "\n".join([
                            _jsonl_line(nodeid="test_a.py::test_one", when="setup", outcome="passed"),
                            _jsonl_line(nodeid="test_a.py::test_one", when="call", outcome="passed"),
                            _jsonl_line(nodeid="test_a.py::test_one", when="teardown", outcome="passed"),
                            _jsonl_line(nodeid="test_a.py::test_two", when="setup", outcome="passed"),
                            _jsonl_line(nodeid="test_a.py::test_two", when="call", outcome="passed"),
                            _jsonl_line(nodeid="test_a.py::test_two", when="teardown", outcome="passed"),
                            _jsonl_line(nodeid="test_a.py::test_three", when="setup", outcome="passed"),
                        ]) + "\n"
                    )
                    raise subprocess.TimeoutExpired(cmd, timeout=12)
                elif call_count == 2:
                    # Culprit confirmation: test_three passes individually
                    jsonl_path.write_text(
                        _jsonl_line(nodeid="test_a.py::test_three", when="setup", outcome="passed")
                        + "\n"
                        + _jsonl_line(nodeid="test_a.py::test_three", when="call", outcome="passed")
                        + "\n"
                        + _jsonl_line(nodeid="test_a.py::test_three", when="teardown", outcome="passed")
                        + "\n"
                    )
                    return (0, "1 passed", "")
                else:
                    # Retry with deselect: remaining tests pass
                    # Verify deselect file was used
                    deselect_file = env.get("PKCS11_CHECK_DESELECT_FILE", "")
                    if deselect_file:
                        deselected = Path(deselect_file).read_text().splitlines()
                        assert "test_a.py::test_one" in deselected
                        assert "test_a.py::test_two" in deselected
                        assert "test_a.py::test_three" in deselected
                    jsonl_path.write_text(
                        "\n".join([
                            _jsonl_line(nodeid="test_a.py::test_four", when="setup", outcome="passed"),
                            _jsonl_line(nodeid="test_a.py::test_four", when="call", outcome="passed"),
                            _jsonl_line(nodeid="test_a.py::test_four", when="teardown", outcome="passed"),
                        ]) + "\n"
                    )
                    return (0, "1 passed", "")
                break
        if call_count == 2:
            return (0, "1 passed", "")
        raise subprocess.TimeoutExpired(cmd, timeout=12)

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
    )

    saved = load_run_state(state_file)
    assert saved is not None
    # File should complete via retry, not escalate
    assert saved.results[0].status in ("passed", "failed")
    assert saved.results[0].target == "test_a.py"
    # Should NOT have escalated to individual test units
    assert all("::" not in u for u in saved.units if u != "test_a.py")
    assert call_count == 3  # initial + culprit confirm + retry
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_file_runner.py::test_run_isolated_timeout_progressive_retry -v`
Expected: FAIL — current code escalates instead of retrying

- [ ] **Step 4: Implement the progressive timeout retry**

Replace the timeout handler block in `run_isolated_pytest_units` (lines 2112-2196). The new code replaces the escalation path with an iterative retry loop, mirroring the crash deselect pattern at lines 2259-2523.

Key changes to the `except subprocess.TimeoutExpired:` block:

1. Keep the existing JSONL parsing (lines 2114-2120)
2. Keep the result recording (lines 2121-2128)
3. **Remove** the `_promote_crashing_unit()` call for timeout (line 2129)
4. **Replace** the escalation block (lines 2138-2169) with a progressive retry loop:

```python
                except subprocess.TimeoutExpired:
                    duration_s = time.monotonic() - start
                    if unit_jsonl_path is not None:
                        unit_records = _load_report_log_records(unit_jsonl_path)
                        if unit_records:
                            report_records_by_unit[unit] = unit_records
                            state.report_records_by_unit[unit] = unit_records
                            if report_config is not None and report_config.jsonl_path is not None:
                                _write_unit_report_record_cache(state_file, unit, unit_records)
                    result = FileRunResult(
                        target=unit,
                        status="timeout",
                        returncode=124,
                        duration_s=duration_s,
                    )
                    _record_result(state, result)
                    save_run_state(state_file, state)

                    # --- Progressive timeout retry (file-level only) ---
                    if (
                        granularity == "mixed"
                        and unit_granularity == "file"
                        and not stop_on_failure
                    ):
                        timeout_jsonl_path: Path | None = unit_jsonl_path
                        timeout_deselect: set[str] = set(unit_disabled_nodeids)
                        timeout_retries = 0
                        timeout_accumulated: dict[str, Any] | None = None
                        total_timeout_dur = 0.0
                        timeout_retry_temps: list[Path] = []
                        timeout_escalate = False
                        _MAX_TIMEOUT_RETRIES = 3

                        try:
                            while timeout_retries < _MAX_TIMEOUT_RETRIES:
                                # Parse partial JSONL for completed tests + culprit
                                if timeout_jsonl_path is not None:
                                    culprit, completed = _identify_crash_culprit(
                                        timeout_jsonl_path
                                    )
                                    iter_detail = _read_jsonl_results(timeout_jsonl_path)
                                else:
                                    culprit, completed = None, []
                                    iter_detail = None

                                if not culprit and not completed:
                                    # No progress info from JSONL — cannot deselect
                                    timeout_escalate = True
                                    break

                                timeout_deselect.update(completed)

                                # Merge partial results
                                if iter_detail is not None:
                                    if timeout_accumulated is None:
                                        timeout_accumulated = iter_detail
                                    else:
                                        for k in timeout_accumulated["counts"]:
                                            timeout_accumulated["counts"][
                                                k
                                            ] += iter_detail["counts"].get(k, 0)
                                        timeout_accumulated["tests"].extend(
                                            iter_detail["tests"]
                                        )
                                        for reason, cnt in iter_detail.get(
                                            "skip_reasons", {}
                                        ).items():
                                            timeout_accumulated.setdefault(
                                                "skip_reasons", {}
                                            )[reason] = (
                                                timeout_accumulated.get(
                                                    "skip_reasons", {}
                                                ).get(reason, 0)
                                                + cnt
                                            )

                                # Confirm the culprit individually
                                if culprit:
                                    console.print(
                                        f"[yellow]Timeout recovery:[/yellow] "
                                        f"testing culprit {culprit}"
                                    )
                                    confirm_rc, confirm_out, confirm_err = (
                                        _run_subprocess_tee(
                                            [
                                                sys.executable,
                                                "-m",
                                                "pytest",
                                                culprit,
                                                *pytest_args,
                                            ],
                                            env=env,
                                            timeout=_unit_timeout_seconds(
                                                timeout, "test"
                                            ),
                                        )
                                    )
                                    confirm_status = _status_from_returncode(confirm_rc)
                                    timeout_deselect.add(culprit)

                                    # Record culprit result
                                    culprit_outcome = (
                                        "timeout"
                                        if confirm_status == "timeout"
                                        else "crashed"
                                        if confirm_status == "crashed"
                                        else "passed-in-isolation"
                                    )
                                    culprit_entry: dict[str, Any] = {
                                        "nodeid": culprit,
                                        "outcome": culprit_outcome,
                                    }
                                    if confirm_status in {"crashed", "timeout"}:
                                        culprit_entry["longrepr"] = (
                                            confirm_err.strip() or confirm_out.strip()
                                        )
                                    if timeout_accumulated is None:
                                        timeout_accumulated = {
                                            "counts": {
                                                key: 0 for key in _DETAIL_COUNT_KEYS
                                            },
                                            "tests": [],
                                        }
                                    timeout_accumulated["tests"].append(culprit_entry)

                                # Retry the file with deselected tests
                                remaining = max(
                                    1, len(timeout_deselect) * 2
                                )  # rough estimate of total
                                # Use num_tests for better timeout on retry
                                num_remaining = max(1, remaining - len(timeout_deselect))
                                retry_timeout = _unit_timeout_seconds(
                                    timeout, "file", num_tests=num_remaining
                                )

                                deselect_path = write_deselect_file(timeout_deselect)
                                timeout_retry_temps.append(deselect_path)

                                retry_jsonl_fd, retry_jsonl_raw = tempfile.mkstemp(
                                    prefix="pkcs11-check-timeout-retry-",
                                    suffix=".jsonl",
                                )
                                os.close(retry_jsonl_fd)
                                retry_jsonl_path = Path(retry_jsonl_raw)
                                timeout_retry_temps.append(retry_jsonl_path)

                                retry_env = dict(env)
                                retry_env["PKCS11_CHECK_DESELECT_FILE"] = str(
                                    deselect_path
                                )
                                retry_cmd = [
                                    sys.executable,
                                    "-m",
                                    "pytest",
                                    unit,
                                    *pytest_args,
                                    "--report-log",
                                    str(retry_jsonl_path),
                                ]
                                console.print(
                                    f"[yellow]Timeout recovery:[/yellow] "
                                    f"retrying {unit} with "
                                    f"{len(timeout_deselect)} tests deselected"
                                )
                                retry_start = time.monotonic()
                                try:
                                    retry_rc, retry_out, retry_err = _run_subprocess_tee(
                                        retry_cmd,
                                        env=retry_env,
                                        timeout=retry_timeout,
                                    )
                                    retry_status = _status_from_returncode(retry_rc)
                                except subprocess.TimeoutExpired:
                                    retry_status = "timeout"
                                    retry_rc = 124
                                    retry_out = retry_err = ""
                                retry_dur = time.monotonic() - retry_start
                                total_timeout_dur += retry_dur

                                if retry_status != "timeout":
                                    # Retry completed — merge final results
                                    final_detail = _read_jsonl_results(retry_jsonl_path)
                                    if final_detail is not None:
                                        if timeout_accumulated is None:
                                            timeout_accumulated = final_detail
                                        else:
                                            for k in timeout_accumulated["counts"]:
                                                timeout_accumulated["counts"][
                                                    k
                                                ] += final_detail["counts"].get(k, 0)
                                            timeout_accumulated["tests"].extend(
                                                final_detail["tests"]
                                            )

                                    keep = retry_status != "passed" or (
                                        timeout_accumulated is not None
                                        and any(
                                            timeout_accumulated["counts"].get(k, 0) > 0
                                            for k in (
                                                "failed",
                                                "xfailed",
                                                "xpassed",
                                                "error",
                                            )
                                        )
                                    )
                                    result = FileRunResult(
                                        target=unit,
                                        status=retry_status,
                                        returncode=retry_rc,
                                        duration_s=(duration_s + total_timeout_dur),
                                        stdout=(retry_out if keep else ""),
                                        stderr=(retry_err if keep else ""),
                                    )
                                    _record_result(state, result)
                                    save_run_state(state_file, state)
                                    if timeout_accumulated is not None:
                                        per_unit_details[unit] = timeout_accumulated
                                    console.print(
                                        f"[green]TIMEOUT RETRY OK[/green] {unit} "
                                        f"({total_timeout_dur:.1f}s, "
                                        f"{len(timeout_deselect)} deselected)"
                                    )
                                    if retry_status == "failed":
                                        exit_code = 1
                                    break  # exit retry loop, continue main loop

                                # Retry also timed out — loop again
                                timeout_retries += 1
                                timeout_jsonl_path = retry_jsonl_path
                                console.print(
                                    f"[red]TIMEOUT RETRY {timeout_retries}/{_MAX_TIMEOUT_RETRIES}[/red] "
                                    f"{unit}"
                                )

                            else:
                                # Exhausted retries
                                timeout_escalate = True

                        finally:
                            all_timeout_jsonls = (
                                [unit_jsonl_path]
                                if unit_jsonl_path and unit_jsonl_path.exists()
                                else []
                            ) + timeout_retry_temps
                            if (
                                report_config is not None
                                and report_config.jsonl_path is not None
                            ):
                                unit_records_agg: list[dict[str, Any]] = []
                                for tmp in all_timeout_jsonls:
                                    if not tmp.exists():
                                        continue
                                    unit_records_agg.extend(
                                        _load_report_log_records(tmp)
                                    )
                                report_records_by_unit[unit] = unit_records_agg
                                state.report_records_by_unit[unit] = unit_records_agg
                                _write_unit_report_record_cache(
                                    state_file, unit, unit_records_agg
                                )
                                save_run_state(state_file, state)
                            for tmp in timeout_retry_temps:
                                tmp.unlink(missing_ok=True)

                        if not timeout_escalate:
                            # Retry succeeded — continue main loop
                            index += 1
                            continue

                        # Safety cap reached: escalate REMAINING tests only
                        if timeout_accumulated is not None:
                            per_unit_details[unit] = timeout_accumulated

                        escalated_units = _escalate_current_file(
                            unit=unit,
                            units=units,
                            index=index,
                            state=state,
                            pytest_args=pytest_args,
                            env=env,
                            console=console,
                            disabled_nodeids=unit_disabled_nodeids,
                            baseline_fingerprint=baseline_fingerprint,
                            exclude_nodeids=timeout_deselect,
                        )
                        if escalated_units:
                            _record_result(
                                state,
                                FileRunResult(
                                    target=unit,
                                    status="escalated",
                                    returncode=124,
                                    duration_s=duration_s,
                                ),
                            )
                            save_run_state(state_file, state)
                            pending_units.extend(escalated_units)
                            exit_code = 1
                            console.print(
                                f"[red]TIMEOUT (escalated {len(escalated_units)} remaining)[/red] "
                                f"{unit} ({duration_s:.1f}s)"
                            )
                            index += 1
                            continue

                    # Non-mixed or test-level timeout handling (unchanged)
                    if granularity in {"mixed", "test"} and unit_granularity == "test":
                        limited_units = _limit_remaining_units_for_file(
                            unit=unit,
                            units=units,
                            index=index,
                            pending_units=pending_units,
                            state=state,
                            pytest_args=pytest_args,
                            env=env,
                            console=console,
                            max_crashes_per_file=max_crashes_per_file,
                            baseline_fingerprint=baseline_fingerprint,
                        )
                        if limited_units:
                            save_run_state(state_file, state)

                    console.print(f"[red]TIMEOUT[/red] {unit} ({duration_s:.1f}s)")
                    exit_code = 1
                    if stop_on_failure:
                        console.print(
                            f"[yellow]Stopped[/yellow] at {unit}. Resume with "
                            f"[bold]--resume --state-file {state_file}[/bold]."
                        )
                        return exit_code
                    index += 1
                    continue
```

- [ ] **Step 5: Run the new test to verify it passes**

Run: `uv run pytest tests/test_file_runner.py::test_run_isolated_timeout_progressive_retry -v`
Expected: PASS

- [ ] **Step 6: Write test for safety cap escalation**

Add to `tests/test_file_runner.py`:

```python
def test_run_isolated_timeout_safety_cap_escalates_remaining(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """After 3 consecutive timeout retries, escalate only remaining tests."""
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"

    call_count = 0

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        nonlocal call_count
        call_count += 1
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                jsonl_path = Path(cmd[i + 1])
                # Every run: 1 test completes, then timeout
                test_name = f"test_a.py::test_{call_count}"
                jsonl_path.write_text(
                    "\n".join([
                        _jsonl_line(nodeid=test_name, when="setup", outcome="passed"),
                        _jsonl_line(nodeid=test_name, when="call", outcome="passed"),
                        _jsonl_line(nodeid=test_name, when="teardown", outcome="passed"),
                        _jsonl_line(nodeid=f"test_a.py::test_slow_{call_count}", when="setup", outcome="passed"),
                    ]) + "\n"
                )
                break
        # Always timeout (except culprit confirmations)
        if any("::" in arg for arg in cmd if not arg.startswith("-")):
            # Culprit confirmation - passes
            return (0, "1 passed", "")
        raise subprocess.TimeoutExpired(cmd, timeout=12)

    # Mock discover_pytest_units to return known nodeids for escalation
    original_discover = file_runner_mod.discover_pytest_units

    def fake_discover(
        targets: list[str], default_root: Any, **kwargs: Any
    ) -> list[str]:
        if kwargs.get("granularity") == "test":
            return [f"test_a.py::test_{i}" for i in range(1, 20)]
        return original_discover(targets, default_root, **kwargs)

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(file_runner_mod, "discover_pytest_units", fake_discover)

    exit_code = run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
    )

    saved = load_run_state(state_file)
    assert saved is not None
    assert exit_code == 1
    # File should be escalated
    assert any(r.status == "escalated" for r in saved.results)
    # Escalated units should NOT include already-completed tests
    escalated = [u for u in saved.units if "::" in u]
    # Completed tests should be excluded from escalation
    assert len(escalated) < 19  # fewer than total because some were deselected
```

- [ ] **Step 7: Run test to verify it passes**

Run: `uv run pytest tests/test_file_runner.py::test_run_isolated_timeout_safety_cap_escalates_remaining -v`
Expected: PASS

- [ ] **Step 8: Write test for no policy promotion on timeout**

Add to `tests/test_file_runner.py`:

```python
def test_run_isolated_timeout_does_not_promote_to_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Timeout should NOT add files to isolation policy (only crashes should)."""
    units = ["test_a.py"]
    pytest_args = ["--p11-module", "/tmp/module.so"]
    state_file = tmp_path / "state.json"
    policy_file = tmp_path / "policy.json"
    policy_file.write_text("{}")

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text("")
                break
        raise subprocess.TimeoutExpired(cmd, timeout=12)

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)

    run_isolated_pytest_units(
        units,
        pytest_args,
        timeout=12,
        state_file=state_file,
        policy_file=policy_file,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    policy = load_isolation_policy(policy_file)
    # Policy should be empty — timeout does not promote
    for backend_policy in policy.values():
        assert "test_a.py" not in backend_policy.promoted_files
```

- [ ] **Step 9: Run all new tests**

Run: `uv run pytest tests/test_file_runner.py -k "timeout_progressive_retry or timeout_safety_cap or timeout_does_not_promote" -v`
Expected: All PASS

- [ ] **Step 10: Run full test suite**

Run: `uv run pytest tests/test_file_runner.py -x -q`
Expected: All tests pass

- [ ] **Step 11: Run mypy**

Run: `uv run mypy --strict src/pkcs11_check/core/file_runner.py`
Expected: No errors

- [ ] **Step 12: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py tests/test_file_runner.py
git commit -m "feat: progressive timeout retry instead of full escalation

When a file-level test unit times out in auto isolation mode, the
runner now retries the file with completed tests deselected instead
of escalating all tests to per-test isolation. This dramatically
reduces overhead for large test files that slightly exceed timeouts.

The culprit test (running when timeout hit) is confirmed individually
before deselecting. After 3 consecutive timeout retries, falls back
to escalation of only remaining untested nodeids.

Timeout no longer promotes files to the isolation policy (only crashes do)."
```

---

## Task 3: Fix AES-XTS test vector loader (TypeError bug)

**Files:**
- Modify: `src/pkcs11_check/testcases/acvp/aes/test_xts.py:36-47`
- No test file needed — the fix enables 1,200 existing test vectors to run

The bug: `_load_xts_vectors()` maps `"tweak": "tweakValue"` which loads the tweak as a raw hex string. The auto-hex-conversion in `_load_vectors()` only converts well-known keys (`key`, `iv`, `pt`, `ct`, `aad`, `nonce`). When `mech_bytes(CKM_AES_XTS, vec["tweak"])` is called, it fails with `TypeError: string argument without an encoding` because `bytes(hex_string)` requires an encoding parameter.

- [ ] **Step 1: Fix the tweak field mapping**

In `src/pkcs11_check/testcases/acvp/aes/test_xts.py`, change line 39:

From:
```python
        "tweak": "tweakValue",
```

To:
```python
        "tweak": ("tweakValue", lambda x: bytes.fromhex(x) if x else b""),
```

And change line 45:

From:
```python
        "tweak": "tweakValue",
```

To:
```python
        "tweak": ("tweakValue", lambda x: bytes.fromhex(x) if x else b""),
```

- [ ] **Step 2: Run ruff check**

Run: `uv run ruff check src/pkcs11_check/testcases/acvp/aes/test_xts.py`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/aes/test_xts.py
git commit -m "fix: AES-XTS test vector tweak field needs hex→bytes conversion

The tweak field was mapped as a plain string ('tweakValue') without
a lambda converter, so it arrived as a hex string instead of bytes.
mech_bytes() then failed with TypeError. Other fields (pt, ct, key)
used lambda converters correctly. This caused 1,200 test failures
on OpenCryptoki (the only provider that supports XTS)."
```

---

## Task 4: Investigate cross-provider failures (14 files)

These are read-only investigation tasks to classify each failure. Each subagent reads the test code and error messages from artifacts, then reports back with a classification.

**Output:** For each file, a classification: `fix` (test bug), `leave` (module bug), or `soften` (too strict).

**Execution:** Run as parallel Sonnet subagents, grouped into 3-4 batches. Each agent writes findings to `docs/superpowers/plans/2026-04-07-investigation-results.md`.

### Batch 1: High-impact cross-provider files (Sonnet agents)

- [ ] **Step 1: Investigate `acvp/test_acvp_ecdh.py` (100F on all 4)**

Read `src/pkcs11_check/testcases/acvp/test_acvp_ecdh.py`. Check what ECDH parameters are sent. Then grep `report.jsonl` for actual error messages from 2+ providers. If each provider gives a different CKR, this is correct (each module has its own ECDH bug). If all give the same CKR or assertion error, it may be a test bug.

Artifacts to check:
- `grep "test_acvp_ecdh" artifacts/kryoptic-main/report.jsonl | head -5`
- `grep "test_acvp_ecdh" artifacts/softhsm2-main/report.jsonl | head -5`

- [ ] **Step 2: Investigate `wycheproof/test_wycheproof_aes.py` (77-123F on 3/4)**

Read the test. Check if AES mode parameters (IV size, padding) match PKCS#11 spec requirements. Failures on 3 providers with different counts suggest module-specific handling.

- [ ] **Step 3: Investigate `test_mech_sign.py` (6-66F on 3/4)**

Read the test. 66 failures on kryoptic but only 6 on opencryptoki — likely different mechanisms failing. Check which specific mechanisms fail on each.

- [ ] **Step 4: Investigate `test_mech_multipart.py` (7-31F on 4/4)**

Read the test. 31 on NSS vs 7-10 on others — NSS-specific multipart issues?

### Batch 2: Medium-impact files (Sonnet agents)

- [ ] **Step 5: Investigate `test_mech_attribute.py` (4-47F on 3/4)**

47 on NSS vs 4 on others. Likely NSS-specific attribute reporting quirks.

- [ ] **Step 6: Investigate `test_mech_keygen.py` (2-34F on 3/4)**

34 on NSS vs 2-3 on others. Check NSS key generation parameter handling.

- [ ] **Step 7: Investigate `acvp/test_acvp_eddsa.py` (4-15F on 4/4)**

EdDSA implementation variance across modules. Check if test expects specific EdDSA behavior that varies.

- [ ] **Step 8: Investigate `wycheproof/test_wycheproof.py` (3-9F on 3/4)**

Quick check — small counts.

### Batch 3: Low-impact files (Sonnet agents)

- [ ] **Step 9: Investigate `test_mech_encrypt.py` (3-6F), `test_mech_wrap.py` (2-5F), `security/test_arithmetic_overflow.py` (3-8F)**

Quick check — small counts. Security tests should stay strict.

- [ ] **Step 10: Investigate `test_mech_derive.py` (1-2F), `test_mech_lifecycle.py` (1F), `test_interop_openssl.py` (1F)**

Quick check — 1-2 failures. Very likely module-specific quirks.

- [ ] **Step 11: Consolidate investigation results**

Write findings to `docs/superpowers/plans/2026-04-07-investigation-results.md` with a table:

```markdown
| File | Classification | Reason | Action |
|------|---------------|--------|--------|
| test_acvp_ecdh.py | leave | Different CKR per provider | None |
| ... | ... | ... | ... |
```

- [ ] **Step 12: Commit investigation results**

```bash
git add docs/superpowers/plans/2026-04-07-investigation-results.md
git commit -m "docs: investigation results for cross-provider test failures"
```

---

## Task 5: Investigate module-specific suspect cases (3 files)

- [ ] **Step 1: Investigate `wycheproof/test_wycheproof_rsa_pss.py` (435F on ock+softhsm2)**

Same failure count on 2 providers is suspicious. Read the test code and check if PSS parameters (salt length, MGF hash) are encoded correctly per PKCS#11 spec. Check `CK_RSA_PKCS_PSS_PARAMS` struct packing.

- [ ] **Step 2: Investigate `wycheproof/test_wycheproof_rsa_oaep.py` (668F on softhsm2)**

Large count on single provider. Check OAEP parameter encoding — `CK_RSA_PKCS_OAEP_PARAMS` struct. Check if the test correctly maps Wycheproof's mgf/hash parameters to PKCS#11 mechanism types.

- [ ] **Step 3: Investigate `acvp/aes/test_cts.py` (405+399F on kryoptic+nss)**

Check the CTS variant detection logic. NSS implements CS3, kryoptic implements CS1. The test should correctly detect and run the right variant. Check if vector selection matches the detected variant.

- [ ] **Step 4: Record findings and apply fixes if warranted**

For each file classified as `fix`, implement the fix. For `leave`, document the module bug. Commit results.

---

## Task 6: Audit xfails in `acvp/test_acvp_ecdsa.py`

- [ ] **Step 1: Read the xfail markers**

Read `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py` and find all `pytest.mark.xfail` or `pytest.xfail` calls. There should be 30 that are consistent across all 4 providers.

- [ ] **Step 2: Verify each xfail has evidence and spec reference**

Per CLAUDE.md philosophy: xfails must have evidence and spec refs. Check each one:
- Does it cite a specific PKCS#11 spec section?
- Does it reference a module issue tracker?
- Is the xfail reason clear and specific?

- [ ] **Step 3: Fix or improve any lacking xfails**

If any xfail is missing evidence: either add the evidence or convert to a regular assertion failure if the behavior is actually spec-compliant.

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py
git commit -m "audit: verify xfail evidence in ACVP ECDSA tests"
```

---

## Task 7: Final verification

- [ ] **Step 1: Run full meta-test suite**

Run: `uv run pytest tests/ -x -q`
Expected: All pass

- [ ] **Step 2: Run mypy on changed files**

Run: `uv run mypy --strict src/pkcs11_check/core/file_runner.py src/pkcs11_check/testcases/acvp/aes/test_xts.py`
Expected: No errors

- [ ] **Step 3: Run ruff on changed files**

Run: `uv run ruff check src/pkcs11_check/core/file_runner.py src/pkcs11_check/testcases/acvp/aes/test_xts.py`
Expected: No errors

- [ ] **Step 4: Commit any remaining fixes**
