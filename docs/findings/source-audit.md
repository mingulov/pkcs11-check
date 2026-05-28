# pkcs11-check Source Audit (review only, no fixes)

Date: 2026-05-28
Scope: pkcs11-check's OWN source (`src/pkcs11_check/`), not provider behavior.
Goal: find harness/binding bugs and risks **other than** the provider findings
already catalogued in `docs/findings/` (PC-/PV-/CR-/EX- classes).
**No source was modified.** This is a review-only document.

Reviewed areas:
- `raw/` ctypes binding: `api.py`, `recipes.py`, `pack.py`, `pack_mechanisms.py`,
  `der.py`, `ec.py`, `rv.py`, `bootstrap.py`, `loader.py`.
- `core/file_runner.py` (subprocess isolation / returncode / resume / timeout).
- `testcases/conftest.py`, `testcases/ckr/_ckr_spec.py` (classification helpers).
- `testcases/_subprocess_preamble.py`, `testcases/security/conftest.py`,
  `testcases/_subprocess_result.py` (child-script generation).
- Cross-cutting: bare excepts, `shell=True`, temp files, PIN leakage, resource leaks.

Tooling: `uv run ruff check src/` → **all checks passed**;
`uv run --extra dev mypy src/` → **Success, no issues in 341 files**.

## Summary of findings

| Severity | Count |
|---|--:|
| HIGH | 0 |
| MED  | 4 |
| LOW  | 6 |

No new HIGH-severity harness bugs (no PC-1-class ctypes lifetime/pointer hazards,
no `shell=True`, no `eval`/`exec`, no hardcoded temp paths). The ctypes packing
layer (`pack.py` / `pack_mechanisms.py`) consistently uses `ctypes.cast(...)`
plus an explicit keepalive list (`ka` / `add_buffer`) for every pointer field,
so the PC-1 hazard class does **not** recur in the binding itself. The remaining
items are MED/LOW risks: a couple can soften or mis-route a finding (CONFIRMED
design tensions), the rest are robustness/escaping/leak concerns (mostly
SUSPECTED, surface as Python errors rather than silently hiding module bugs).

---

## MED

### M1 — PIN embedded verbatim into generated subprocess script (CONFIRMED)
- **Location:** `src/pkcs11_check/testcases/_subprocess_preamble.py:99`
  (`login_line = f'login_user(raw, sh, CKU_USER, b"{pin}")\n'`); also slot label
  interpolation at lines 86–93.
- **What:** The user PIN is string-interpolated directly into the Python source
  passed to `subprocess.run([sys.executable, "-c", script])`. The PIN therefore
  appears in plaintext in the child process argv (visible via `ps`/`/proc`), and
  in the `script` string that could be printed in a pytest failure/traceback.
- **Why it's a risk:** Violates the project rule "PIN values are never logged,
  printed, or included in error messages." Also an injection/escaping bug: a PIN
  (or slot label) containing `"`, `\`, or a newline breaks the generated source
  or could inject code. Most CI PINs are trivial, but the contract is explicit.
- **Suggested direction:** Pass the PIN to the child via an env var
  (like `P11TEST_PIN`, already redacted in `file_runner`) or stdin, and read it
  in the preamble from `os.environ`, instead of interpolating into source. Escape
  `slot_label` with `repr()`/`json.dumps()` rather than raw `f"...{label}..."`.

### M2 — `assert_ckr` / `full_compat` can never *fail* on a generic-but-wrong CKR (CONFIRMED, design tension)
- **Location:** `src/pkcs11_check/testcases/ckr/_ckr_spec.py:123` (`_UNIVERSAL`
  includes `CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_FUNCTION_FAILED`),
  `:133` (`_TOKEN_UNIVERSAL` includes `CKR_DEVICE_ERROR`), `:136 full_compat`,
  `:248–260 assert_ckr` compat branch.
- **What:** `full_compat()` unconditionally appends the universal CKR set
  (incl. `CKR_FUNCTION_FAILED`, `CKR_GENERAL_ERROR`, `CKR_DEVICE_ERROR`) to every
  negative-CKR expectation. Any module that returns one of those generic codes
  for a *specific* negative condition is routed to **xfail** (a "noted deviation"),
  never to **fail**.
- **Why it's a risk:** This softens what could be a real WRONG_CKR finding into a
  silent xfail. Per spec §5.1.1–5.1.3 those codes are universally permitted, so
  this is defensible by design — but it means `assert_ckr` structurally cannot
  detect "module returns CKR_FUNCTION_FAILED instead of the precise reason code,"
  which is itself a quality signal worth tracking. Confirmed behavior, not a bug;
  flagged so the classification model owners can decide whether generic-reject
  deviations deserve their own bucket rather than the same xfail as a precise
  non-spec reject.
- **Suggested direction:** Consider distinguishing "rejected with a precise but
  non-preferred code" (xfail) from "rejected with a generic catch-all code"
  (separate xfail reason / counter), so generic-reject prevalence is visible in
  reports without changing pass/fail semantics.

### M3 — substring CKR matching fallback can match the EXPECTED code, not the ACTUAL one (SUSPECTED)
- **Location:** `src/pkcs11_check/testcases/conftest.py:369–370` (`is_known_error`
  fallback) and `:378–382` (`_matched_ckr_name` fallback).
- **What:** When a caught exception has no `.rv` attribute, both helpers fall back
  to substring-matching CKR names against `str(exc)`. The `CkrAssertionError`
  message format is `"Unexpected CK_RV <ACTUAL>; expected one of: <NAME1>, <NAME2>…"`
  (see `raw/rv.py:38–42`), i.e. it contains BOTH the actual and all expected CKR
  names. A substring match can therefore match an *expected* name even when the
  *actual* return differs — wrongly classifying a genuine failure as a "known"
  CKR and routing it to `pytest.skip`/`pytest.xfail`, hiding a finding.
- **Why it's a risk:** This is exactly the prefix/substring hazard the
  `CkrAssertionError` docstring (`raw/rv.py:16–19`) warns about. In practice
  `expect_rv` always sets `.rv`, so the buggy fallback is mostly dead — but it
  is reachable for any plain `AssertionError` raised outside `expect_rv`, and is
  a latent way to mis-route a fail → skip/xfail.
- **Suggested direction:** Drop the substring fallback entirely (require `.rv`),
  or constrain matching to the portion of the message before `"; expected one of:"`.

### M4 — `_two_call_output` second call with a NULL-reported size of 0 (SUSPECTED)
- **Location:** `src/pkcs11_check/raw/recipes.py:170–185` (`_two_call_output`),
  also the `read_attributes` size path `:921–929`.
- **What:** On the standard two-call path, if the size-query call returns
  `CKR_OK` with `out_len.value == 0`, a zero-length `out_buf` is allocated and the
  function returns `b""`. For operations that genuinely produce no output that is
  fine, but if a module under-reports 0 on the NULL probe (and does not set
  `CKR_BUFFER_TOO_SMALL` on the second call), the harness will return an empty
  result and a downstream equality/roundtrip assertion fails with a confusing
  message rather than surfacing the size-probe quirk directly.
- **Why it's a risk:** Surfaces as a misleading test failure rather than a clear
  "module reported size 0" diagnostic. Does not hide the finding, but obscures
  the root cause. `retry_on_buffer_too_small` only triggers when the module
  returns `CKR_BUFFER_TOO_SMALL`, not for a silent 0.
- **Suggested direction:** When the NULL probe yields `CKR_OK` with size 0 for an
  operation expected to produce output, emit a `compliance.note()` /
  diagnostic, or treat 0 as a hint to fall back to a generous pre-allocated buffer.

---

## LOW

### L1 — `bytes(...).decode("utf-8")` on token labels / string attrs without `errors=` (SUSPECTED)
- **Location:** `src/pkcs11_check/raw/bootstrap.py:41` (token label filter);
  `src/pkcs11_check/raw/recipes.py:947` (`read_attributes` `str` vtype).
- **What:** Token labels (`bootstrap.get_slot_ids(label=...)`) and `str`-typed
  attributes are `decode("utf-8")`d with no error handling. A token returning a
  non-UTF-8 label or malformed string attribute raises `UnicodeDecodeError`,
  aborting slot discovery / attribute read.
- **Why it's a risk:** Aborts the operation with a Python traceback instead of
  reporting the malformed value (which is itself a provider quirk). Labels are
  fixed-width space-padded byte arrays, not guaranteed valid UTF-8.
- **Suggested direction:** Use `decode("utf-8", errors="replace")` (or return raw
  bytes) for label filtering and for `read_attributes` string decoding.

### L2 — operation-state leak on mid-operation error in single-shot recipes (SUSPECTED)
- **Location:** `src/pkcs11_check/raw/recipes.py` — `encrypt_single:675`,
  `sign_single:707`, `decrypt_single:746`, `verify_single`, and `find_objects:997`
  (no `try/finally` around the `*Init` → terminal-call pair).
- **What:** If the terminal call (`_two_call_output` / `C_FindObjects`) raises
  after `C_EncryptInit`/`C_SignInit`/`C_FindObjectsInit` succeeded, the session is
  left with an active operation; no cancel/Final is issued.
- **Why it's a risk:** In tests that reuse a session across operations, a later
  op may return a spurious `CKR_OPERATION_ACTIVE`, mis-attributing a finding to
  the wrong call. Bounded in practice by per-test/subprocess session teardown.
- **Suggested direction:** Wrap the init→terminal pair in `try/finally` and issue
  the matching cancel (e.g. `C_FindObjectsFinal`, or a zero-length finalize) on
  error — only where the helper owns the operation lifecycle.

### L3 — `_run_subprocess_tee` does not reap the child on timeout (SUSPECTED)
- **Location:** `src/pkcs11_check/core/file_runner.py:1967–1994`.
- **What:** On timeout the loop calls `proc.kill()` then `raise
  subprocess.TimeoutExpired` from inside the `try`; the `finally` only closes the
  selector. `proc.wait()` is not called on this path, and the caller
  (`:2207`) catches `TimeoutExpired` without reaping.
- **Why it's a risk:** Potential transient zombie / undrained pipe until
  `Popen.__del__` runs. Minor; does not affect classification correctness.
- **Suggested direction:** Call `proc.wait()` (with a short grace timeout) before
  re-raising, or `proc.kill(); proc.communicate()` in the timeout branch.

### L4 — broad `except Exception` in interface/info enumeration (LOW, non-assertion paths)
- **Location:** `src/pkcs11_check/core/loader.py:229,242`;
  `src/pkcs11_check/compliance_report.py:377,386`;
  `src/pkcs11_check/core/preflight.py:62,77`;
  `src/pkcs11_check/core/file_runner.py:1378` (`# noqa: BLE001`).
- **What:** Broad catch-alls that fall back to defaults / `status="error"`.
- **Why it's a risk:** Per the project's "no bare except" rule these are broad,
  but all sit on **info/diagnostic/manifest** paths, not on test-assertion paths,
  so they degrade reporting rather than hide a module finding. Listing for
  completeness; they do not mask crashes/CKRs in the test suite.
- **Suggested direction:** Narrow to the expected ctypes/OSError/JSON exception
  types where practical; otherwise annotate why broad is acceptable here.

### L5 — `ecdsa_sig_der_to_p1363` raises `OverflowError` on oversized r/s (SUSPECTED)
- **Location:** `src/pkcs11_check/raw/der.py:122–124`
  (`r.to_bytes(key_size, "big")`).
- **What:** If a module returns a DER signature whose `r`/`s` exceed `key_size`
  bytes, `int.to_bytes` raises `OverflowError` rather than a domain-specific
  error.
- **Why it's a risk:** Surfaces as a raw `OverflowError` traceback instead of a
  clear "signature integer too large for curve" message. Does not hide the
  finding; just a less informative failure.
- **Suggested direction:** Catch/validate length and raise `ValueError` with
  context, or let the caller assert on signature length first.

### L6 — telemetry mechanism-counting reaches into ctypes private `_obj` (LOW)
- **Location:** `src/pkcs11_check/raw/api.py:304–310`
  (`args[1]._obj.mechanism`, guarded by `except (AttributeError, TypeError)`).
- **What:** Mechanism-usage telemetry inspects the private `_obj` attribute of a
  `byref` argument. If the call site passes the mechanism differently, counting
  silently no-ops.
- **Why it's a risk:** Telemetry-only; a silent miss undercounts coverage stats
  but does not affect test outcomes. The `except` is specific (not bare).
- **Suggested direction:** Acceptable as-is; if coverage accuracy matters,
  standardize how mechanisms are passed so `_obj` access is reliable.

---

## Areas reviewed and found sound (no finding)

- **ctypes pointer lifetime (PC-1 class):** `pack.py` `_pack_bytes`,
  `_alloc_writable_pointer`, `_fill_random_data`, the SSL3/TLS/WTLS key-mat
  packers, and `attr_template`/`TemplateArg` all use `ctypes.cast(...)` and keep
  every backing buffer alive via the `ka` list / `add_buffer` / `_keepalive` /
  stored `storage`. All pointer struct fields are declared `c_void_p`
  (`types_std.py`), so casts are type-correct. No raw-array-to-pointer-field
  assignment without keepalive was found in the binding.
- **`file_runner` returncode interpretation:** `_status_from_returncode`
  (signal→crashed, exit 5→empty, other non-zero→failed) and the timeout branch
  correctly surface crashes and timeouts; `_subprocess_result.assert_subprocess_completed`
  fails on both `rc<0` and `rc>0`. Crashes are never swallowed.
- **DER/ASN.1 (`der.py`):** length/integer/sequence decoders bounds-check every
  read and raise `ValueError` on truncation/trailing data; no buffer overrun.
- **EC OIDs (`ec.py`):** spot-checked OIDs (secp192r1, secp256r1, ed25519) correct.
- **`security/conftest.py` SETUP_XFAIL path:** only fires after a clean child exit
  and only on an explicit known-CKR match printed by the child; cannot hide a crash.
- **PIN redaction in `file_runner`:** `_REDACTED_ENV_KEYS` and `--p11-pin`
  redaction in arg snapshots/fingerprints are applied consistently (the only PIN
  plaintext exposure is M1, in the subprocess preamble).
- **No `shell=True`, no `os.system`, no `eval`/`exec`, no hardcoded `/tmp` paths;**
  all temp files use `tempfile.mkstemp`/`NamedTemporaryFile`/`TemporaryDirectory`.
- **`ruff` and `mypy --strict` both clean.**
