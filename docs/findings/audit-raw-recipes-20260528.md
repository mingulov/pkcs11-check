# Audit: raw layer + recipes + file_runner (2026-05-28)

> Observational only. No production code changes; fixes are a separate follow-up cycle.

**Scope:** `src/pkcs11_check/raw/{bootstrap,pack,pack_mechanisms,recipes,rv,types_std}.py`, `src/pkcs11_check/core/file_runner.py`.

**Method:** static read against `dev` HEAD. Cross-checks against `CLAUDE.md` rules, the
shipped Phase 1–6 classification model, and the L1/L2/M1/M3 fixes already committed
(commits c509013, 1f1e2e5, 33b5f0e, 718a429).

**Headline:** 0 CRITICAL · 0 HIGH · 3 MEDIUM · 2 LOW. The PKCS#11 layer is in good
shape — recently-fixed L2 (cancel-on-error) and M1 (PIN-embedding) covered the
high-volume risks. The MEDIUM findings are missed call-sites of the L2 pattern
plus one option-precedence wrinkle in `_two_call_output`. The LOW findings are
fringe correctness gaps unlikely to trigger in practice.

---

## Error-handling masking / cancel-on-error gaps

These extend the L2 fix (commit c509013) that added `_cancel_operation`
cleanup to the four single-shot recipes. Sibling sites still need it.

### M-RAW-1 — `_message_crypto` missing `_cancel_operation` after Init  ·  MEDIUM
- **Site:** `src/pkcs11_check/raw/recipes.py:1483-1516` (approx).
- **Evidence:** after `C_MessageEncryptInit` / `C_MessageDecryptInit` returns
  `CKR_OK`, the function proceeds to the size-query call and the actual call. If
  either fails, no cancel is issued — the next operation on the same session
  hits a spurious `CKR_OPERATION_ACTIVE`. Same shape as the bugs c509013 fixed in
  `encrypt_single`/`decrypt_single`/`sign_single`/`verify_single`.
- **Suggested fix:** wrap the body in `try` after the Init succeeds; on
  `BaseException`, call `_cancel_operation(...)` and re-raise. Mirror c509013's
  pattern.
- **Confidence:** 90%.

### M-RAW-2 — `_multipart_output` missing cancel-on-error after Init  ·  MEDIUM
- **Site:** `src/pkcs11_check/raw/recipes.py:1215-1237` (approx).
- **Evidence:** the `init_fn → Update loop → Final` pattern lacks cancel on
  Update- or Final-error. Less severe than the single-shot case (multi-part
  sessions are often disposable), but creates the same "spurious
  CKR_OPERATION_ACTIVE on next op" hazard for callers that reuse the session.
- **Suggested fix:** same try/except `_cancel_operation` wrapper.
- **Confidence:** 85%.

### L-RAW-3 — Sibling single-shot helpers without cancel-on-error  ·  LOW
- **Sites:** `sign_recover_single`, `verify_recover_single`, `sign_multipart`,
  `digest_single_with_key` (search `recipes.py`).
- **Evidence:** the L2 fix landed on the four most-used recipes; these
  less-common ops have the same shape but weren't updated.
- **Suggested fix:** apply the same cancel-on-error pattern.
- **Confidence:** 80%.

---

## Recipe convention / option precedence

### M-RAW-4 — `_two_call_output`: `retry_on_buffer_too_small` silently ignored in `output_size_hint` mode  ·  MEDIUM
- **Site:** `src/pkcs11_check/raw/recipes.py:187-195` (approx).
- **Evidence:** when `output_size_hint > 0`, the function does a single call and
  returns. `retry_on_buffer_too_small` is not checked in this branch. The
  docstring claims the two flags "combine cleanly" in `decrypt_single` — but
  they don't combine at all: the retry never fires in single-call mode. Callers
  who set both flags expecting the retry as a safety net silently get only the
  size-hint behavior.
- **Suggested fix:** either (a) honor `retry_on_buffer_too_small` even in
  size-hint mode (retry the single call with a doubled buffer on
  `CKR_BUFFER_TOO_SMALL`), or (b) reject the combination at the call site with
  `ValueError("retry_on_buffer_too_small incompatible with output_size_hint")`.
  Option (a) is more useful; (b) is safer.
- **Confidence:** 95%.

### L-RAW-5 — `encapsulate_key` zero-size second-call buffer  ·  LOW
- **Site:** `src/pkcs11_check/raw/recipes.py:~1616`.
- **Evidence:** on the "Kryoptic returns CKR_OK on first call" branch, if a
  misbehaving module returns `CKR_OK` without setting `ct_len`, the second call
  receives a zero-length ciphertext buffer. Conformant Kryoptic does set
  `ct_len`, so this is degenerate in practice; still worth a guard.
- **Suggested fix:** assert `ct_len.value > 0` between calls; raise a clear
  error message if violated.
- **Confidence:** 75%.

---

## Out of scope / noted not-issues

Patterns that look suspicious on first read but are intentional or safe:

- **`child_setup_reject_known`** (`testcases/security/conftest.py`): uses
  `is_known_error` with exact `.rv` matching first; no substring hazard after
  the M3 fix (commit 33b5f0e).
- **`_subprocess.py` (ckr/)**: does not embed PIN literals in child boilerplate;
  the M1 fix (commit 1f1e2e5) covered the security/conftest sibling and was
  unnecessary here.
- **`PackedMechanism` keepalive chains** (`pack_mechanisms.py`): all variants
  correctly call `add_buffer` / `_keepalive` to keep ctypes buffers alive past
  the packer scope.
- **`_alloc_writable_pointer`**: stores buffers in `result._keepalive` via
  `add_buffer` — safe.
- **`mech_gcm_message_generated_iv` / `mech_ccm_message_generated_nonce`**: do
  not pass `keepalive` to `_mech_struct`, but the buffers ARE added via
  `add_buffer` afterward — kept alive.
- **`_two_call_output` size 0 from NULL probe**: returns `b""`, which is correct
  for zero-output ops (e.g. sign with no output). A mis-reporting module's
  non-zero-then-zero would fail downstream as a value mismatch (the finding is
  visible, if misleadingly placed).
- **`login_user` (`bootstrap.py`)**: correctly rejects `str` PIN and enforces
  bytes-like — consistent with CLAUDE.md PIN rules.
- **`encapsulate_key` handle reconciliation**
  (`final_handle = key_handle.value if key_handle.value else first_call_handle`):
  correct for both Kryoptic-CKR_OK and standard-CKR_BUFFER_TOO_SMALL paths.

---

## Suggested follow-up

A single small "L2-extension" change (M-RAW-1 + M-RAW-2 + L-RAW-3 covered
together) would close the cancel-on-error pattern across all PKCS#11 recipe
sites — one commit, three new sibling guards mirroring c509013, plus regression
meta-tests at the call sites. M-RAW-4 is a separate small change with its own
trade-off (honor vs reject). L-RAW-5 is a one-line guard if/when an offending
module is observed.

Nothing here is urgent. None of these introduces a security regression; they
are correctness / hygiene gaps in the same shape as fixes already landed.
