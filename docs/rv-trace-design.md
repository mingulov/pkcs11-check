# Per-test CK_RV trace in reports — design

**Date:** 2026-05-30
**Topic:** Capture the exact `CK_RV` returned by every `C_*` call at the raw
ctypes choke point (`pkcs11_check.raw`) and attach it per test, via pytest
`record_property`, so it rides in `report.jsonl`'s `user_properties` and survives
the pooled shard merge verbatim. Gated off by default; secret-safe by
construction.

## Context

The suite already funnels every `C_*` call through a single choke point:
`RawPKCS11._call(name, *args)` at `raw/api.py:302–314`. It increments
`self._call_log[name]`, extracts the mechanism id for mechanism-bearing
functions (`args[1]._obj.mechanism`), and the **raw integer RV is right there**
at `int(func(*args))` — *before* `_to_ckr()`, which is naming only, not
interpretation. So the value the module actually returned is observable at one
place, before any test-level "accept any of these codes" logic.

The report pipeline preserves arbitrary `user_properties` for free:
pytest `_report_to_json` copies the field untouched (`_pytest/reports.py:597`),
reportlog `json.dumps` it (`pytest_reportlog/plugin.py:71–77`), and the pooled
shard merge is a byte-for-byte `shutil.copyfileobj` (`core/merge.py:48–73`). A
native list-of-dicts of primitives serializes to clean nested JSON; a
non-serializable value would be `str()`-ed rather than crash, but every field
here is `int`/`str`/`null`, so it is safe. `user_properties` is currently always
`[]`, so nothing competes.

The per-test bookkeeping seam also already exists: `call_log`,
`used_mechanisms`, and `mechanism_counts` are instance attributes on the
session-scoped `RawPKCS11`, reset per test in the three session fixtures
(`fixtures.py:99, 238, 392`, at the `reset_call_log()` sites — *after* bootstrap
and `C_Login`) and drained at `pytest_runtest_teardown` (`plugin.py:542–584`).
The RV trace is a fourth sibling of that family.

## Goals

1. Record, per test, the ordered list of every `C_*` call's exact raw `CK_RV`,
   keyed to function name and (where applicable) mechanism type, in
   `report.jsonl`'s `user_properties`.
2. Off by default. When off, `report.jsonl` is byte-identical to today.
3. Enable by CLI option or env var.
4. Never record secret material (PINs, key bytes, plaintext, `CKA_VALUE`).
   Add a meta-test that asserts no leak.
5. *(Deferred, optional phase)* best-effort output **byte-length** per
   output-producing call (length only, never the bytes). Pre-designed below;
   lands after the core is proven, and can be dropped without touching core.

## Non-goals

- **No diffing / regression-comparison tooling.** The consumer of this data
  performs the diff. We only produce the trace and prove (in a meta-test) that a
  single RV change is localized to the exact `(i, fn, mech)` entry.
- **No transparent-shim acceptance.** That criterion belonged to the consumer
  target, not this feature.
- **No change to any test's outcome.** The trace is observational. It never
  influences pass/xfail/fail/skip, and the classification model is untouched.
- **No new secret surface.** We capture only function names, mechanism ids, and
  RVs (plus, in the deferred phase, output byte-lengths) — nothing that can carry
  key/plaintext material.

## The contract (both sides agree)

- Property name: `pkcs11_rv_trace`.
- Value (v1 core): a JSON list of entries, each:
  ```json
  {"i": <abs int>, "fn": "C_DeriveKey", "mech": <u32|null>,
   "rv": <int>, "rv_name": "CKR_..."}
  ```
  The optional `"out_len": <int>` field is added **only** by the deferred
  out_len phase; v1 core never emits it. Consumers must treat it as optional.
  - `i` — **absolute** call index within the test (0-based). Absolute, not
    list-position, so that compact mode (below) can elide a prefix and the
    consumer still knows where each tail entry sits in the full sequence.
  - `fn` — the `C_*` function name (string, from the choke-point closure).
  - `mech` — mechanism type as an unsigned int for mechanism-bearing functions,
    else `null`. (`CK_MECHANISM_TYPE` is `CK_ULONG`, u32 in practice; the
    contract's `<u64|null>` is a superset and remains valid.)
  - `rv` — the raw integer `CK_RV` the module returned, before `_to_ckr` and
    before any test-level interpretation.
  - `rv_name` — `str(_to_ckr(rv))`: `"CKR_OK"`, `"CKR_MECHANISM_INVALID"`, or
    `"0x........"` for unknown codes.
  - `out_len` *(deferred phase only)* — present when an output byte-length was
    cheaply and unambiguously readable for an output-producing call; absent
    otherwise.
- Sidecar (compact mode only): property `pkcs11_rv_trace_dropped` = integer
  count of elided leading entries, so truncation is never silent.

## Design

Small seams, each following an existing pattern. §1/§3/§4 are v1; §2 (out_len)
is the deferred phase.

### 1. Capture — `raw/api.py`

Add to `RawPKCS11.__init__` a `_rv_trace: deque | None = None` (the gate) and a
`_rv_trace_total: int = 0` counter. Add methods mirroring the
`reset_call_log` family:

- `enable_rv_trace(self, *, maxlen: int | None = None) -> None` — sets
  `self._rv_trace = deque(maxlen=maxlen)` (unbounded list semantics when
  `maxlen is None`, ring buffer when set) and zeroes the counter.
- `reset_rv_trace(self) -> None` — clears the deque and counter (per test),
  preserving the configured `maxlen`. No-op when tracing is disabled.
- `rv_trace` property → `list(self._rv_trace)` (a copy), or `[]` when disabled.
- `rv_trace_dropped` property → `max(0, self._rv_trace_total - len(self._rv_trace))`.

In `_call`, hoist `mech_id: int | None = None` above the existing mechanism
block (assign it inside that block instead of a bare local). Compute the
return CKR **once** and reuse it (no double `func(*args)`, no double lookup):

```python
result = int(func(*args))
ckr = _to_ckr(result)
if self._rv_trace is not None:
    self._rv_trace.append(
        {"i": self._rv_trace_total, "fn": name, "mech": mech_id,
         "rv": result, "rv_name": str(ckr)}
    )
    self._rv_trace_total += 1
return ckr
```

When tracing is off, `self._rv_trace is None` → no entry, no allocation,
`user_properties` untouched. (The single new local `ckr` and the `is None`
branch do not change any observable output.) The deferred out_len phase inserts
one `_read_out_len(...)` call here behind the same `is None` guard.

### 2. Output length — `raw/api.py` *(DEFERRED — optional phase, not in v1 core)*

Pre-designed and verified low-risk, but split out so v1 core stays minimal and
the original contract is exact. Implement only when greenlit.

**Verified:** every output-producing `C_*` routes through
`recipes._two_call_output`, which passes the length as
`byref(CK_ULONG(...))` and **always as the last positional argument**. So the
length is `args[-1]._obj.value` universally — no per-function index table.

Gate by a **function-name set**, not by reading blindly:

```python
_OUTPUT_LEN_FUNCS: frozenset[str] = frozenset({
    "C_Encrypt", "C_Decrypt", "C_Sign", "C_Digest",
    "C_EncryptUpdate", "C_DecryptUpdate",
    "C_EncryptFinal", "C_DecryptFinal", "C_SignFinal", "C_DigestFinal",
    "C_SignRecover", "C_VerifyRecover", "C_WrapKey",
    # plus any other _two_call_output caller (authoritative set derived
    # during implementation; kept honest by the drift-guard meta-test)
})
```

The set is **essential**: `C_DeriveKey`, `C_UnwrapKey`, and
`C_GenerateKeyPair` also have a `byref(handle)` last arg — reading it would
mislabel a **key handle** as a length. Gating by name prevents that.

```python
def _read_out_len(name: str, args: tuple, rv: int) -> int | None:
    if name not in _OUTPUT_LEN_FUNCS or rv not in _OUT_LEN_OK_RVS:
        return None
    try:
        return int(args[-1]._obj.value)
    except (AttributeError, TypeError, IndexError):
        return None
```

`_OUT_LEN_OK_RVS = (CKR_OK, CKR_BUFFER_TOO_SMALL)` — both set a real length;
other errors leave the `CK_ULONG` stale, so we skip them. The value is a
**byte count**, never a buffer.

This phase inserts, inside the `if self._rv_trace is not None:` block of `_call`:
```python
out = _read_out_len(name, args, result)
if out is not None:
    entry["out_len"] = out      # (entry built as a local first in this phase)
```
and ships a **drift-guard meta-test** asserting every `_two_call_output` caller
name (grepped from `recipes.py`) is in `_OUTPUT_LEN_FUNCS`, so a future
output-producing function cannot silently miss `out_len`.

### 3. Lifecycle / gating — `fixtures.py`, `plugin.py`, `cli/test_cmd.py`

- **Option + env (dual, mirrors `--report-log` / `PKCS11_CHECK_REPORT_LOG`):**
  - `pytest_addoption`: `--p11-rv-trace` (store_true) and
    `--p11-rv-trace-compact` (`type=int, default=None` — an explicit window size
    `N`; **no** `nargs="?"`, which would let argparse swallow a following test
    path as the int and crash). Enabling compact implies tracing.
  - `test_cmd.py` typer flag `--rv-trace` (and `--rv-trace-compact N`) sets the
    pytest option (always emitting `--p11-rv-trace-compact=N` with the `=` form)
    **and** exports `PKCS11_CHECK_RV_TRACE=1`
    (`PKCS11_CHECK_RV_TRACE_COMPACT=N`) — with a `try/finally` `os.environ.pop`
    cleanup, exactly mirroring the `PKCS11_CHECK_REPORT_LOG` path — so it
    propagates into isolated/subprocess runs (children inherit `os.environ`).
  - `p11_config` fixture resolves `rv_trace_compact: int | None` and
    `rv_trace: bool` from *either* the options or the env vars, and **compact
    implies enabled**: `rv_trace = opt_rv_trace or (rv_trace_compact is not
    None) or env_rv_trace`. Stores both on `P11TestConfig` (pydantic
    `BaseSettings`; two new fields `rv_trace: bool = False`,
    `rv_trace_compact: int | None = None`).
- **Per-test reset:** at each `reset_call_log()` site in the three session
  fixtures (`fixtures.py:99, 238, 392`), when `p11_config.rv_trace` is on, call
  `raw.enable_rv_trace(maxlen=p11_config.rv_trace_compact)` each test (enable
  doubles as reset — fresh `deque`, zeroed counter). Because this runs *after*
  bootstrap/login, the PIN-bearing `C_Login` and session-open calls are excluded
  from the test-body trace.
- **Drain:** an **independent block at the top of `pytest_runtest_teardown`**
  (after the `_is_testcase_item` check), *not* nested under the coverage
  early-return (`plugin.py:531–534` returns on a missing `_CUMULATIVE_FUNCTIONS`
  stash; rv-trace must not be coupled to that). It scans `item.funcargs` for the
  first of `("p11_raw_session", "p11_session", "p11_module_session")` that has a
  `.raw`, and when `raw._rv_trace is not None`:
  ```python
  item.user_properties.append(("pkcs11_rv_trace", raw.rv_trace))
  if raw.rv_trace_dropped:
      item.user_properties.append(("pkcs11_rv_trace_dropped", raw.rv_trace_dropped))
  ```
  **Verified** (grep): no `pytest_runtest_makereport` hookwrapper and no other
  `user_properties` writer exists, so the append flows straight to reportlog.
  The value lands on the **teardown** `TestReport` record — that is when the hook
  runs, and pytest builds the teardown report from `item.user_properties` *after*
  all `pytest_runtest_teardown` hooks complete (`runner.call_and_report`). The
  setup/call records keep `user_properties == []`. Consumers read the trace from
  the teardown record.

The raw layer never reads env/config — its gate is purely `_rv_trace is not
None`, set by the fixture. The choke point stays clean.

### 4. Compact mode (own phase, after core lands)

`enable_rv_trace(maxlen=N)` already gives the ring buffer; absolute `i` is the
counter, not the list position. So compact mode is a `deque(maxlen=N)` swap
behind the same drain seam plus the `pkcs11_rv_trace_dropped` sidecar — no
choke-point change. Default N when compact requested: 512. Full mode (unbounded)
remains the default when tracing is merely on.

Rationale (per design dialogue): the tail of the trace — the calls right before
the test ends or crashes — is the high-value part, and a ring buffer bounds size
without losing it. Total/dropped counts make truncation explicit.

## Testing (meta-tests, `tests/`)

All in-process. Tests exercise the **real** `RawPKCS11._call` with stub
`_funcs`. Because `__init__` requires a real module, build the instance via a
small test helper: `raw = object.__new__(RawPKCS11)` then set the exact attrs
`_call` touches — `_funcs` (`{"C_Sign": lambda *a: 0, …}`), `_call_log`
(`defaultdict(int)`), `_used_mechanisms` (`set()`), `_mechanism_counts`
(`Counter()`), `_lib = None`, `_rv_trace`, `_rv_trace_total`. (House style
already uses lambda stubs / `_FakeRaw`; this drives the genuine choke point.)

**v1 core:**

1. **Zero-distortion at the choke point.** Drive a fixed call sequence with
   tracing on; assert `rv_trace` equals the exact expected
   `[{i, fn, mech, rv, rv_name}, …]`, including `mech` (pass a real
   `CK_MECHANISM`/`PackedMechanism.byref()` as `args[1]`) for a mechanism-bearing
   call and `null` otherwise, and `i` increasing 0,1,2,….
2. **Off ⇒ byte-identical.** With tracing off, after a call sequence,
   `rv_trace == []` and a simulated teardown adds nothing to `user_properties`.
3. **No-leak (secret-safety).** Run a sequence including `C_Login` with a
   sentinel PIN and a key/plaintext sentinel through stubbed funcs; `json.dumps`
   the trace; assert no sentinel byte pattern appears and every entry's keys are
   a subset of the **core whitelist** `{i, fn, mech, rv, rv_name}`.
4. **Pinpoint a deliberate RV change.** Capture two traces differing by one
   call's RV; assert the differing entry is uniquely identified by
   `(i, fn, mech)`. (No diff tool shipped; this only proves the data supports the
   consumer's pinpointing.)

**Compact phase:** with `maxlen=N` and `>N` calls, assert the trace holds the
last N with absolute `i`, and `rv_trace_dropped == total − N`.

**Deferred out_len phase:** for a stubbed `C_Sign`-shaped call whose last arg is
`byref(CK_ULONG(known))`, assert `out_len == known`; for a non-output function
(and for `C_DeriveKey`, whose last arg is a handle), assert `out_len` absent;
plus the **drift-guard** test (every `_two_call_output` caller ∈
`_OUTPUT_LEN_FUNCS`). The whitelist for this phase becomes
`{i, fn, mech, rv, rv_name, out_len}`.

## Phasing

1. **Core** — capture (`_call` + trace methods on `RawPKCS11`), gating
   (option + env + config), reset/drain (fixtures + teardown), and tests 1–4.
   Delivers all v1 acceptance below.
2. **Compact** — `deque(maxlen=N)` window + `pkcs11_rv_trace_dropped` sidecar +
   its test. Isolated behind the same drain seam.
3. **Deferred out_len** *(optional, greenlit after core)* — `_OUTPUT_LEN_FUNCS`,
   `_read_out_len`, the one-line insert in `_call`, drift-guard + length tests.

## Acceptance (v1 core)

- Flag on ⇒ each test's teardown `report.jsonl` record carries
  `["pkcs11_rv_trace", [...]]` with the core schema `{i, fn, mech, rv, rv_name}`.
- Flag off ⇒ `report.jsonl` byte-identical to today (`user_properties == []`).
- No-leak meta-test green; entry keys are core-whitelist-only.
- A single RV change is localized to the exact `(i, fn, mech)` entry.
- Pooled shard merge preserves the trace verbatim (byte-copy path, already true).

## File-change map (verified against current code)

| File | Change | Phase |
|---|---|---|
| `raw/api.py` | `__init__`: add `_rv_trace=None`, `_rv_trace_total=0`; `import deque`. Add `enable_rv_trace`/`reset_rv_trace`/`rv_trace`/`rv_trace_dropped`. In `_call`: hoist `mech_id`, capture `ckr` once, append entry when enabled. | Core |
| `config.py` | `P11TestConfig`: `rv_trace: bool = False`, `rv_trace_compact: int \| None = None`. | Core |
| `fixtures.py` | `p11_config`: read `--p11-rv-trace`/`--p11-rv-trace-compact` + env, compact-implies-enabled. Three reset sites (`:99,238,392`): `enable_rv_trace(maxlen=…)` when on. | Core |
| `plugin.py` | `pytest_addoption`: two options. `pytest_runtest_teardown`: independent top-of-hook drain (own funcarg scan, not under the coverage stash guard) appending `pkcs11_rv_trace` (+`_dropped`) to `item.user_properties`. | Core/Compact |
| `cli/test_cmd.py` | typer `--rv-trace`/`--rv-trace-compact`; `_build_pytest_args` append; `os.environ` export with `try/finally` cleanup. | Core |
| `tests/test_rv_trace.py` (new) | stub-`_call` meta-tests 1–4. | Core |
| `raw/api.py` + `tests/` | `_OUTPUT_LEN_FUNCS`, `_read_out_len`, one-line insert; drift-guard + length tests. | Deferred out_len |

## Deferred / "think later"

- **Further size streamlining beyond last-N.** Levers, none touching the choke
  point: drop redundant `rv_name` (derivable from `rv` + lookup), elide
  `CKR_OK` runs, RLE repeated `(fn, mech, rv)`. Isolate serialization so a future
  `PKCS11_CHECK_RV_TRACE_COMPACT`-style knob can swap schemas without re-touching
  `_call`. Decide once we see real trace sizes.
- **out_len for `C_GetAttributeValue` / template-shaped outputs.** Skipped in v1
  (template extraction is non-trivial and risks touching attribute values).
