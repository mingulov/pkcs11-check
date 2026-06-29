# Roadmap

A non-binding view of where pkcs11-check is heading, so users can see what is
planned or under consideration. Nothing here is a dated commitment; current
behavior is documented in the README and the rest of `docs/`.

## Planned / under consideration

- *Rate-limit-aware retry and backoff.* Some providers - notably cloud KMS
  bridges and network HSMs - throttle a client by returning an error (a busy,
  throttle, or device-error return code) instead of blocking. pkcs11-check
  should recognize such throttle responses and apply a bounded
  backoff-and-retry at the operation layer (much like the existing
  provider-restart recovery), so transient rate limiting does not surface as
  spurious findings. This will be opt-in / configurable, so strict runs can
  still treat every return code at face value.

- *Easier scoping-out of unsupported curves and mechanisms.* PKCS#11 has no
  per-curve or per-key-size capability flag, so the suite finds an unsupported
  EC curve only by trying it; a clean rejection is recorded as a
  `not_operational` deviation, and across a whole vector file one capability gap
  becomes thousands of `not_operational` xfails (see
  [interpreting-results.md](interpreting-results.md)). A simpler way to tell a
  run which curves / key sizes / mechanisms a module actually implements would
  let those families be skipped up front instead of attempted, cutting the
  noise. This is run scoping (what to exercise), supplied per run by the user -
  not a shipped per-provider allowlist - so result classification stays
  provider-neutral.

- *Windows / cross-platform support.* The PKCS#11 ctypes ABI now supports Windows
  (issue #3). The subprocess output reader no longer uses `select()` over pipes
  (POSIX-only); the cryptoki structures pack 1-byte on Windows via a
  platform-conditional `_CKStructure` base; the function-list version offset is
  computed from the packed layout instead of assuming pointer-size padding;
  `CK_ULONG` is 32-bit on Win64 (LLP64), handled by `ctypes.c_ulong` plus a
  width gate that skips the 64-bit oversized-length probes (unrepresentable in a
  32-bit `CK_ULONG`, gated on the type width not the OS name) rather than silently
  truncating them; the runner classifies Windows NTSTATUS crash codes; and a
  module's dependent DLLs resolve via `os.add_dll_directory`. Validated under Wine
  (a pywine + SoftHSM2-for-Windows target), which faithfully reproduces the Win64
  layout/width ABI. Remaining: a real-Windows pass (a VM, or CI `windows-latest`)
  for final conformance sign-off. Wine is an ABI reproducer, not a conformance gate.

- *SO (security officer) login flows.* CKU_SO workflows, including
  trusted-certificate import with `CKA_TRUSTED=True`, are not yet covered.

- *Wider interop simulators.* Provider-generated in-band IV profiles,
  proxy/loader mutable-parameter preservation checks, and broader
  mutable-output simulator targets.

- *Fuzzing / external fuzzer hooks.* Exposing the input-boundary probes to
  external fuzzers is under consideration.
