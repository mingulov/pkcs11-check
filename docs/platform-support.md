# Platform support

pkcs11-check is a pure-Python (ctypes) framework and runs on Linux, Windows, macOS,
and FreeBSD. This page records what is verified in CI versus expected-by-POSIX-family,
and the few places platform behavior differs.

## Support matrix

Legend: `CI` = exercised by a CI lane; `POSIX` = expected to work because the platform
is POSIX and shares Linux's code path (not CI-verified); `supported` = implemented and
unit-tested but not exercised end-to-end in CI; `degraded` = works, with a documented
weaker guarantee; `n/a` = not applicable.

| Capability                                   | Linux      | Windows            | macOS          | FreeBSD  |
|----------------------------------------------|------------|--------------------|----------------|----------|
| ctypes ABI (CK_ULONG size, struct packing)   | CI         | CI                 | CI             | POSIX    |
| Module load (`.so` / `.dll` / `.dylib`)      | CI (.so)   | CI (.dll)          | CI (.dylib)    | POSIX (.so) |
| Subprocess tee / crash survival              | CI         | CI                 | CI             | POSIX    |
| Crash detection (POSIX signal / NTSTATUS / ctypes SEH) | CI  | CI                 | CI             | POSIX    |
| mmap demand-zero security probes             | CI         | n/a (skips clean)  | POSIX          | POSIX    |
| SIGALRM teardown watchdog                    | CI         | n/a (subprocess deadline backstops) | POSIX | POSIX |
| External key provisioning (opt-in)           | CI         | supported          | POSIX          | POSIX    |
| Opt-in shell hooks (token mint)              | CI         | supported (`cmd /c`) | POSIX        | POSIX    |
| Disabled-tests / node-id matching            | CI         | supported (forward-slash normalized) | POSIX | POSIX |
| Private cache privacy                        | CI (0o700) | degraded (per-user `%LOCALAPPDATA%`, no ACL tightening) | CI (0o700) | POSIX (0o700) |
| Meta-test suite (`pytest tests/`)            | CI         | CI                 | CI             | not run  |
| Functional smoke (real provider)             | CI (SoftHSM2) | CI (SoftHSM2-for-Windows) | CI (Homebrew SoftHSM2) | not run |

## Notes

- Linux support is not x86-only: ABI width comes from `ctypes` and integer attributes use native
  byte order. The external provider matrix now includes full emulated s390x (big-endian LP64),
  armhf, and i386 lanes. That evidence is diagnostic rather than a support certification: s390x
  is not a framework CI lane, and the latest full s390x provider runs were incomplete.
- The GitHub Actions `macos-latest` runner is arm64 (Apple Silicon). arm64 macOS is still
  LP64, so `CK_ULONG` is 8 bytes and the ctypes ABI path is the same as Linux; the lane
  additionally exercises the `.dylib` load path with a real Homebrew SoftHSM2 module.
- Windows uses the LLP64 model, so `CK_ULONG` (a C `unsigned long`) is 4 bytes; the raw
  layer handles this and packs pkcs11 structs with `_pack_ = 1`. An unhandled native crash on
  Windows exits with a positive NTSTATUS code (e.g. `0xC0000005` access violation) rather than
  a negative POSIX signal, and the framework classifies it as a crash. A direct ctypes access
  violation can instead arrive as `OSError: exception: access violation` with a normal pytest
  exit; the framework now classifies that structured direct failure in setup, call, or teardown as
  a crash too. If it belongs to an owned nested probe, it contributes to `child_crash`. An ordinary
  `OSError` or traceback text alone is not crash evidence.
- The mmap demand-zero security probes need POSIX `MAP_ANONYMOUS`; on Windows they skip
  cleanly (recorded as a setup xfail), never crash.
- Private-cache privacy on Windows relies on the per-user `%LOCALAPPDATA%` profile
  directory (NTFS default ACL). POSIX `os.chmod` cannot set an owner-only ACL there, so
  the 0o700 mode-bit tightening used on POSIX is a near-noop on Windows; the profile
  directory is the trust boundary. See `core/cache_paths.py`.

## FreeBSD

FreeBSD is POSIX and shares Linux's code path for every capability above (LP64 ABI,
`os.fork`, `SIGALRM`, POSIX `mmap`, `.so` loading, POSIX mode bits). It is expected to
work but is not covered by a dedicated CI lane (GitHub Actions has no native FreeBSD
runner). Rows marked `POSIX` in the matrix reflect this: same behavior as Linux, not
independently CI-verified. If you run pkcs11-check on FreeBSD, the meta-test suite
(`uv run pytest tests/`) is the quickest confidence check.
