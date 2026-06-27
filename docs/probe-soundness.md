# Probe soundness - when a crash is a finding (and when it isn't)

**Status:** governing principle. Supersedes any reading of the length-truncation
note that says "small buffer + big length = unsound, discard it."

## The default: a crash is a finding

pkcs11-check exists to find module bugs. **A crash, OOB, or corruption that a
probe triggers in a module is a finding by default.** This is the same rule as
"a segfault IS the finding" - it applies to length/count/size probes too.

The burden of proof runs one way: calling a reproducer **unsound** requires a
*specific* argument that the module did something *correct*. The absence of such
an argument means it is a finding. Do not invert this.

## The recurring error to stop making

A security probe deliberately passes a **length or count larger than the
buffer/array it provides**, then the module crashes. The mistake is to dismiss
this as "harness-induced UB - we lied about the buffer, so the module was
'correct' to over-read."

That reasoning is wrong as a blanket rule, and it has repeatedly thrown away
**real, vendor-confirmed bugs** (e.g. heap overflows accepted and fixed
upstream). Here is why it is wrong:

- The security suite's whole premise is an **untrusted caller**. Passing an
  oversized length with a short buffer is exactly what a malicious or buggy
  caller does. Simulating that is the *point*, not a harness defect.
- A module that feeds an **unvalidated caller-supplied length** into a memory
  operation (`memcpy`, slice, `malloc(len)`, `len + pad`) has a genuine
  input-validation vulnerability (CWE-20 / 120 / 131 / 190 / 789). The crash is
  the finding.
- Vendors accept these. The classes below are all real regardless of how big the
  *caller's* buffer was.

### Bug classes these probes legitimately find (unconditionally real)

- **Internal-buffer overflow** - an oversized length is stored and later used to
  `memset`/`memcpy` over a *fixed-size internal* buffer.
- **Allocation-size integer wrap** - `len + pad` or `count * sizeof` wraps,
  `malloc()` under-allocates, the following copy **writes** out of bounds.
- **Write-side overflow / truncation-to-small-then-copy-large** - a `(word32)` /
  `(int)` narrowing under-sizes a destination that is then written in full.
- **Type-pun truncation** - a 64→32 cast of a length *pointer* corrupts state.

The crash in all of these is the module corrupting **its own** memory; it does
not depend on the caller's buffer being short.

## The one genuine false-positive

There is exactly one case where the crash is *contingent on our short buffer*
and not a module defect: a 64-bit-correct module that **honestly processes a
large-but-valid length** by reading the caller's buffer, where we
under-provisioned that buffer. The module did nothing wrong; it read what the
caller (we) claimed was there.

Empirically this is rare - conformant modules reject absurd lengths
(`CKR_DATA_LEN_RANGE` / `CKR_ARGUMENTS_BAD`) rather than read gigabytes. But it
is the real kernel of caution, and it is the *only* thing the soundness rule
should guard against.

## The decisive test: make the buffer honest, then judge

Do **not** discard a reproducer because the buffer was short. Instead:

1. **Back every caller-supplied buffer to its claimed length** with a demand-zero
   mmap (the shared honeypot, `_HONEYPOT_MMAP_CODE` / `_HONEYPOT_PTR`). Demand-zero
   means a 4 GiB claim costs only the pages actually touched.
2. Re-run the probe:
   - **Still crashes with an honest buffer → unconditionally REAL.** It is an
     internal/alloc-wrap/write-side bug. Keep it; it is the finding.
   - **No longer crashes → the crash was contingent** on our short buffer. The
     residual concern ("module trusts a caller length without a fits-word32
     guard") is a *hardening* observation caught by source review or a
     truncation-correctness probe - not a memory-corruption finding.

This single step separates real findings from the one false-positive, and it
*preserves* every real crash. Reach for it before ever writing the word
"unsound."

### Un-mappable magnitudes (2^63, 2^64, ULONG_MAX)

These cannot be mmap-backed. They target the **allocation-wrap / write-side**
class, where the crash is the module's own arithmetic and is independent of the
source buffer. Confirm with ASAN's read-vs-write classification:

- **WRITE overflow** (or read of the module's *own* heap) → real finding.
- pure **READ past our short source** with no write-side fault → the contingent
  case above.

Keep these as subprocess + ASAN-lane probes and document the rationale; do not
assert "no crash" on a non-ASAN build for an un-mappable magnitude without this.

## Truncation-correctness probes are a different thing

A probe that asks "does the module silently **truncate** 64→32 and produce wrong
output / process the wrong number of bytes?" is a *correctness* test, not a
memory-safety test. It must use an honest (mmap-backed) buffer and verify the
**effect** (output equivalence / bytes processed), never a reject-expectation -
otherwise it false-accuses a module that correctly honors the full length. This
is the legitimate, narrow origin of the length-truncation soundness note; do not
generalize it into "all oversized-length probes are unsound."

## Scalar overflows are always sound

When the oversized magnitude is a **scalar value** in a correctly-sized struct
(`ulTagBits`, `sLen`, a `CKA_VALUE_LEN` value in an 8-byte buffer), no buffer is
under-provisioned. The module must validate/reject; a crash is a real
internal-arithmetic bug. Keep these as-is.

## Checklist before writing "unsound"

- [ ] Did I make every caller buffer honest (mmap) and confirm the crash *disappears*?
- [ ] Is the crash a WRITE/internal-corruption (real) rather than a pure read of my short source?
- [ ] Do I have a *specific* argument that the module behaved correctly?

If you cannot check all three, it is a finding. Report it.
