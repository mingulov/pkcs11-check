# Audit 41: Surface Audit, Scripts & Tooling

**Date:** 2026-04-01
**Files audited:** `test_surface_audit.py`, `test_tool_templates.py`, `scripts/mechanism-audit.py`, `scripts/ckr-coverage-check.py`, `scripts/mechanism_coverage.py`, `scripts/mechanism-matrix.py`, `scripts/generate_raw_standard.py`, `scripts/check_raw_exports.py`

## Findings

### Coverage Status

Surface audit probes for hidden/undocumented mechanisms across all mechanism families. Scripts provide mechanism coverage analysis, CKR coverage checking, mechanism matrix generation, and raw standard generation from headers.

### Quality Issues

- [NOTED] `scripts/generate_raw_standard.py` — generates types_std.py and metadata_std.py from v3.2 header. Verified in iteration 02 that output perfectly matches header (480 CKM, 160 CKA, 105 CKR, 104 C_ functions).
- [NOTED] `scripts/check_raw_exports.py` — validates raw module exports. Working correctly.

### Coverage Gaps

- [GAP] Surface audit may not probe vendor-specific mechanism ranges — spec defines vendor mechanism range 0x80000000+. No explicit scan for vendor mechanisms.
- [GAP] `scripts/mechanism-audit.py` output should be cross-referenced against this audit's findings to ensure consistency.
- [GAP] test_tool_templates.py — need to verify templates produce valid, runnable test files.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
