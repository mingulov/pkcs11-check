# Audit 26: Protocol Operations

**Date:** 2026-04-01
**OASIS specs referenced:** `tls_1.2_mechanisms.md`, `ssl.md`, `wtls.md`, `ike_mechanisms.md`, `double_ratchet.md`, `ct-kip.md`
**Files audited:** `test_tls12.py`, `test_ssl3.py`, `test_wtls.py`, `test_ike.py`, `test_x942_dh.py`, `test_x3dh.py`, `test_double_ratchet.py`, `test_protocol_edge_cases.py`

## Findings

### Quality Issues

- [FIXED] (in iteration 01) `test_tls12.py:922,971` — hardcoded `0x69` replaced with symbolic CKR constants.

### Coverage Status

TLS 1.2 PRF, SSL3 key material, WTLS, IKE derivation, X3DH (presence checks), Double Ratchet (CKM_X2RATCHET) all have test files. Protocol edge cases file exists for boundary testing.

### Coverage Gaps

- [GAP] CT-KIP mechanisms (CKM_KIP_DERIVE, CKM_KIP_MAC, CKM_KIP_WRAP) — spec defines these but no tests exist. Very few modules support CT-KIP.
- [GAP] X3DH actual derivation flows — only presence/consistency checks, no INITIALIZE/RESPOND tested.
- [GAP] Double Ratchet — availability checks only, no actual ratchet advance tested.
- [GAP] TLS 1.2 all derivation variants — not all CKM_TLS12_* sub-mechanisms fully exercised.

## Statistics

- Issues found: 0 new fixed, 4 gaps documented
