# Audit 32: OTP, CT-KIP & CMS

**Date:** 2026-04-01
**OASIS specs referenced:** `otp_mechanisms.md`, `otp_key_objects.md`, `ct-kip.md`, `cms_mechanisms.md`
**Files audited:** `test_otp.py`, `test_cms.py`

## Findings

### Coverage Status

OTP key attributes and mechanism presence tested. CMS signature mechanism (CKM_CMS_SIG) has basic coverage.

### Coverage Gaps

- [GAP] OTP mechanisms (SECURID, HOTP, ACTI) — mechanism availability checked but no actual OTP generation/verification flow tested. Very few soft tokens support OTP.
- [GAP] CT-KIP (CKM_KIP_DERIVE, CKM_KIP_MAC, CKM_KIP_WRAP) — no tests. CT-KIP is extremely rare in software tokens.
- [GAP] CMS signature creation/verification — test_cms.py likely probes availability but no full PKCS#7 CMS signature workflow.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
