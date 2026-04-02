# Audit 25: Message-Based API (v3.0+)

**Date:** 2026-04-01
**OASIS specs referenced:** `message_based_encryption_functions.md`, `message_based_decryption_functions.md`, `message-based_signing_and_macing_functions.md`, `message-based_functions_for_verifying_signatures_and_macs.md`
**Files audited:** `test_message_crypto.py`, `test_mech_message.py`

## Findings

### Coverage Status

AES-GCM message API tested: MessageEncryptInit, EncryptMessage, EncryptMessageBegin/Next, MessageEncryptFinal. Per-message parameters (CK_GCM_MESSAGE_PARAMS) with AAD support verified.

### Spec Deviations

- [NOTED] `CK_GCM_MESSAGE_PARAMS` correctly omits `ulIvBits` field (differs from `CK_AES_GCM_PARAMS`). Tests handle this correctly.

### Coverage Gaps

- [GAP] Message-based decryption — only encryption tested in test_mech_message.py.
- [GAP] Message-based signing/verification — not tested. Spec defines C_MessageSignInit/C_SignMessage etc.
- [GAP] Non-GCM message mechanisms — ChaCha20-Poly1305 and Salsa20-Poly1305 message API untested.
- [GAP] Error recovery — no test for message operation state after failed message (spec defines error cleanup behavior).

## Statistics

- Issues found: 0 fixed, 4 gaps documented
