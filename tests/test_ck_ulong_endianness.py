"""CK_ULONG attribute values are NATIVE-endian; only the spec may say otherwise.

A module writes a CK_ULONG attribute as a C `unsigned long` into a caller buffer, so its
byte order is the platform's. Decoding it with a hardcoded "little" is correct on x86 and
silently wrong on a big-endian host - a latent bug that no amount of LE testing can reveal,
and a blocker for any s390x lane.

`raw/recipes.py` already does this correctly with `byteorder=sys.byteorder`; the testcase
tree drifted from that.

The exemption matters as much as the rule. IEEE 1619 defines the XTS tweak/sequence number
as LITTLE-ENDIAN by specification, so testcases/acvp/aes/test_xts.py is correct as written
and must NOT be "fixed" - it encodes with to_bytes(16, "little") on the way out for the same
reason. A blanket sweep over every hardcoded endianness would have broken it.
"""

from __future__ import annotations

import re
from pathlib import Path

TESTCASES = Path(__file__).resolve().parents[1] / "src" / "pkcs11_check" / "testcases"

# Spec-mandated little-endian, not platform-dependent. Keep this list minimal and justified.
SPEC_MANDATED_LITTLE_ENDIAN = {
    "acvp/aes/test_xts.py",  # IEEE 1619 XTS tweak is little-endian by definition
}


def test_no_hardcoded_little_endian_ck_ulong_decodes() -> None:
    offenders: list[str] = []
    for path in TESTCASES.rglob("*.py"):
        rel = path.relative_to(TESTCASES).as_posix()
        if rel in SPEC_MANDATED_LITTLE_ENDIAN:
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r'from_bytes\([^)]*["\']little["\']', line):
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert offenders == [], (
        "CK_ULONG attribute values are native-endian; use byteorder=sys.byteorder as "
        "raw/recipes.py does. If a value is little-endian BY SPECIFICATION, add it to "
        "SPEC_MANDATED_LITTLE_ENDIAN with the citation.\n  " + "\n  ".join(offenders)
    )
