from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HEADER = REPO_ROOT / "third_party/pkcs11-headers/3.2/pkcs11.h"
OUT_TYPES = REPO_ROOT / "src/pkcs11_check/raw/types_std.py"
OUT_METADATA = REPO_ROOT / "src/pkcs11_check/raw/metadata_std.py"


def generate_raw_standard(*, header: Path, out_types: Path, out_metadata: Path) -> None:
    if not header.is_file():
        raise SystemExit(f"missing header: {header}")

    out_types.write_text(
        '"""Generated PKCS#11 standard types/constants."""\n'
        "from __future__ import annotations\n\n"
        "STANDARD_GENERATED = True\n"
    )
    out_metadata.write_text(
        '"""Generated PKCS#11 standard metadata."""\n'
        "from __future__ import annotations\n\n"
        'STANDARD_COUNTS = {"functions": 0, "attrs": 0, "mechanisms": 0}\n'
    )


def main() -> None:
    generate_raw_standard(header=HEADER, out_types=OUT_TYPES, out_metadata=OUT_METADATA)


if __name__ == "__main__":
    main()
