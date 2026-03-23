from __future__ import annotations

from pathlib import Path


HEADER = Path("third_party/pkcs11-headers/3.2/pkcs11.h")
OUT_TYPES = Path("src/pkcs11_check/raw/types_std.py")
OUT_METADATA = Path("src/pkcs11_check/raw/metadata_std.py")


def main() -> None:
    if not HEADER.is_file():
        raise SystemExit(f"missing header: {HEADER}")

    OUT_TYPES.write_text(
        '"""Generated PKCS#11 standard types/constants."""\n'
        "from __future__ import annotations\n\n"
        "STANDARD_GENERATED = True\n"
    )
    OUT_METADATA.write_text(
        '"""Generated PKCS#11 standard metadata."""\n'
        "from __future__ import annotations\n\n"
        'STANDARD_COUNTS = {"functions": 0, "attrs": 0, "mechanisms": 0}\n'
    )


if __name__ == "__main__":
    main()
