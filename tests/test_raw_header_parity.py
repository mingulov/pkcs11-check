"""Verify generated raw output matches the reference baseline.

The reference files were produced from a prior header source. This test
ensures that switching header sources preserves all symbols, structs, and
function metadata that the codebase depends on.
"""

from __future__ import annotations

import re
from pathlib import Path

from pkcs11_check.raw.types_std import CK_X9_42_MQV_DERIVE_PARAMS

TESTS_DIR = Path(__file__).parent
REF_TYPES = TESTS_DIR / "data" / "types_std_reference.py"
REF_METADATA = TESTS_DIR / "data" / "metadata_std_reference.py"


def _extract_names(text: str, pattern: str) -> set[str]:
    return set(re.findall(pattern, text))


def _extract_constants(text: str) -> set[str]:
    return _extract_names(
        text,
        r"^(CK[A-Z0-9_]+)\s*=",
    )


def _extract_classes(text: str) -> set[str]:
    return _extract_names(text, r"^class\s+(CK_\w+)")


def _extract_function_sigs(text: str) -> set[str]:
    # Quote-agnostic: ruff-formatted output uses double quotes, reference uses single.
    return _extract_names(text, r"['\"](C_\w+)['\"]:")


class TestTypesParity:
    """Every constant and struct from the reference must exist in current output."""

    def test_all_reference_constants_present(self) -> None:
        ref = _extract_constants(REF_TYPES.read_text())
        cur = _extract_constants(
            (Path(__file__).parents[1] / "src/pkcs11_check/raw/types_std.py").read_text()
        )
        missing = ref - cur
        assert not missing, f"Missing constants: {sorted(missing)[:20]}"

    def test_all_reference_structs_present(self) -> None:
        ref = _extract_classes(REF_TYPES.read_text())
        cur = _extract_classes(
            (Path(__file__).parents[1] / "src/pkcs11_check/raw/types_std.py").read_text()
        )
        missing = ref - cur
        assert not missing, f"Missing structs: {sorted(missing)}"

    def test_x942_mqv_field_names_match_oasis_header(self) -> None:
        fields = [field[0] for field in CK_X9_42_MQV_DERIVE_PARAMS._fields_]

        assert "pOtherInfo" in fields
        assert "pPublicData" in fields
        assert "pPublicData2" in fields
        assert "OtherInfo" not in fields
        assert "PublicData" not in fields
        assert "PublicData2" not in fields


class TestMetadataParity:
    """Every function from the reference must exist in current output."""

    def test_all_reference_functions_present(self) -> None:
        ref = _extract_function_sigs(REF_METADATA.read_text())
        cur = _extract_function_sigs(
            (Path(__file__).parents[1] / "src/pkcs11_check/raw/metadata_std.py").read_text()
        )
        missing = ref - cur
        assert not missing, f"Missing functions: {sorted(missing)}"

    def test_function_count_not_regressed(self) -> None:
        ref = _extract_function_sigs(REF_METADATA.read_text())
        cur = _extract_function_sigs(
            (Path(__file__).parents[1] / "src/pkcs11_check/raw/metadata_std.py").read_text()
        )
        assert len(cur) >= len(ref), f"Function count regressed: {len(cur)} < {len(ref)}"


class TestTypedConstants:
    """Verify all generated constants use typed families, not plain int."""

    def test_no_plain_int_constants(self) -> None:
        text = (Path(__file__).parents[1] / "src/pkcs11_check/raw/types_std.py").read_text()
        # Match lines like "CKA_TOKEN = 0x00000001" (plain int, no class wrapper)
        plain_pattern = re.compile(r"^(CK[A-Z_]+)\s*=\s*0x[0-9a-fA-F]+$", re.MULTILINE)
        plain_ints = plain_pattern.findall(text)
        assert not plain_ints, (
            f"Plain int constants found (should use typed classes): {plain_ints[:10]}"
        )
