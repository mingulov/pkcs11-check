"""Tests for pkcs11_check.report.sanitize - pure text-reduction render helpers."""

from __future__ import annotations

from pkcs11_check.report.sanitize import (
    collapse_multiline,
    normalize_dashes,
    sanitize_line,
    summarize_crash,
    truncate_ckr_list,
    truncate_hex,
)

EM_DASH = chr(0x2014)
EN_DASH = chr(0x2013)


def test_truncate_hex_leaves_short_runs_untouched() -> None:
    assert truncate_hex("got CKR_OK deadbeef") == "got CKR_OK deadbeef"


def test_truncate_hex_shortens_long_run_with_byte_count() -> None:
    blob = "ab" * 200  # 400 hex chars = 200 bytes
    out = truncate_hex(blob, limit=64)
    assert out == f"{blob[:64]}...(200 bytes)"
    assert len(out) < 90


def test_truncate_hex_handles_inline_run() -> None:
    text = "Expected: " + ("3a" * 100) + " end"
    out = truncate_hex(text)
    assert out.startswith("Expected: 3a3a")
    assert "...(100 bytes) end" in out


def test_collapse_multiline_single_line_untouched() -> None:
    assert collapse_multiline("one line") == "one line"


def test_collapse_multiline_keeps_first_and_counts_rest() -> None:
    assert collapse_multiline("head\na\nb") == "head (+2 more lines)"


def test_collapse_multiline_singular_marker() -> None:
    assert collapse_multiline("head\nonly") == "head (+1 more line)"


def test_truncate_ckr_list_short_unchanged() -> None:
    assert truncate_ckr_list(["CKR_OK", "CKR_ARGUMENTS_BAD"]) == "CKR_OK, CKR_ARGUMENTS_BAD"


def test_truncate_ckr_list_caps_with_overflow_marker() -> None:
    assert truncate_ckr_list(["A", "B", "C", "D", "E"], keep=3) == "A, B, C (+2)"


def test_truncate_ckr_list_empty() -> None:
    assert truncate_ckr_list([]) == ""


def test_normalize_dashes_em_and_en() -> None:
    assert normalize_dashes(f"a{EM_DASH}b") == "a - b"
    assert normalize_dashes(f"a{EN_DASH}b") == "a - b"


def test_normalize_dashes_collapses_surrounding_spaces() -> None:
    assert normalize_dashes(f"a {EM_DASH} b") == "a - b"


def test_sanitize_line_collapses_then_truncates_then_normalizes() -> None:
    text = f"head {EM_DASH} " + ("ff" * 100) + "\nstdout: noise\nstderr: noise"
    out = sanitize_line(text)
    assert out.startswith("head - ff")
    assert "...(100 bytes)" in out
    assert "(+2 more lines)" in out
    assert "stdout:" not in out


def test_sanitize_line_plain_text_untouched() -> None:
    assert sanitize_line("C_Sign accepted invalid input") == "C_Sign accepted invalid input"


def test_summarize_crash_keeps_descriptor_drops_dump() -> None:
    summary = "C_EncryptInit(AES_GCM, pIv=NULL): module crashed with signal 11\nstdout: \nstderr: "
    assert (
        summarize_crash(summary)
        == "C_EncryptInit(AES_GCM, pIv=NULL): module crashed with signal 11"
    )


def test_summarize_crash_appends_crashing_call_from_trace() -> None:
    trace = '[{"i":0,"fn":"C_Initialize","rv":0},{"i":1,"fn":"C_GenerateKey","rv":0}]'
    summary = (
        f"probe blew up: module crashed with signal 11\nstdout: P11_RV_TRACE_JSON:{trace}\nstderr: "
    )
    assert (
        summarize_crash(summary)
        == "probe blew up: module crashed with signal 11 [died in C_GenerateKey]"
    )


def test_summarize_crash_skips_teardown_calls() -> None:
    trace = (
        '[{"i":0,"fn":"C_Sign","rv":0},{"i":1,"fn":"C_CloseSession","rv":0},'
        '{"i":2,"fn":"C_Finalize","rv":0}]'
    )
    summary = f"x: signal 11\nstdout: P11_RV_TRACE_JSON:{trace}\nstderr:"
    assert summarize_crash(summary) == "x: signal 11 [died in C_Sign]"


def test_summarize_crash_no_double_naming() -> None:
    trace = '[{"i":0,"fn":"C_DigestInit","rv":0}]'
    summary = f"double C_DigestInit: exit code 1\nstdout: P11_RV_TRACE_JSON:{trace}"
    assert summarize_crash(summary) == "double C_DigestInit: exit code 1"
