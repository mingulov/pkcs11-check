"""CKR buffer sizing tests via raw ctypes calls.

Tests CKR_BUFFER_TOO_SMALL: output functions with undersized buffers.
Uses pkcs11_check.raw.RawPKCS11 - wrapper handles buffer sizing internally.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Literal

import pytest

from pkcs11_check.classification import (
    Classification,
    classify,
    derive_verdict,
    fail_as,
    raise_for_record,
    record,
)
from pkcs11_check.raw.rv import is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import CKR_BUFFER_TOO_SMALL, CKR_OK
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    pin_from_config,
)
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed

pytestmark = [pytest.mark.access, pytest.mark.subprocess]

CountMode = Literal["none", "exact", "range"]


def _run_probe(p11_config: Any, probe: str) -> tuple[int, str, str]:
    """Launch the ``ckr_raw_buffer`` probe (Level.LOGIN) and return (rc, out, err).

    The PIN travels solely through ``_P11CHECK_PIN`` (via ``pin_from_config`` ->
    ``run_probe``); it is never embedded in the probe source or params (Invariant I3).
    """
    result = run_probe(
        "ckr_raw_buffer",
        {"module_path": str(p11_config.module), "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


def classify_undersized_digest_outcome(overwritten: int, ckr_ok: bool) -> None:
    """Classify C_Digest's response to an undersized (1-byte) output buffer.

    The probe over-allocates the real buffer but declares ``*pulDigestLen = 1``
    and counts how many bytes were written past that declared boundary, so the
    return code and an actual out-of-bounds write are SEPARATE signals:

    - ``overwritten > 0`` -> the module wrote past the declared buffer: a real
      OOB write (would corrupt a genuinely 1-byte caller buffer) -> ``fail``,
      regardless of the return code.
    - ``CKR_OK`` with ``overwritten == 0`` -> the module returned success but did
      NOT overflow: a clean PKCS#11 §5.10.2 return-code deviation (it should have
      returned ``CKR_BUFFER_TOO_SMALL``) with no security impact -> ``xfail``,
      recorded not hidden. (Every probed provider takes this path; the original
      "SECURITY" hard-fail conflated a benign return-code deviation with a buffer
      overflow.)
    - otherwise (CKR_BUFFER_TOO_SMALL, no overwrite) -> returns; the caller runs
      the size-query retry checks.
    """
    if overwritten > 0:
        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            f"C_Digest wrote {overwritten} bytes past a declared 1-byte output buffer.",
            ComplianceLevel.CRITICAL,
            reference="PKCS#11 v3.2",
        )
        # A real out-of-bounds write past the declared output buffer: the module
        # ignored the declared size it was given -> self-contradiction.
        classify(
            "self_contradiction",
            kind="policy",
            label="C_Digest:undersized-output-buffer",
            operation="C_Digest",
            spec_ref="PKCS#11 v3.2",
            summary=(
                f"SECURITY: C_Digest wrote {overwritten} bytes past a declared 1-byte output "
                f"buffer (out-of-bounds write)"
            ),
        )
    if ckr_ok:
        # CKR_OK with no overflow: a benign return-code deviation (should have
        # returned CKR_BUFFER_TOO_SMALL) with no security impact -> xfail.
        classify(
            "honest_deviation",
            label="C_Digest:undersized-output-buffer",
            operation="C_Digest",
            spec_ref="PKCS#11 v3.2",
            summary=(
                "C_Digest returned CKR_OK for a 1-byte output buffer without writing past it "
                "(PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, "
                "no buffer overflow)"
            ),
        )


@dataclass(frozen=True)
class BufferProbeSchema:
    """Required protocol fields and effect checks for one buffer probe."""

    expected_ckr: int | None = int(CKR_BUFFER_TOO_SMALL)
    expected_count: int | None = None
    require_initial_count: bool = False
    required_fields: tuple[str, ...] = ("CKR", "GUARD_OVERWRITTEN", "RETURNED_COUNT")
    require_retry: bool = False
    retry_fields: tuple[str, ...] = ("RETRY_CKR", "RETRY_LENGTH")
    retry_effect_fields: tuple[str, ...] = ()
    retry_length_reference: str | None = None
    success_effect_fields: tuple[str, ...] = ()
    retry_usable: bool = False
    max_count: int | None = None
    count_mode: CountMode = "none"
    count_min: int | None = None
    count_max: int | None = None


def _collect_buffer_measurement(
    fields: dict[str, str],
    *,
    schema: BufferProbeSchema,
    context: str,
    validate_required: bool,
) -> list[Classification]:
    """Collect provider effects and (when appropriate) protocol defects."""
    failures: list[Classification] = []
    operation = context.split(":", 1)[0]
    values: dict[str, int] = {}

    def add(
        reason: str,
        *,
        kind: str | None = None,
        summary: str,
    ) -> None:
        outcome, severity = derive_verdict(reason, kind)
        failures.append(
            Classification(
                reason=reason,
                outcome=outcome,
                severity=severity,
                kind=kind,
                label=context,
                summary=summary,
                operation=operation,
            )
        )

    def parse(name: str, *, required: bool = False) -> int | None:
        value = fields.get(name)
        if value is None:
            if required and validate_required:
                add("harness_error", summary=f"{context}: missing {name} measurement")
            return None
        try:
            parsed = int(value, 0)
        except (TypeError, ValueError):
            if validate_required:
                add("harness_error", summary=f"{context}: malformed {name} measurement {value!r}")
            return None
        values[name] = parsed
        return parsed

    ckr = parse("CKR", required="CKR" in schema.required_fields)
    overwritten = parse("GUARD_OVERWRITTEN", required="GUARD_OVERWRITTEN" in schema.required_fields)
    for name in schema.required_fields:
        if name not in {"CKR", "GUARD_OVERWRITTEN"}:
            parse(name, required=True)

    initial = parse(
        "INITIAL_COUNT",
        required=(
            schema.require_initial_count
            or schema.expected_count is not None
            or schema.count_mode != "none"
        ),
    )
    returned = parse(
        "RETURNED_COUNT",
        required=(
            schema.expected_count is not None
            or schema.require_initial_count
            or schema.max_count is not None
            or schema.count_mode != "none"
        ),
    )
    # Both success and BUFFER_TOO_SMALL make the returned count observable.  A clean
    # CKR deviation must not hide an independently contradictory size measurement.
    count_is_observable = ckr in (int(CKR_BUFFER_TOO_SMALL), int(CKR_OK))
    if (
        count_is_observable
        and schema.expected_count is not None
        and initial is not None
        and initial != schema.expected_count
    ):
        add(
            "self_contradiction",
            kind="metadata",
            summary=(
                f"{context}: initial count {initial} contradicts expected count "
                f"{schema.expected_count}"
            ),
        )
    if schema.count_mode == "exact":
        expected_returned = schema.expected_count if schema.expected_count is not None else initial
        if (
            count_is_observable
            and initial is not None
            and returned is not None
            and expected_returned is not None
            and returned != expected_returned
        ):
            add(
                "self_contradiction",
                kind="metadata",
                summary=(
                    f"{context}: returned count {returned} contradicts expected count "
                    f"{expected_returned}"
                ),
            )
    elif schema.count_mode == "range" and count_is_observable and returned is not None:
        lower = schema.count_min if schema.count_min is not None else schema.expected_count
        upper = schema.count_max
        if lower is not None and returned < lower:
            add(
                "self_contradiction",
                kind="metadata",
                summary=(
                    f"{context}: returned count {returned} is below the permitted minimum {lower}"
                ),
            )
        if upper is not None and returned > upper:
            add(
                "self_contradiction",
                kind="metadata",
                summary=(
                    f"{context}: returned count {returned} exceeds the permitted maximum {upper}"
                ),
            )
    if schema.max_count is not None and returned is not None and returned > schema.max_count:
        add(
            "self_contradiction",
            kind="metadata",
            summary=(
                f"{context}: returned count {returned} exceeds declared maximum {schema.max_count}"
            ),
        )

    if ckr is not None and schema.expected_ckr is not None and ckr != schema.expected_ckr:
        add(
            "honest_deviation",
            summary=(
                f"{context}: returned CKR 0x{ckr:08x} instead of expected "
                f"CKR 0x{schema.expected_ckr:08x}"
            ),
        )
    elif (
        ckr is not None
        and schema.expected_ckr is None
        and ckr
        not in (
            int(CKR_BUFFER_TOO_SMALL),
            int(CKR_OK),
        )
    ):
        if not is_standard_ckr(ckr) and not is_vendor_defined_ckr(ckr):
            add(
                "self_contradiction",
                kind="metadata",
                summary=f"{context}: returned undefined CKR 0x{ckr:08x}",
            )
        else:
            add(
                "nonspec_reject",
                summary=(
                    f"{context}: returned unsupported clean CKR 0x{ckr:08x}; "
                    "expected CKR_OK or CKR_BUFFER_TOO_SMALL"
                ),
            )
    if overwritten is not None and overwritten < 0:
        add(
            "self_contradiction",
            kind="metadata",
            summary=f"{context}: guard measurement {overwritten} is negative",
        )
    elif overwritten is not None and overwritten > 0:
        add(
            "self_contradiction",
            kind="policy",
            summary=(
                f"{context}: provider overwrote {overwritten} guard byte(s) beyond the "
                "declared output buffer"
            ),
        )

    if ckr == int(CKR_BUFFER_TOO_SMALL):
        if schema.retry_usable:
            usable = parse("RETRY_USABLE", required=True)
            if usable == 0:
                add(
                    "self_contradiction",
                    kind="lifecycle",
                    summary=f"{context}: retry length is unusable after CKR_BUFFER_TOO_SMALL",
                )
        else:
            usable = None
        retry_required = schema.require_retry or usable is not None and usable > 0
        for name in schema.retry_fields:
            parse(name, required=retry_required)
        for name in schema.retry_effect_fields:
            parse(name, required=retry_required)
    else:
        for name in schema.retry_fields + schema.retry_effect_fields:
            if name in fields:
                parse(name)

    # A child may have emitted retry evidence even when its initial CKR deviated
    # from the expected value.  Always retain and classify that evidence rather
    # than letting the clean initial deviation hide a retry failure.
    retry_ckr = values.get("RETRY_CKR")
    retry_length = values.get("RETRY_LENGTH")
    if retry_ckr is not None and retry_ckr != int(CKR_OK):
        add(
            "self_contradiction",
            kind="lifecycle",
            summary=f"{context}: retry returned CKR 0x{retry_ckr:08x} instead of CKR_OK",
        )
    retry_reference = (
        values.get(schema.retry_length_reference) if schema.retry_length_reference else initial
    )
    if retry_length is not None and (
        retry_length <= 0 or retry_reference is not None and retry_length != retry_reference
    ):
        add(
            "self_contradiction",
            kind="lifecycle",
            summary=(
                f"{context}: retry length {retry_length} is unusable; expected "
                f"{retry_reference if retry_reference is not None else 'a positive length'}"
            ),
        )

    if ckr == int(CKR_OK):
        for name in schema.success_effect_fields:
            parse(name, required=True)

    for name in (
        "RETRY_OUTPUT_CORRECT",
        "OUTPUT_CORRECT",
        "RETRY_MATCH",
        "MATCH",
    ):
        if name in fields:
            effect = parse(name)
            if effect == 0:
                add(
                    "wrong_result",
                    kind="crypto",
                    summary=f"{context}: {name} reports incorrect output",
                )
    for name, kind in (
        ("FINAL_OK", "lifecycle"),
        ("OUTPUT_LENGTH_WITHIN_DECLARED", "policy"),
        ("SIZE_SENTINEL_CORRECT", "metadata"),
    ):
        if name in fields:
            effect = parse(name)
            if effect == 0:
                add(
                    "self_contradiction",
                    kind=kind,
                    summary=f"{context}: {name} reports an invalid provider effect",
                )
    if "FINAL_CKR" in fields:
        final_ckr = parse("FINAL_CKR")
        if final_ckr not in (None, int(CKR_OK)):
            add(
                "self_contradiction",
                kind="lifecycle",
                summary=f"{context}: final operation returned CKR 0x{final_ckr:08x}",
            )
    harness = [item for item in failures if item.reason == "harness_error"]
    if len(harness) > 1:
        details = "; ".join(item.summary for item in harness)
        first = failures.index(harness[0])
        failures[first] = replace(
            harness[0],
            summary=details,
            detail={"protocol": "measurement_schema", "probe_incomplete": True},
        )
        failures = [
            item
            for index, item in enumerate(failures)
            if item.reason != "harness_error" or index == first
        ]
    return failures


def _raise_strongest(failures: list[Classification]) -> Classification | None:
    """Return provider failures before harness failures, preserving all records."""
    for outcome in ("fail", "xfail"):
        for item in failures:
            if item.outcome == outcome and item.reason != "harness_error":
                return item
        for item in failures:
            if item.outcome == outcome:
                return item
    return None


def classify_buffer_measurement(
    fields: dict[str, str],
    *,
    expected_count: int | None = None,
    count_mode: CountMode = "none",
    count_min: int | None = None,
    count_max: int | None = None,
    context: str,
    raise_outcome: bool = True,
    expected_ckr: int | None = int(CKR_BUFFER_TOO_SMALL),
    max_count: int | None = None,
    require_initial_count: bool = False,
    required_fields: tuple[str, ...] = ("CKR", "GUARD_OVERWRITTEN", "RETURNED_COUNT"),
    require_retry: bool = False,
    retry_effect_fields: tuple[str, ...] = (),
    success_effect_fields: tuple[str, ...] = (),
    retry_usable: bool = False,
    retry_length_reference: str | None = None,
) -> Classification | None:
    """Classify a buffer probe using its explicit, per-probe protocol schema."""
    schema = BufferProbeSchema(
        expected_ckr=expected_ckr,
        expected_count=expected_count,
        require_initial_count=require_initial_count,
        required_fields=required_fields,
        require_retry=require_retry,
        retry_effect_fields=retry_effect_fields,
        success_effect_fields=success_effect_fields,
        retry_usable=retry_usable,
        retry_length_reference=retry_length_reference,
        max_count=max_count,
        count_mode=count_mode,
        count_min=count_min,
        count_max=count_max,
    )
    failures = _collect_buffer_measurement(
        fields, schema=schema, context=context, validate_required=True
    )
    for item in failures:
        record(item)
    strongest = _raise_strongest(failures)
    if strongest is not None and raise_outcome:
        raise_for_record(strongest)
    return strongest


def _parse_buffer_fields(output: str) -> dict[str, str]:
    """Parse the one-line measurement fields emitted by a raw buffer probe."""
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name in {
            "CKR",
            "INITIAL_COUNT",
            "RETURNED_COUNT",
            "GUARD_OVERWRITTEN",
            "RETRY_CKR",
            "RETRY_LENGTH",
            "RETRY_MATCH",
            "RETRY_OUTPUT_CORRECT",
            "RETRY_USABLE",
            "OUTPUT_CORRECT",
            "MATCH",
            "FINAL_CKR",
            "FINAL_LEN",
            "RETRY_LEN",
            "NEEDED",
            "LEN",
            "OVERWRITTEN",
            "FINAL_OK",
            "OUTPUT_LENGTH_WITHIN_DECLARED",
            "SIZE_SENTINEL_CORRECT",
        }:
            fields[name] = value.strip()
    return fields


def _check_buffer_probe(
    rc: int,
    output: str,
    stderr: str,
    *,
    context: str,
    expected_count: int | None = None,
    count_mode: CountMode = "none",
    count_min: int | None = None,
    count_max: int | None = None,
    expected_ckr: int | None = int(CKR_BUFFER_TOO_SMALL),
    max_count: int | None = None,
    require_initial_count: bool = False,
    required_fields: tuple[str, ...] = ("CKR", "GUARD_OVERWRITTEN", "RETURNED_COUNT"),
    require_retry: bool = False,
    retry_effect_fields: tuple[str, ...] = (),
    success_effect_fields: tuple[str, ...] = (),
    retry_usable: bool = False,
    retry_length_reference: str | None = None,
) -> None:
    """Apply provider effects before process precedence for one buffer probe."""
    semantic: list[Classification] = []
    malformed_marker: str | None = None
    for line in output.splitlines():
        if line.startswith("SETUP_XFAIL:"):
            prefix = "SETUP_XFAIL:"
            reason, kind = "not_operational", None
        elif line.startswith("BREAK:"):
            prefix = "BREAK:"
            reason, kind = "self_contradiction", "crypto"
        elif line.startswith("DEVIATION_XFAIL:"):
            prefix = "DEVIATION_XFAIL:"
            reason, kind = "honest_deviation", None
        else:
            continue
        payload = line.removeprefix(prefix).strip()
        if not payload:
            malformed_marker = prefix.removesuffix(":")
            continue
        outcome, severity = derive_verdict(reason, kind)
        semantic.append(
            Classification(
                reason=reason,
                outcome=outcome,
                severity=severity,
                kind=kind,
                label=context,
                summary=f"{context}: {payload}",
                detail={"protocol_marker": prefix.removesuffix(":")},
            )
        )
    for item in semantic:
        record(item)
    fields = _parse_buffer_fields(output)
    schema = BufferProbeSchema(
        expected_ckr=expected_ckr,
        expected_count=expected_count,
        require_initial_count=require_initial_count,
        required_fields=required_fields,
        require_retry=require_retry,
        retry_effect_fields=retry_effect_fields,
        success_effect_fields=success_effect_fields,
        retry_usable=retry_usable,
        retry_length_reference=retry_length_reference,
        max_count=max_count,
        count_mode=count_mode,
        count_min=count_min,
        count_max=count_max,
    )
    # A non-normal process disposition is authoritative.  We still collect complete
    # fields already emitted by the child, but never fabricate missing-field harness
    # records for a signal, SEH, timeout, or non-zero child exit.
    has_terminal_marker = any(
        line == "OK" or line.startswith("OK:") for line in output.splitlines()
    )
    process_is_normal = (
        rc == 0
        and SUBPROCESS_TIMEOUT_MARKER not in stderr
        and (has_terminal_marker or (bool(semantic) and not fields))
        and not any(
            line.startswith("HARNESS_ERROR:")
            for line in (*output.splitlines(), *stderr.splitlines())
        )
    )
    failures = _collect_buffer_measurement(
        fields,
        schema=schema,
        context=context,
        validate_required=process_is_normal and has_terminal_marker and malformed_marker is None,
    )
    for item in failures:
        record(item)
    termination, explicit_harness = assert_subprocess_completed(rc, output, stderr, context=context)
    if explicit_harness:
        return
    # A provider observation without the terminal OK marker is incomplete protocol.
    # Check this before provider deviations so a clean CKR mismatch cannot mask the
    # harness failure, while all observations parsed above remain recorded.
    if malformed_marker is not None:
        malformed = Classification(
            reason="harness_error",
            outcome="fail",
            severity="HIGH",
            label=context,
            summary=f"{context}: malformed {malformed_marker} marker",
            detail={"probe_incomplete": True, "protocol": "malformed_marker"},
        )
        record(malformed)
        raise_for_record(malformed)
    if fields and not has_terminal_marker:
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: buffer probe did not emit a complete OK measurement",
            detail={"probe_incomplete": True, "termination": termination},
        )
    strongest = _raise_strongest(failures)
    if strongest is not None:
        raise_for_record(strongest)
    if semantic:
        raise_for_record(semantic[0])
    if not any(line == "OK" or line.startswith("OK:") for line in output.splitlines()):
        fail_as(
            "harness_error",
            label=context,
            summary=f"{context}: buffer probe did not emit a complete OK measurement",
            detail={"probe_incomplete": True, "termination": termination},
        )


class TestBufferTooSmall:
    """Output operations with undersized buffers."""

    def test_digest_buffer_too_small(self, p11_config: Any) -> None:
        """C_Digest with 1-byte output -> CKR_BUFFER_TOO_SMALL.

        PKCS#11 v3.2: C_Digest with undersized output buffer MUST return
        CKR_BUFFER_TOO_SMALL and update *pulDigestLen with the required size.

        Uses a 64-byte buffer filled with guard bytes (0xAA) and passes out_len=1.
        After the call, checks how many guard bytes were overwritten to confirm
        whether the module actually wrote past the declared buffer boundary.
        """
        rc, out, err = _run_probe(p11_config, "digest_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_Digest undersized buffer",
            expected_count=32,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_encrypt_buffer_too_small(self, p11_config: Any) -> None:
        """C_Encrypt AES-ECB with 1-byte output -> CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_probe(p11_config, "encrypt_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_Encrypt undersized buffer",
            expected_count=16,
            count_mode="exact",
        )

    def test_sign_buffer_too_small(self, p11_config: Any) -> None:
        """C_Sign with 1-byte output -> CKR_BUFFER_TOO_SMALL."""
        rc, out, err = _run_probe(p11_config, "sign_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_Sign undersized buffer",
            expected_count=256,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )


class TestListBufferTooSmallGuards:
    """List-returning APIs must not write past the declared output count."""

    def test_get_slot_list_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetSlotList with one declared slot must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_slot_list_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetSlotList undersized list buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_get_mechanism_list_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetMechanismList with one declared slot must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_mechanism_list_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetMechanismList undersized list buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_get_interface_list_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetInterfaceList with one declared slot must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_interface_list_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetInterfaceList undersized list buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )


class TestSearchOutputGuards:
    """Search APIs must not write past the declared object-handle count."""

    def test_find_objects_max_count_one_preserves_guard(self, p11_config: Any) -> None:
        """C_FindObjects must return at most ulMaxObjectCount handles."""
        rc, out, err = _run_probe(p11_config, "find_objects_max_count_one_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_FindObjects one-handle output guard",
            expected_ckr=int(CKR_OK),
            max_count=1,
        )


class TestAttributeBufferTooSmallGuards:
    """C_GetAttributeValue must preserve caller buffers and size state."""

    def test_get_attribute_value_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_GetAttributeValue must not write past an undersized attribute buffer."""
        rc, out, err = _run_probe(p11_config, "get_attribute_value_guard")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetAttributeValue undersized attribute buffer guard",
            required_fields=("CKR", "GUARD_OVERWRITTEN", "RETURNED_COUNT", "NEEDED"),
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
            retry_length_reference="NEEDED",
        )


class TestDecryptBufferTooSmallGuards:
    """Decrypt output APIs must preserve state after CKR_BUFFER_TOO_SMALL."""

    def test_aes_cbc_pad_decrypt_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_Decrypt(CKM_AES_CBC_PAD) must be retryable after an undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_decrypt_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_Decrypt AES-CBC-PAD undersized output buffer guard",
            expected_count=len(b"cbc-pad-output"),
            count_mode="range",
            count_min=len(b"cbc-pad-output"),
            count_max=16,
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_aes_cbc_pad_decrypt_update_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_DecryptUpdate(CKM_AES_CBC_PAD) must preserve state after undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_decrypt_update_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_DecryptUpdate AES-CBC-PAD undersized output buffer guard",
            expected_ckr=None,
            require_retry=True,
            retry_usable=True,
            retry_effect_fields=("FINAL_CKR", "RETRY_OUTPUT_CORRECT"),
            success_effect_fields=("FINAL_CKR", "FINAL_OK", "MATCH"),
        )

    def test_aes_cbc_pad_encrypt_final_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_EncryptFinal(CKM_AES_CBC_PAD) must preserve state after undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_encrypt_final_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_EncryptFinal AES-CBC-PAD undersized output buffer guard",
            expected_ckr=None,
            require_retry=True,
            retry_usable=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
            success_effect_fields=("MATCH",),
        )

    def test_aes_cbc_pad_decrypt_final_buffer_too_small_preserves_guard_and_retries(
        self, p11_config: Any
    ) -> None:
        """C_DecryptFinal(CKM_AES_CBC_PAD) must preserve state after undersized output."""
        rc, out, err = _run_probe(p11_config, "aes_cbc_pad_decrypt_final_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_DecryptFinal AES-CBC-PAD undersized output buffer guard",
            expected_ckr=None,
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
            success_effect_fields=("MATCH",),
        )


class TestByteOutputBufferTooSmallGuards:
    """Byte-output APIs must not write past the declared output length."""

    def test_wrap_key_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_WrapKey with one declared byte must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "wrap_key_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_WrapKey undersized output buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_ecdh_aes_wrap_compressed_public_key_buffer_too_small_preserves_guard(
        self,
        p11_config: Any,
        p11_raw_session: Any,
    ) -> None:
        """ECDH-AES C_WrapKey with compressed EC public key must size safely."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH_AES_KEY_WRAP"):
            pytest.skip("CKM_ECDH_AES_KEY_WRAP not supported")
        if not (rs.has_mechanism("EC_KEY_PAIR_GEN") or rs.has_mechanism("ECDSA_KEY_PAIR_GEN")):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        rc, out, err = _run_probe(
            p11_config, "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        )
        _check_buffer_probe(
            rc,
            out,
            err,
            context="ECDH-AES C_WrapKey compressed public key undersized output buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )

    def test_get_operation_state_buffer_too_small_preserves_guard(self, p11_config: Any) -> None:
        """C_GetOperationState with one declared byte must preserve adjacent guard bytes."""
        rc, out, err = _run_probe(p11_config, "get_operation_state_buffer_too_small")
        _check_buffer_probe(
            rc,
            out,
            err,
            context="C_GetOperationState undersized output buffer guard",
            require_initial_count=True,
            count_mode="exact",
            require_retry=True,
            retry_effect_fields=("RETRY_OUTPUT_CORRECT",),
        )
