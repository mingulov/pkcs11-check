"""Honest-region contract guard for the F2 arithmetic/FFI probe migration.

P11C-0198-010: a probe that advertises a readable length must back it with an
honestly mapped region carrying at least that many bytes
(``demand_zero_region(minimum_length)`` / ``demand_zero_buffer(min_size=)``).
Magnitudes no mapping can back stay collected ONLY as explicitly non-normative
``EXTENDED`` hostile-caller observations via ``hostile_unbacked_region``
(``honest=0``); they must never support a provider memory-corruption
conclusion.

Scope: the F2-owned probe modules and the two security test files. Task 2
message hunks (``_ffi_length_message.py``, ``TestMessageApiLengthBoundary``),
F11's ``TestUpdateOutputGuard`` / ``_ffi_length_state_guards.py``, and F12
alignment files are explicitly out of scope and are never scanned here.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBES_DIR = REPO_ROOT / "src/pkcs11_check/testcases/_probes"
SECURITY_DIR = REPO_ROOT / "src/pkcs11_check/testcases/security"

# F2-owned probe modules (brief: production ownership).
OWNED_PROBE_MODULES = (
    "arithmetic_overflow.py",
    "_ffi_length_isize.py",
    "_ffi_length_length_params.py",
    "_ffi_length_null_params.py",
    "_ffi_length_base.py",
    "ffi_length.py",
)

# Names that count as "uses the honest-region API" inside a _run_* probe body:
# the raw F1 API plus the two F2-owned honest/hostile demand helpers.
HONEST_API_NAMES = frozenset(
    {
        "demand_zero_region",
        "demand_zero_buffer",
        "hostile_unbacked_region",
        "_demand_readable_or_hostile",
        "_honest_template_or_hostile",
    }
)

# Reviewed sound probes that pass no caller-controlled readable length to the
# provider (scalars, explicit NULL, honestly backed allocation scalars) and
# therefore need no region. Exact set: every member must exist and must NOT
# reference the honest-region API; every other _run_* must reference it.
SOUND_NO_REGION: frozenset[tuple[str, str]] = frozenset(
    {
        ("arithmetic_overflow.py", "_run_gcm_tag_bits_overflow"),
        ("arithmetic_overflow.py", "_run_pss_salt_length_overflow"),
        ("arithmetic_overflow.py", "_run_key_value_len_overflow"),
        ("_ffi_length_length_params.py", "_run_rsa_pss_salt_length"),
        ("_ffi_length_length_params.py", "_run_gcm_tag_bits_length"),
        ("_ffi_length_length_params.py", "_run_ccm_mac_length"),
        ("_ffi_length_null_params.py", "_run_generate_key_oom"),
        ("_ffi_length_null_params.py", "_run_gcm_null_iv"),
        ("_ffi_length_null_params.py", "_run_ecdh_null_public_data"),
        ("_ffi_length_null_params.py", "_run_oaep_null_source_data"),
        ("_ffi_length_null_params.py", "_run_hkdf_null_salt"),
        ("_ffi_length_null_params.py", "_run_hkdf_null_info"),
        ("_ffi_length_null_params.py", "_run_eddsa_null_context_data"),
        ("_ffi_length_null_params.py", "_run_mldsa_empty_context"),
        ("_ffi_length_null_params.py", "_run_ccm_null_nonce"),
        ("_ffi_length_null_params.py", "_run_concat_base_data_null"),
        ("_ffi_length_null_params.py", "_run_tls_kdf_null_label"),
        ("_ffi_length_null_params.py", "_run_sp800_108_null_data_params"),
    }
)


def _parse_probe_module(name: str) -> ast.Module:
    path = PROBES_DIR / name
    return ast.parse(path.read_text(encoding="utf-8"), filename=name)


def _called_names(fn: ast.FunctionDef) -> set[str]:
    names: set[str] = set()
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                names.add(func.id)
    return names


def test_no_bare_demand_zero_buffer_in_owned_probes() -> None:
    """Every honeypot use states the length it is about to advertise (F1 API).

    A bare ``demand_zero_buffer()`` may return a cached mapping smaller than
    the claimed length; the minimum must be explicit.
    """
    offenders: list[str] = []
    checked = 0
    for mod in OWNED_PROBE_MODULES:
        tree = _parse_probe_module(mod)
        for sub in ast.walk(tree):
            if not isinstance(sub, ast.Call):
                continue
            func = sub.func
            if not (isinstance(func, ast.Name) and func.id == "demand_zero_buffer"):
                continue
            checked += 1
            has_minimum = bool(sub.args) or any(kw.arg == "min_size" for kw in sub.keywords)
            if not has_minimum:
                offenders.append(f"{mod}:{sub.lineno}: bare demand_zero_buffer()")
    assert not offenders, "under-backed honeypot use:\n" + "\n".join(offenders)
    assert checked >= 1, "guard is vacuous: no demand_zero_buffer call found"


def test_demand_zero_region_calls_carry_an_explicit_minimum() -> None:
    """``demand_zero_region()`` with no minimum cannot back any advertised length."""
    offenders: list[str] = []
    for mod in OWNED_PROBE_MODULES:
        tree = _parse_probe_module(mod)
        for sub in ast.walk(tree):
            if not isinstance(sub, ast.Call):
                continue
            func = sub.func
            if not (isinstance(func, ast.Name) and func.id == "demand_zero_region"):
                continue
            has_minimum = bool(sub.args) or any(kw.arg == "minimum_length" for kw in sub.keywords)
            if not has_minimum:
                offenders.append(f"{mod}:{sub.lineno}: bare demand_zero_region()")
    assert not offenders, "minimum-less region demand:\n" + "\n".join(offenders)


def test_every_owned_probe_is_honest_or_reviewed_sound() -> None:
    """Every ``_run_*`` probe uses the honest-region API or is reviewed sound."""
    sound_seen: set[tuple[str, str]] = set()
    offenders: list[str] = []
    run_count = 0
    for mod in OWNED_PROBE_MODULES:
        tree = _parse_probe_module(mod)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.FunctionDef) and node.name.startswith("_run_")):
                continue
            run_count += 1
            key = (mod, node.name)
            uses_api = bool(_called_names(node) & HONEST_API_NAMES)
            if key in SOUND_NO_REGION:
                sound_seen.add(key)
                if uses_api:
                    offenders.append(
                        f"{mod}:{node.name}: reviewed-sound probe now uses the "
                        "honest-region API; move it out of SOUND_NO_REGION"
                    )
            elif not uses_api:
                offenders.append(
                    f"{mod}:{node.name}: passes a provider length without the "
                    "honest-region API and is not reviewed sound"
                )
    assert run_count > 0, "guard is vacuous: no _run_* probes found"
    assert sound_seen == SOUND_NO_REGION, (
        "SOUND_NO_REGION drift: stale="
        f"{sorted(SOUND_NO_REGION - sound_seen)} "
        f"missing={sorted(sound_seen - SOUND_NO_REGION)}"
    )
    assert not offenders, "\n".join(offenders)


def test_owned_demand_helpers_use_the_raw_region_api() -> None:
    """The F2 demand helpers must bottom out in F1's committed region API."""
    helpers = {
        "arithmetic_overflow.py": ("_demand_readable_or_hostile", "_honest_template_or_hostile"),
        "_ffi_length_base.py": ("_demand_readable_or_hostile",),
    }
    for mod, names in helpers.items():
        tree = _parse_probe_module(mod)
        fns = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        for name in names:
            assert name in fns, f"{mod}: missing helper {name}"
            called = _called_names(fns[name])
            assert "demand_zero_region" in called, (
                f"{mod}:{name}: honest path must demand_zero_region the claimed length"
            )
            assert "hostile_unbacked_region" in called, (
                f"{mod}:{name}: un-mappable path must mark hostile_unbacked_region"
            )


def test_honest_threshold_matches_honeypot_candidates() -> None:
    """``_MAX_HONEST_BYTES`` must equal the largest honeypot mapping, exactly."""
    import pkcs11_check.testcases._probes._ffi_length_base as base
    import pkcs11_check.testcases._probes.arithmetic_overflow as arith
    import pkcs11_check.testcases._probes.honeypot as honeypot

    largest = honeypot._HONEYPOT_SIZES[0]
    assert arith._MAX_HONEST_BYTES == largest, (
        f"arithmetic_overflow._MAX_HONEST_BYTES={arith._MAX_HONEST_BYTES:#x} "
        f"!= honeypot largest candidate {largest:#x}"
    )
    assert base._MAX_HONEST_BYTES == largest, (
        f"_ffi_length_base._MAX_HONEST_BYTES={base._MAX_HONEST_BYTES:#x} "
        f"!= honeypot largest candidate {largest:#x}"
    )


def test_hostile_marker_is_single_valued_across_owned_files() -> None:
    """The ``HOSTILE_CALLER:`` wire marker has one definition per probe family."""
    for mod in ("arithmetic_overflow.py", "_ffi_length_base.py"):
        tree = _parse_probe_module(mod)
        values = [
            node.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and target.id == "HOSTILE_CALLER_PREFIX"
            for value in [node.value]
            if isinstance(node.value, ast.Constant)
        ]
        assert values == ["HOSTILE_CALLER:"], (
            f"{mod}: HOSTILE_CALLER_PREFIX must be defined once as 'HOSTILE_CALLER:', "
            f"got {values!r}"
        )


def _imported_from(tree: ast.Module, name: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == name:
                    found.add(node.module or "")
    return found


def test_parent_tests_import_the_canonical_hostile_marker() -> None:
    """Parent files match the probe family's marker constant, not a copy."""
    arith_test = ast.parse(
        (SECURITY_DIR / "test_arithmetic_overflow.py").read_text(encoding="utf-8"),
        filename="test_arithmetic_overflow.py",
    )
    ffi_test = ast.parse(
        (SECURITY_DIR / "test_ffi_length_boundary.py").read_text(encoding="utf-8"),
        filename="test_ffi_length_boundary.py",
    )
    assert "pkcs11_check.testcases._probes.arithmetic_overflow" in _imported_from(
        arith_test, "HOSTILE_CALLER_PREFIX"
    ), "test_arithmetic_overflow.py must import HOSTILE_CALLER_PREFIX from its probe module"
    assert "pkcs11_check.testcases._probes._ffi_length_base" in _imported_from(
        ffi_test, "HOSTILE_CALLER_PREFIX"
    ), "test_ffi_length_boundary.py must import HOSTILE_CALLER_PREFIX from _ffi_length_base"


def _test_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    """Map ``Class.test`` -> FunctionDef for every collected product test."""
    found: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                    found[f"{node.name}.{item.name}"] = item
    return found


# Hostile-capable parent tests: the probe may emit HOSTILE_CALLER:, so the
# test must route through the hostile-marker check. Exact partition with the
# sound sets below: any new test fails here until it is classified.
HOSTILE_ARITHMETIC_TESTS = frozenset(
    {
        "TestDataLengthOverflow.test_data_length_overflow",
        "TestMechanismParamLengthOverflow.test_mechanism_param_length_overflow",
        "TestTemplateCountOverflow.test_template_count_overflow",
        "TestTemplateCountOverflowValidHandles.test_template_count_overflow_with_valid_object_handle",
        "TestDeriveTemplateCountOverflowValidBase.test_derive_key_template_count_overflow_with_valid_base_key",
        "TestKemTemplateCountOverflow.test_kem_output_template_count_overflow",
        "TestAttributeValueLenOverflow.test_attribute_value_len_overflow",
        "TestGenerateKeyPairCountOverflow.test_generate_key_pair_count_overflow",
    }
)

SOUND_ARITHMETIC_TESTS = frozenset(
    {
        "TestGcmDecryptUpdateAccumulation.test_gcm_decrypt_update_accumulation_does_not_crash",
        "TestGcmTagBitsOverflow.test_gcm_tag_bits_overflow",
        "TestPssSaltLengthOverflow.test_pss_salt_length_overflow",
        "TestKeyValueLenOverflow.test_key_value_len_overflow",
    }
)

HOSTILE_FFI_TESTS = frozenset(
    {
        "TestIsizeMaxDataLength.test_encrypt_isize_boundary",
        "TestIsizeMaxDataLength.test_decrypt_isize_boundary",
        "TestIsizeMaxDataLength.test_sign_isize_boundary",
        "TestIsizeMaxDataLength.test_verify_isize_data_len",
        "TestIsizeMaxDataLength.test_digest_isize_boundary",
        "TestIsizeMaxUpdateLength.test_update_isize_data_len",
        "TestRandomIsizeLength.test_seed_random_isize_length_rejects_cleanly",
        "TestIsizeMaxOutputLength.test_sign_isize_output",
        "TestIsizeMaxOutputLength.test_digest_isize_output",
        "TestIsizeMaxOutputLength.test_verify_isize_sig_len",
        "TestAesCbcEncryptDataMalformedParams.test_aes_cbc_encrypt_data_malformed_params",
        "TestGcmAadLengthBoundary.test_gcm_aad_length_boundary",
        "TestCcmAadLengthBoundary.test_ccm_aad_length_boundary",
        "TestPbkdf2NestedLengthBoundary.test_pbkdf2_nested_length_boundary",
        "TestPbeNestedLengthBoundary.test_pbe_nested_length_boundary",
        "TestTlsKdfRandomLengthBoundary.test_tls_kdf_random_length_boundary",
        "TestSp800108NestedCountBoundary.test_sp800_108_data_param_count_boundary",
        "TestSp800108NestedCountBoundary.test_sp800_108_additional_derived_key_count_boundary",
        "TestRsaOaepSourceDataLengthBoundary.test_rsa_oaep_source_data_length_boundary",
        "TestGcmIvLengthBoundary.test_gcm_iv_length_boundary",
        "TestCcmNonceLengthBoundary.test_ccm_nonce_length_boundary",
        "TestEddsaContextLengthBoundary.test_eddsa_context_length_boundary",
    }
)

SOUND_FFI_TESTS = frozenset(
    {
        # Task 2 message hunks: out of scope, must stay untouched.
        "TestMessageApiLengthBoundary.test_encrypt_message_isize_input_len",
        "TestMessageApiLengthBoundary.test_decrypt_message_isize_input_len",
        "TestMessageApiLengthBoundary.test_decrypt_message_multipart_isize_input_len",
        "TestMessageApiLengthBoundary.test_sign_message_isize_input_len",
        "TestMessageApiLengthBoundary.test_verify_message_isize_input_len",
        "TestMessageApiLengthBoundary.test_sign_message_multipart_isize_input_len",
        "TestMessageApiLengthBoundary.test_verify_message_multipart_isize_input_len",
        "TestMessageApiLengthBoundary.test_encrypt_message_multipart_isize_input_len",
        # F11 Update guards: out of scope, must stay untouched.
        "TestUpdateOutputGuard.test_encrypt_update_one_byte_output_preserves_guard",
        "TestUpdateOutputGuard.test_decrypt_update_one_byte_output_preserves_guard",
        # Backed-scalar / NULL / truthful-capacity sound cases: stay strict.
        "TestAllocationGuard.test_generate_key_oom_value_len",
        "TestMechanismNullInnerParams.test_gcm_null_iv",
        "TestMechanismNullInnerParams.test_ecdh_null_public_data",
        "TestMechanismNullInnerParams.test_oaep_null_source_data",
        "TestMechanismNullInnerParams.test_hkdf_null_salt",
        "TestHkdfNullInfo.test_hkdf_null_info",
        "TestEddsaNullContext.test_eddsa_null_context_data",
        "TestMlDsaExplicitEmptyContext.test_mldsa_verify_empty_context_nonnull_pointer",
        "TestAesCcmNullNonce.test_ccm_null_nonce",
        "TestSimpleKdfNullData.test_concat_base_data_null",
        "TestTlsKdfNullParams.test_tls_kdf_null_label",
        "TestSp800108NullDataParams.test_sp800_108_null_data_params",
        "TestRsaPssSaltLengthBoundary.test_rsa_pss_salt_length_boundary",
        "TestGcmTagBitsLengthBoundary.test_gcm_tag_bits_length_boundary",
        "TestCcmMacLengthBoundary.test_ccm_mac_length_boundary",
        "TestContinueAfterNullOutputQuery.test_encrypt_update_continuation_after_size_query",
        "TestContinueAfterNullOutputQuery.test_decrypt_update_continuation_after_size_query",
        "TestContinueAfterNullOutputQuery.test_encrypt_final_continuation_after_size_query",
        "TestContinueAfterNullOutputQuery.test_decrypt_final_continuation_after_size_query",
        "TestSingleShotOutputGuard.test_encrypt_one_byte_output_preserves_guard",
        "TestSingleShotOutputGuard.test_decrypt_one_byte_output_preserves_guard",
    }
)


def test_hostile_capable_parents_route_through_the_marker_check() -> None:
    """Every hostile-capable test checks HOSTILE_CALLER before conformance routing."""
    arith_tree = ast.parse(
        (SECURITY_DIR / "test_arithmetic_overflow.py").read_text(encoding="utf-8"),
        filename="test_arithmetic_overflow.py",
    )
    ffi_tree = ast.parse(
        (SECURITY_DIR / "test_ffi_length_boundary.py").read_text(encoding="utf-8"),
        filename="test_ffi_length_boundary.py",
    )
    arith_tests = _test_functions(arith_tree)
    ffi_tests = _test_functions(ffi_tree)
    assert set(arith_tests) == HOSTILE_ARITHMETIC_TESTS | SOUND_ARITHMETIC_TESTS, (
        "arithmetic test partition drift: "
        f"extra={sorted(set(arith_tests) - HOSTILE_ARITHMETIC_TESTS - SOUND_ARITHMETIC_TESTS)} "
        f"missing={sorted(HOSTILE_ARITHMETIC_TESTS | SOUND_ARITHMETIC_TESTS - set(arith_tests))}"
    )
    assert set(ffi_tests) == HOSTILE_FFI_TESTS | SOUND_FFI_TESTS, (
        "FFI test partition drift: "
        f"extra={sorted(set(ffi_tests) - HOSTILE_FFI_TESTS - SOUND_FFI_TESTS)} "
        f"missing={sorted(HOSTILE_FFI_TESTS | SOUND_FFI_TESTS - set(ffi_tests))}"
    )
    offenders: list[str] = []
    for name in sorted(HOSTILE_ARITHMETIC_TESTS):
        called = _called_names(arith_tests[name])
        if "_observe_hostile_caller_robustness" not in called:
            offenders.append(f"test_arithmetic_overflow.py:{name}: no hostile routing")
    for name in sorted(HOSTILE_FFI_TESTS):
        called = _called_names(ffi_tests[name])
        # _classify_unhonorable_length_outcome embeds the marker check at its
        # top, so calling it counts as routing; direct observers count too.
        routed = called & {
            "_classify_unhonorable_length_outcome",
            "_observe_hostile_caller_robustness",
        }
        if not routed:
            offenders.append(f"test_ffi_length_boundary.py:{name}: no hostile routing")
    assert not offenders, "\n".join(offenders)


def test_unhonorable_classifier_checks_the_hostile_marker_first() -> None:
    """The shared FFI classifier must observe the marker before crash routing."""
    tree = ast.parse(
        (SECURITY_DIR / "test_ffi_length_boundary.py").read_text(encoding="utf-8"),
        filename="test_ffi_length_boundary.py",
    )
    fn = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_classify_unhonorable_length_outcome"
    )
    called = _called_names(fn)
    assert "_observe_hostile_caller_robustness" in called, (
        "_classify_unhonorable_length_outcome must delegate to "
        "_observe_hostile_caller_robustness when the marker is present"
    )
    # The marker check must precede the crash/fail path: the observer call must
    # appear before the first assert_subprocess_completed call in body order.
    order: list[str] = []
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
            if sub.func.id in {
                "_observe_hostile_caller_robustness",
                "_is_hostile_caller",
                "assert_subprocess_completed",
            }:
                order.append(sub.func.id)
    assert "_is_hostile_caller" in order, "classifier must call _is_hostile_caller"
    first_observe = min(
        i for i, name in enumerate(order) if name == "_observe_hostile_caller_robustness"
    )
    first_crash = min(
        (i for i, name in enumerate(order) if name == "assert_subprocess_completed"),
        default=len(order),
    )
    assert first_observe < first_crash, (
        "hostile observation must precede the crash/fail path in "
        "_classify_unhonorable_length_outcome"
    )
