"""Synthetic contract tests for the provider-attribute access prevention guard."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from tests._attribute_access_guard import Violation, analyze_file, analyze_paths, analyze_source


def _violations(
    source: str,
    *,
    path: str = "synthetic.py",
    **kwargs: Any,
) -> list[Violation]:
    return analyze_source(source, path=path, **kwargs)


def _kinds(source: str, **kwargs: Any) -> list[str]:
    return [violation.kind for violation in _violations(source, **kwargs)]


def _canonical_uaf_setup_source() -> str:
    return """
import ctypes
import sys
from pkcs11_check.core.crash_codes import ctypes_access_violation_code
from cryptography.hazmat.primitives.asymmetric import ec
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.recipes import gen_ec_keypair
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_DERIVE, CKA_EC_POINT, CKA_TOKEN
from pkcs11_check.testcases._ec_export import (
    InvalidProviderECPointError,
    ProviderECPointEncodingError,
    parse_provider_ec_point,
)

def _read_derive_peer_point(raw, sh, pub_b_h):
    attrs_b = read_attributes(raw, sh, pub_b_h, [CKA_EC_POINT])
    if CKA_EC_POINT not in attrs_b:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_EC_POINT, protocol="UAF", context="derive")
        sys.stdout.flush()
        return False, None
    return True, attrs_b[CKA_EC_POINT]

def _destroy_derive_setup_handles(raw, sh, handles, cleanup):
    first_error = None
    access_violation = None
    for handle in handles:
        try:
            raw.C_DestroyObject(sh, handle)
        except BaseException as exc:
            if first_error is None:
                first_error = exc
            if ctypes_access_violation_code(exc) is not None:
                access_violation = exc
    try:
        cleanup()
    except BaseException as exc:
        if first_error is None:
            first_error = exc
        if ctypes_access_violation_code(exc) is not None:
            access_violation = exc
    if access_violation is not None:
        raise access_violation
    if first_error is not None:
        raise first_error

def _run_derive(ctx, _extra):
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh = ctx.sh
    cleanup = ctx.cleanup
    curve_oid = encode_named_curve_parameters("secp256r1")
    try:
        pub_a_h, priv_a_h = gen_ec_keypair(
            raw,
            sh,
            curve_oid,
            public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        print(f"SETUP_XFAIL:EC keypair generation rejected: {exc}")
        cleanup()
        raise SystemExit(0) from None
    try:
        pub_b_h, priv_b_h = gen_ec_keypair(
            raw,
            sh,
            curve_oid,
            public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
    except AssertionError as exc:
        print(f"SETUP_XFAIL:EC keypair (peer) generation rejected: {exc}")
        raw.C_DestroyObject(sh, pub_a_h)
        raw.C_DestroyObject(sh, priv_a_h)
        cleanup()
        raise SystemExit(0) from None
    setup_handles = (pub_a_h, priv_a_h, pub_b_h, priv_b_h)
    try:
        point_present, point_value = _read_derive_peer_point(raw, sh, pub_b_h)
    except CkrAssertionError as exc:
        if isinstance(exc.rv, bool) or not isinstance(exc.rv, int) or exc.rv <= 0:
            raise
        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact
        emit_uaf_setup_fact(state="read_error", rv=exc.rv)
        sys.stdout.flush()
        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)
        return
    if not point_present:
        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)
        return
    if not isinstance(point_value, bytes) or not point_value:
        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact
        emit_uaf_setup_fact(state="unusable", value=point_value)
        sys.stdout.flush()
        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)
        return
    try:
        normalized_point = parse_provider_ec_point(
            point_value,
            ec.SECP256R1(),
            label="derive peer CKA_EC_POINT",
        )
    except ProviderECPointEncodingError as exc:
        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact
        emit_uaf_setup_fact(state="malformed_encoding", diagnostic=str(exc))
        sys.stdout.flush()
        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)
        return
    except InvalidProviderECPointError as exc:
        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact
        emit_uaf_setup_fact(state="invalid_point", diagnostic=str(exc))
        sys.stdout.flush()
        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)
        return
    ec_point_b = normalized_point.sec1_bytes
"""


def test_direct_provider_subscript_is_reported() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return attrs[CKA_VALUE]
"""

    violations = _violations(source)

    assert [violation.kind for violation in violations] == ["unsafe_subscript"]
    assert violations[0].line == 6
    assert violations[0].path == "synthetic.py"
    assert "attr_or_record" in violations[0].message


def test_chained_provider_get_is_reported() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    return read_attributes(raw, session, handle, [CKA_VALUE]).get(CKA_VALUE)
"""

    assert _kinds(source) == ["unsafe_get"]


def test_read_call_without_mapping_access_is_clean() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return attrs
"""

    assert _kinds(source) == ["taint_escape"]


def test_local_mapping_is_not_provider_tainted() -> None:
    source = """
def check():
    attrs = {CKA_VALUE: b"value"}
    return attrs[CKA_VALUE], attrs.get(CKA_VALUE)
"""

    assert _violations(source) == []


def test_import_aliases_and_recipe_module_alias_are_resolved() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes as read
import pkcs11_check.raw.recipes as recipes

def check(raw, session, handle):
    first = read(raw, session, handle, [CKA_VALUE])
    second = recipes.read_attributes(raw, session, handle, [CKA_VALUE])
    return first[CKA_VALUE], second.get(CKA_VALUE)
"""

    assert _kinds(source) == ["unsafe_subscript", "unsafe_get"]


def test_qualified_package_import_is_resolved_without_false_taint() -> None:
    source = """
import pkcs11_check.raw.recipes
import pkcs11_check.testcases._attribute_values as values
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE

def check(raw, session, handle):
    attrs = pkcs11_check.raw.recipes.read_attributes(raw, session, handle, [CKA_VALUE])
    value = values.attr_or_record(attrs, CKA_VALUE, label="value")
    if value is MISSING_ATTRIBUTE:
        return None
    return value
"""

    assert _violations(source) == []


def test_from_package_module_imports_are_resolved() -> None:
    source = """
from pkcs11_check.raw import recipes
from pkcs11_check.testcases import _attribute_values as values
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE

def check(raw, session, handle):
    attrs = recipes.read_attributes(raw, session, handle, [CKA_VALUE])
    value = values.attr_or_record(attrs, CKA_VALUE, label="value")
    if value is MISSING_ATTRIBUTE:
        return None
    return value
"""

    assert _violations(source) == []


def test_lexical_import_shadowing_does_not_create_false_taint() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def read_attributes(raw, session, handle, names):
    return {name: None for name in names}

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return attrs[CKA_VALUE]
"""

    assert _violations(source) == []


def test_runtime_alias_reassignment_stops_provider_taint() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def local(*args):
    return {}

def check(raw, session, handle):
    read_attributes = local
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return attrs[CKA_VALUE]
"""

    assert _violations(source) == []


def test_assignment_walrus_and_tuple_unpacking_preserve_provenance() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = first
    third = (read_attributes(raw, session, handle, [CKA_VALUE]),)[0]
    (fourth,) = (read_attributes(raw, session, handle, [CKA_VALUE]),)
    fifth = (attrs := read_attributes(raw, session, handle, [CKA_VALUE]))
    return second[CKA_VALUE], third.get(CKA_VALUE), fourth[CKA_VALUE], fifth[CKA_VALUE]
"""

    assert _kinds(source) == [
        "unsafe_subscript",
        "unsafe_get",
        "unsafe_subscript",
        "unsafe_subscript",
    ]


def test_local_wrapper_return_and_identity_propagate_provenance() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def load(raw, session, handle):
    return read_attributes(raw, session, handle, [CKA_VALUE])

def identity(value):
    return value

def check(raw, session, handle):
    attrs = identity(load(raw, session, handle))
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_helper_parameter_access_is_reported_at_helper_site() -> None:
    source = """
def consume(attrs):
    return attrs[CKA_VALUE]

from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    consume(read_attributes(raw, session, handle, [CKA_VALUE]))
"""

    violations = _violations(source)

    assert [violation.kind for violation in violations] == ["unsafe_subscript"]
    assert violations[0].line == 3


def test_unknown_calls_and_returns_report_taint_escapes() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    send_to_unknown(attrs)
    return attrs
"""

    assert _kinds(source) == ["taint_escape", "taint_escape"]


def test_for_loop_over_provider_mapping_reports_taint_escape() -> None:
    """``for k in attrs:`` iterates a provider-backed mapping directly, so it must
    be flagged the same as ``list(attrs)``/``attrs.items()`` -- ``_exec_loop`` did
    not previously check ``node.iter`` for ``For``/``AsyncFor`` at all, so a bare
    membership loop bypassed taint tracking entirely while the equivalent
    ``list(...)``/``.items()`` forms were (accidentally) already caught elsewhere.
    """
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    for key in attrs:
        print(key)
"""

    assert _kinds(source) == ["taint_escape"]


def test_membership_guard_proves_subscript_present() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs:
        return attrs[CKA_VALUE]
    return None
"""

    assert _violations(source) == []


def test_single_arm_positive_in_at_block_end_flags_fallthrough() -> None:
    """Nothing follows the if, so absence falls off the block end.

    A terminal body does not save this shape: presence returns from the
    body while absence alone reaches the end unclassified. (When a
    statement follows — total-function ``return None``, trailing
    ``fail_as(...)`` — the rest owns the absence path; see
    test_membership_guard_proves_subscript_present.)
    """
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs:
        return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_negative_membership_early_return_proves_subscript_present() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        return None
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_negated_membership_spellings_match_plain_spellings() -> None:
    """``not (K in m)`` is ``K not in m``; ``not (K not in m)`` is ``K in m``.

    The guard must see through the negation instead of missing the
    membership shape (and the absence path it governs).
    """
    negated_absence = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if not (CKA_VALUE in attrs):
        return None
    return attrs[CKA_VALUE]
"""
    # Same shape as test_negative_membership_early_return_proves_subscript_present.
    assert _kinds(negated_absence) == ["unstructured_absence"]

    negated_presence = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if not (CKA_VALUE not in attrs):
        return attrs[CKA_VALUE]
"""
    # Same shape as test_single_arm_positive_in_at_block_end_flags_fallthrough.
    assert _kinds(negated_presence) == ["unstructured_absence"]


def test_builtin_call_flags_unchecked_optional_argument() -> None:
    """Builtin-kind callees return early but must still check their arguments.

    An unchecked attr_or_record() optional passed to fail_as() is the same
    bug as one passed to an unknown call; the early return must not hide it.
    (Tainted mappings stay legal for sanctioned callees — only the optional
    check applies here.)
    """
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import attr_or_record
from pkcs11_check.classification import fail_as

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="probe")
    fail_as("wrong_result", detail=value)
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_single_arm_positive_in_last_in_branch_flags_conservatively() -> None:
    """``is_last`` is last-in-immediate-block: handling past the branch exit
    is not visible, so a last-in-branch guard flags (conservative)."""
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if condition:
        if CKA_VALUE in attrs:
            return attrs[CKA_VALUE]
    return None
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_double_negation_reports_effective_operator() -> None:
    """``not (not (K in m))`` toggles back to a positive-``in`` guard."""
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if not (not (CKA_VALUE in attrs)):
        return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_negated_membership_assertion_matches_plain_assertion() -> None:
    """``assert not (K in m)`` is a raw membership assertion like the plain
    spelling: it classifies nothing (and vanishes under ``-O``)."""
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    assert not (CKA_VALUE in attrs)
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_unknown_call_checks_optional_argument_exactly_once() -> None:
    """The shared argument-check helper must not double-emit: one unchecked
    optional into an unknown callee is exactly one violation."""
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="probe")
    unknown_sink(value)
"""

    assert _kinds(source) == ["unstructured_absence"]


@pytest.mark.parametrize(
    ("key", "protocol", "context"),
    [
        ("CKA_MODULUS", "RSA_ATTRIBUTE", '"decrypt:pkcs:random"'),
        ("CKA_EC_POINT", "UAF", '"derive"'),
    ],
    ids=["rsa", "uaf"],
)
def test_canonical_child_missing_attribute_evidence_certifies_site(
    key: str,
    protocol: str,
    context: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import {key}

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [{key}])
    if {key} not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute({key}, protocol="{protocol}", context={context})
        return
    return attrs[{key}]
"""

    assert _violations(source) == []


def test_canonical_uaf_setup_fact_evidence_certifies_complete_setup_region() -> None:
    assert _violations(_canonical_uaf_setup_source()) == []


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            "setup_handles = (pub_a_h, priv_a_h, pub_b_h, priv_b_h)",
            "setup_handles = (pub_a_h, priv_a_h, priv_b_h, priv_b_h)",
        ),
        (
            "        point_present, point_value = _read_derive_peer_point(raw, sh, pub_b_h)",
            "        point_present, point_value = _read_derive_peer_point(raw, sh, priv_b_h)",
        ),
        ("or exc.rv <= 0:", "or exc.rv < 0:"),
        (
            'emit_uaf_setup_fact(state="read_error", rv=exc.rv)',
            'emit_uaf_setup_fact(state="unusable", value=exc.rv)',
        ),
        (
            'emit_uaf_setup_fact(state="read_error", rv=exc.rv)',
            'emit_uaf_setup_fact(state="read_error", rv=exc)',
        ),
        (
            'emit_uaf_setup_fact(state="unusable", value=point_value)',
            'emit_uaf_setup_fact(state="unusable", value=other_value)',
        ),
        (
            "sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)",
            "_destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        sys.stdout.flush()",
        ),
        (
            "sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return",
            "sys.stdout.flush()\n        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return",
        ),
        (
            'label="derive peer CKA_EC_POINT"',
            'label="wrong label"',
        ),
        (
            "except ProviderECPointEncodingError as exc:",
            "except ValueError as exc:",
        ),
        (
            "import sys\n",
            "import sys as host_sys\n",
        ),
        (
            "    attrs_b = read_attributes(raw, sh, pub_b_h, [CKA_EC_POINT])",
            "    attrs_b = other_reader(raw, sh, pub_b_h, [CKA_EC_POINT])",
        ),
        (
            "    parse_provider_ec_point,\n",
            "",
        ),
        (
            "if not point_present:\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return",
            "if not point_present:\n        pass\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return",
        ),
        (
            'emit_uaf_setup_fact(state="malformed_encoding", diagnostic=str(exc))',
            'emit_uaf_setup_fact(state="invalid_point", diagnostic=str(exc))',
        ),
    ],
    ids=[
        "setup-tuple",
        "reader-argument",
        "numeric-guard",
        "read-state",
        "read-provenance",
        "unusable-provenance",
        "tail-reorder",
        "tail-repeat",
        "parser-label",
        "parser-exception",
        "sys-binding",
        "missing-reader-helper",
        "missing-parser-import",
        "absence-extra",
        "parser-state",
    ],
)
def test_uaf_setup_region_rejects_protocol_mutation(
    needle: str,
    replacement: str,
) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    assert needle in source
    mutated = source.replace(needle, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            "def _read_derive_peer_point(raw, sh, pub_b_h):",
            "def _read_derive_peer_point(raw, sh, *args):",
        ),
        (
            "    if CKA_EC_POINT not in attrs_b:",
            "    if CKA_EC_POINT in attrs_b:",
        ),
        (
            "        return False, None\n    return True, attrs_b[CKA_EC_POINT]",
            "        return False, None\n    return True, attrs_b.get(CKA_EC_POINT)",
        ),
    ],
    ids=["reader-variadic", "reader-presence-guard", "reader-present-access"],
)
def test_uaf_setup_region_rejects_reader_provenance_mutation(
    needle: str,
    replacement: str,
) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    assert needle in source
    mutated = source.replace(needle, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            "    first_error = None\n",
            "    return\n    first_error = None\n",
        ),
        (
            "def _destroy_derive_setup_handles(raw, sh, handles, cleanup):",
            "def _destroy_derive_setup_handles(raw, sh, *args):",
        ),
        (
            "    first_error = None\n",
            "    first_error = None\n    return\n",
        ),
    ],
    ids=["destroy-helper-terminal", "destroy-helper-variadic", "destroy-helper-pass-shape"],
)
def test_uaf_setup_region_rejects_destroy_helper_mutation(
    needle: str,
    replacement: str,
) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    assert needle in source
    mutated = source.replace(needle, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    "mutation",
    [
        "    global sys\n",
        "    return\n",
        "    sys.stdout = evil\n",
        '    eval("sys")\n',
        "    sys.exception()\n",
        "    _read_derive_peer_point = evil\n",
    ],
    ids=[
        "global",
        "terminal-bypass",
        "stdout-redirection",
        "reflection",
        "sys-reflection",
        "reader-rebind",
    ],
)
def test_uaf_setup_region_rejects_unanchored_prefix_mutation(mutation: str) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = "    setup_handles = (pub_a_h, priv_a_h, pub_b_h, priv_b_h)\n"
    assert needle in source
    mutated = source.replace(needle, mutation + needle, 1)
    assert "child_evidence_contract" in _kinds(mutated)


def test_uaf_setup_region_rejects_reader_import_replacement() -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = "from pkcs11_check.raw.recipes import read_attributes\n"
    assert needle in source
    mutated = source.replace(needle, needle + "read_attributes = evil\n", 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ("    sh = ctx.sh\n", "    sh = raw = ctx.sh\n"),
        ("    cleanup = ctx.cleanup\n", "    cleanup = raw = ctx.cleanup\n"),
        (
            '    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"\n',
            "    assert evil(ctx.sh) is not None\n",
        ),
        (
            "            public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},\n",
            "            evil={CKA_DERIVE: False, CKA_TOKEN: False},\n",
        ),
        (
            "            public_attrs={CKA_DERIVE: False, CKA_TOKEN: False},\n",
            "            public_attrs={CKA_DERIVE: False, CKA_TOKEN: True},\n",
        ),
    ],
    ids=["chained-sh", "chained-cleanup", "assert-call", "keygen-keyword", "keygen-dict"],
)
def test_uaf_setup_region_rejects_noncanonical_success_prefix(
    needle: str,
    replacement: str,
) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    assert needle in source
    mutated = source.replace(needle, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    "insertion",
    [
        "sys.stdout = evil\n",
        "host_sys = sys\nhost_sys.stdout = io.StringIO()\n",
        'globals()["read_attributes"] = evil\n',
        'setattr(module, "_destroy_derive_setup_handles", evil)\n',
        ("module = sys.modules[__name__]\nmodule._read_derive_peer_point = evil\n"),
        ("module = sys.modules[__name__]\nmodule._destroy_derive_setup_handles = evil\n"),
        'exec("read_attributes = evil")\n',
    ],
    ids=[
        "module-stdout",
        "alias-stdout",
        "globals-reader",
        "setattr-destroy",
        "alias-reader",
        "alias-destroy",
        "exec-reader",
    ],
)
def test_uaf_setup_region_rejects_module_protected_mutation(insertion: str) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = "import sys\n"
    assert needle in source
    mutated = source.replace(needle, needle + insertion, 1)
    assert "child_evidence_contract" in _kinds(mutated)


def test_uaf_setup_region_rejects_manual_exception_reader() -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    canonical = """def _read_derive_peer_point(raw, sh, pub_b_h):
    attrs_b = read_attributes(raw, sh, pub_b_h, [CKA_EC_POINT])
    if CKA_EC_POINT not in attrs_b:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_EC_POINT, protocol=\"UAF\", context=\"derive\")
        sys.stdout.flush()
        return False, None
    return True, attrs_b[CKA_EC_POINT]
"""
    replacement = """def _read_derive_peer_point(raw, sh, pub_b_h):
    try:
        attrs_b = read_attributes(raw, sh, pub_b_h, [CKA_EC_POINT])
    except CkrAssertionError:
        return False, None
    return True, attrs_b[CKA_EC_POINT]
"""
    assert canonical in source
    mutated = source.replace(canonical, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


def test_uaf_setup_region_rejects_reordered_parser_handlers() -> None:
    source = _canonical_uaf_setup_source()
    first = """    except ProviderECPointEncodingError as exc:
        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact
        emit_uaf_setup_fact(state="malformed_encoding", diagnostic=str(exc))
        sys.stdout.flush()
        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)
        return
"""
    second = """    except InvalidProviderECPointError as exc:
        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact
        emit_uaf_setup_fact(state="invalid_point", diagnostic=str(exc))
        sys.stdout.flush()
        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)
        return
"""
    assert first in source and second in source
    mutated = source.replace(first, "__PARSER_HANDLER__\n", 1).replace(second, first, 1)
    mutated = mutated.replace("__PARSER_HANDLER__", second, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            '        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
            '        exc.rv = value\n        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
        ),
        (
            '        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
            "        alias = exc\n"
            "        alias.rv = value\n"
            '        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
        ),
        (
            '        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
            '        del exc.rv\n        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
        ),
        (
            '        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
            '        exc.rv += value\n        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
        ),
        (
            '        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
            '        exc = value\n        emit_uaf_setup_fact(state="read_error", rv=exc.rv)\n',
        ),
    ],
    ids=["rv-assign", "alias-assign", "rv-delete", "rv-augassign", "exc-rebind"],
)
def test_uaf_setup_fact_rejects_exception_provenance_mutations(
    needle: str,
    replacement: str,
) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    assert needle in source
    mutated = source.replace(needle, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            "    except CkrAssertionError as exc:\n",
            "    except RuntimeError as exc:\n",
        ),
        (
            "    except CkrAssertionError as exc:\n",
            "    except CkrAssertionError as error:\n",
        ),
        (
            "from pkcs11_check.raw.rv import CkrAssertionError\n",
            "from fake import CkrAssertionError\n",
        ),
    ],
    ids=["wrong-exception", "wrong-binding", "shadowed-import"],
)
def test_uaf_setup_fact_rejects_noncanonical_read_error_handler(
    needle: str,
    replacement: str,
) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    assert needle in source
    mutated = source.replace(needle, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        return continue_testing(value)\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        raise continue_testing(value)\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        raise RuntimeError() from continue_testing(value)\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        evil.flush(continue_testing(value))\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        evil.flush()\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        sys.stdout.flush(value)\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        _destroy_derive_setup_handles(raw, make_raw(), setup_handles, cleanup)\n"
            "        return\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        cleanup()\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        sys.stdout.flush()\n"
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        _destroy_derive_setup_handles = evil\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
        ),
        (
            "        sys.stdout.flush()\n"
            "        _destroy_derive_setup_handles(raw, sh, setup_handles, cleanup)\n"
            "        return\n",
            "        sys = evil\n        sys.stdout.flush()\n        return\n",
        ),
    ],
    ids=[
        "return-expression",
        "raise-expression",
        "raise-from-expression",
        "flush-argument",
        "wrong-flush-receiver",
        "flush-argument-on-canonical-receiver",
        "nested-cleanup-argument",
        "unbounded-cleanup",
        "duplicate-flush",
        "rebound-cleanup-helper",
        "rebound-sys",
    ],
)
def test_uaf_setup_fact_rejects_noncanonical_terminal_tail(
    needle: str,
    replacement: str,
) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    assert needle in source
    mutated = source.replace(needle, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    "insertion",
    [
        "        alias = exc\n",
        "        consume(exc)\n",
        '        payload = {"exception": exc}\n',
        "        return exc\n",
        "        yield exc\n",
        "        diagnostic = exc.__dict__\n",
        "        diagnostic = exc.rv.foo\n",
        "        def capture():\n            return exc\n        capture()\n",
        '        setattr(exc, "message", value)\n',
    ],
    ids=[
        "alias",
        "call",
        "container",
        "return",
        "yield",
        "dict",
        "attribute-chain",
        "closure",
        "reflective-mutation",
    ],
)
def test_uaf_setup_fact_rejects_exception_binding_escape_or_use(insertion: str) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = (
        "        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact\n"
    )
    assert needle in source
    mutated = source.replace(needle, insertion + needle, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    "extra",
    [
        '        locals()["exc"].rv = value\n',
        '        vars()["exc"].rv = value\n',
        '        globals()["exc"] = value\n',
        '        eval("exc")\n',
        '        exec("exc.rv = value")\n',
        "        sys.exception().rv = value\n",
        "        sys.exc_info()[1].rv = value\n",
        "        saved = sys.exception()\n",
    ],
    ids=[
        "locals",
        "vars",
        "globals",
        "eval",
        "exec",
        "sys-exception",
        "sys-exc-info",
        "saved-exception",
    ],
)
def test_uaf_setup_fact_rejects_reflection_without_exception_name_use(extra: str) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = (
        "        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact\n"
    )
    assert needle in source
    mutated = source.replace(needle, extra + needle, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    "extra", ["        pass\n", "        consume(value)\n", "        diagnostic = value\n"]
)
def test_uaf_setup_fact_rejects_extra_handler_statement(extra: str) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = (
        "        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact\n"
    )
    assert needle in source
    mutated = source.replace(needle, extra + needle, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            "    except ProviderECPointEncodingError as exc:\n",
            "    except ValueError as exc:\n",
        ),
        (
            "    except InvalidProviderECPointError as exc:\n",
            "    except RuntimeError as exc:\n",
        ),
        (
            '        emit_uaf_setup_fact(state="malformed_encoding", diagnostic=str(exc))\n',
            '        emit_uaf_setup_fact(state="invalid_point", diagnostic=str(exc))\n',
        ),
    ],
    ids=["malformed-wrong-type", "invalid-wrong-type", "relabelled-state"],
)
def test_uaf_setup_fact_rejects_relabelled_ec_point_exception(
    needle: str,
    replacement: str,
) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    assert needle in source
    mutated = source.replace(needle, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            "from pkcs11_check.testcases._ec_export import (\n",
            "from fake import (\n",
        ),
        (
            "    ProviderECPointEncodingError,\n",
            "    ProviderECPointEncodingError as Error,\n",
        ),
        (
            "    ProviderECPointEncodingError,\n",
            "",
        ),
        (
            ")\n\ndef _read_derive_peer_point",
            ")\nProviderECPointEncodingError = fake_error\n\ndef _read_derive_peer_point",
        ),
    ],
    ids=["shadow-import", "aliased-import", "missing-import", "module-rebind"],
)
def test_uaf_setup_fact_rejects_noncanonical_ec_point_binding(
    needle: str,
    replacement: str,
) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    assert needle in source
    mutated = source.replace(needle, replacement, 1)
    assert "child_evidence_contract" in _kinds(mutated)


def test_uaf_setup_fact_rejects_missing_destroy_helper_definition() -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = "def _destroy_derive_setup_handles(raw, sh, handles, cleanup):\n"
    assert needle in source
    mutated = source.replace(
        needle, "def other_destroy_setup_handles(raw, sh, handles, cleanup):\n", 1
    )
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    "insertion",
    [
        "        consume(exc.rv)\n",
        "        diagnostic = str(exc)\n",
        "        str = fake_str\n",
        "        isinstance = fake_isinstance\n",
    ],
    ids=["rv-escape", "diagnostic-alias", "shadowed-str", "shadowed-isinstance"],
)
def test_uaf_setup_fact_rejects_noncanonical_exception_provenance(insertion: str) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = (
        "        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact\n"
    )
    assert needle in source
    mutated = source.replace(needle, insertion + needle, 1)
    assert "child_evidence_contract" in _kinds(mutated)


@pytest.mark.parametrize(
    "binding",
    [
        "        def exc():\n            return None\n",
        "        class exc:\n            pass\n",
        "        import fake as exc\n",
        "        from fake import value as exc\n",
        (
            "        try:\n"
            "            raise RuntimeError()\n"
            "        except RuntimeError as exc:\n"
            "            pass\n"
        ),
        "        match value:\n            case _ as exc:\n                pass\n",
        "        with manager() as exc:\n            pass\n",
        "        for exc in values:\n            pass\n",
        "        exc = value\n",
        "        if (exc := value):\n            pass\n",
        "        [exc for exc in values]\n",
        "        def capture(exc):\n            return None\n",
    ],
    ids=[
        "function",
        "class",
        "import",
        "from-import",
        "nested-except",
        "match-capture",
        "with-target",
        "for-target",
        "assignment",
        "walrus",
        "comprehension",
        "parameter",
    ],
)
def test_uaf_setup_fact_rejects_rebound_exception_name(binding: str) -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = (
        "        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact\n"
    )
    assert needle in source
    mutated = source.replace(needle, binding + needle, 1)
    assert "child_evidence_contract" in _kinds(mutated)


def test_uaf_setup_fact_rejects_unrelated_exception_bindings() -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    binding = (
        "        def other():\n"
        "            return None\n"
        "        class Other:\n"
        "            pass\n"
        "        import fake as other_import\n"
        "        from fake import value as other_from\n"
        "        try:\n"
        "            raise RuntimeError()\n"
        "        except RuntimeError as other_handler:\n"
        "            pass\n"
        "        match value:\n"
        "            case _ as other_match:\n"
        "                pass\n"
        "        with manager() as other_with:\n"
        "            pass\n"
        "        for other_for in values:\n"
        "            pass\n"
        "        [other_comp for other_comp in values]\n"
    )
    needle = (
        "        from pkcs11_check.testcases._probes._attribute_facts import emit_uaf_setup_fact\n"
    )
    assert needle in source
    mutated = source.replace(needle, binding + needle, 1)
    assert "child_evidence_contract" in _kinds(mutated)


def test_uaf_setup_fact_rejects_exception_binding_as_unusable_value() -> None:
    source = _canonical_uaf_setup_source()
    assert _violations(source) == []
    needle = '        emit_uaf_setup_fact(state="unusable", value=point_value)\n'
    assert needle in source
    mutated = source.replace(
        needle, '        emit_uaf_setup_fact(state="unusable", value=exc)\n', 1
    )
    assert "child_evidence_contract" in _kinds(mutated)


def test_scalar_ec_child_evidence_is_rejected_even_in_else_branch() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_PARAMS

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_EC_PARAMS])
    if CKA_EC_PARAMS in attrs:
        return attrs[CKA_EC_PARAMS]
    else:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(
            CKA_EC_PARAMS,
            protocol="EC_SETUP",
            context="ecdh_aes_wrap_compressed_public_key_buffer_too_small",
        )
        available = False
        return
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


def test_canonical_child_evidence_keeps_unrelated_unsafe_access() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    first = attrs[CKA_MODULUS]
    other = read_attributes(raw, session, handle, [CKA_VALUE])
    return first, other[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


@pytest.mark.parametrize(
    ("import_line", "call"),
    [
        (
            "from pkcs11_check.testcases._probes._attribute_facts import "
            "emit_missing_attribute as emit",
            'emit(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
        ),
        (
            "import pkcs11_check.testcases._probes._attribute_facts as facts",
            "facts.emit_missing_attribute(CKA_MODULUS, "
            'protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
        ),
        (
            "import pkcs11_check.testcases._probes._attribute_facts",
            "pkcs11_check.testcases._probes._attribute_facts.emit_missing_attribute("
            'CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
        ),
        (
            "from pkcs11_check.testcases._probes._attribute_facts import *",
            "emit_missing_attribute(CKA_MODULUS, "
            'protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
        ),
    ],
    ids=["local-alias", "module-alias", "qualified", "wildcard"],
)
def test_noncanonical_child_imports_emit_contract_diagnostics(
    import_line: str,
    call: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        {import_line}
        {call}
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)


def test_top_level_child_import_is_not_a_local_canonical_pair() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


@pytest.mark.parametrize(
    "call",
    [
        'helper(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
        "emit_missing_attribute(CKA_EC_POINT, "
        'protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
        'emit_missing_attribute(CKA_MODULUS, protocol="dynamic", context="decrypt:pkcs:random")',
        'emit_missing_attribute(CKA_MODULUS, protocol=protocol, context="decrypt:pkcs:random")',
        "emit_missing_attribute(CKA_MODULUS, "
        'context="decrypt:pkcs:random", protocol="RSA_ATTRIBUTE")',
        'emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=make_context())',
        "emit_missing_attribute(*[CKA_MODULUS], "
        'protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
    ],
)
def test_noncanonical_child_calls_retain_absence_and_emit_contract(call: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        {call}
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


@pytest.mark.parametrize(
    "branch",
    [
        "emit_missing_attribute(CKA_MODULUS, "
        'protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
        "if condition:\n            emit_missing_attribute(CKA_MODULUS, "
        'protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
        "value = [item for item in values]\n        emit_missing_attribute(CKA_MODULUS, "
        'protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")',
        "emit_missing_attribute(CKA_MODULUS, "
        'protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")\n'
        "        if condition:\n            return",
    ],
    ids=["fallthrough", "nested-if", "comprehension", "nested-after-call"],
)
def test_nonflat_child_branches_retain_absence_and_emit_contract(branch: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        {branch}
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unsafe_subscript" in _kinds(source)


@pytest.mark.parametrize(
    "mutation",
    [
        "emit_missing_attribute = fake",
        "del emit_missing_attribute",
        "saved = emit_missing_attribute",
        "def emit_missing_attribute(*args, **kwargs):\n            return None",
    ],
    ids=["rebind", "delete", "escape", "shadow"],
)
def test_child_helper_rebinding_and_escape_retain_absence(mutation: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes

def fake(*args, **kwargs):
    return None

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        {mutation}
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_child_wrapper_and_callback_are_not_evidence_pairs() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        callback = lambda: emit_missing_attribute(
            CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random"
        )
        callback()
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


@pytest.mark.parametrize(
    "statement",
    [
        "generated = (item for item in values)",
        "type Alias = int",
        "def wrapper(value=emit_missing_attribute):\n            return value",
        "items = [item for item in values]",
    ],
    ids=["generator", "type-alias", "callable-default", "comprehension"],
)
def test_child_adversarial_proof_region_shapes_retain_absence(statement: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        {statement}
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_dynamic_context_name_and_rebinding_retain_absence() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    context = make_context()
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=context)
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_probe_package_module_alias_activates_contract_inventory() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

from pkcs11_check.testcases._probes import _attribute_facts as facts

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)


@pytest.mark.parametrize(
    ("import_line", "reference"),
    [
        (
            "from pkcs11_check.testcases import _probes as probes",
            "probes._attribute_facts.emit_missing_attribute",
        ),
        (
            "import pkcs11_check.testcases._probes as probes",
            "probes._attribute_facts.emit_missing_attribute",
        ),
        (
            "import pkcs11_check.testcases",
            "pkcs11_check.testcases._probes._attribute_facts.emit_missing_attribute",
        ),
    ],
    ids=["parent-from", "parent-module", "parent-qualified"],
)
def test_parent_probe_module_references_emit_contract_diagnostics(
    import_line: str,
    reference: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS
{import_line}

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        {reference}(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_module_key_walrus_in_class_definition_expression_retain_absence() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

class Marker:
    pass

@((CKA_MODULUS := Marker))
class Eager:
    pass

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_rsa_context_walrus_in_nested_definition_decorator_retain_absence() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def decorator(value):
    return value

def check(raw, session, handle, case):
    @decorator(case := "decrypt:pkcs:random")
    def nested():
        return None
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_nested_function_body_binding_does_not_invalidate_outer_context() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def nested():
        case = "not-the-context"
        return case
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


@pytest.mark.parametrize(
    "preamble",
    [
        "from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_MODULUS",
        "from pkcs11_check.raw.types_std import CKA_MODULUS, CKA_MODULUS as MODULUS",
        "from pkcs11_check.raw.types_std import *\n"
        "from pkcs11_check.raw.types_std import CKA_MODULUS",
    ],
    ids=["duplicate", "competing-alias", "wildcard"],
)
def test_key_import_aliases_are_owned_individually(preamble: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
{preamble}

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(
            CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random"
        )
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_nested_candidate_function_is_not_certified() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

class Wrapper:
    def check(raw, session, handle):
        attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
        if CKA_MODULUS not in attrs:
            from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
            emit_missing_attribute(
                CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random"
            )
            return
        return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_generic_candidate_function_is_not_certified() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check[T](raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


@pytest.mark.parametrize(
    ("preamble", "function"),
    [
        (
            "",
            """def check(raw, session, handle, attrs):
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
""",
        ),
        (
            "",
            """def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_EC_POINT])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
""",
        ),
        (
            "from pkcs11_check.raw.recipes import read_attributes as read",
            """def check(raw, session, handle):
    attrs = read(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
""",
        ),
        (
            "import pkcs11_check.raw.recipes as recipes",
            """def check(raw, session, handle):
    attrs = recipes.read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
""",
        ),
        (
            "",
            """def check(raw, session, handle):
    requested = [CKA_MODULUS]
    attrs = read_attributes(raw, session, handle, requested)
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
""",
        ),
        (
            "",
            """def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    attrs = other
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
""",
        ),
        (
            "",
            """def check(raw, session, handle):
    if condition:
        attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
""",
        ),
        (
            "",
            """def check(raw, session, handle):
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    return attrs[CKA_MODULUS]
""",
        ),
    ],
    ids=[
        "parameter",
        "wrong-key",
        "aliased-import",
        "qualified-call",
        "dynamic-list",
        "rebound",
        "conditional",
        "after-guard",
    ],
)
def test_guarded_map_requires_direct_canonical_provenance(
    preamble: str,
    function: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS
{preamble}

{function}
"""
    assert "child_evidence_contract" in _kinds(source)


def test_guarded_map_try_reader_is_not_an_admitted_proof() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    try:
        attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    except LookupError:
        return None
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


def test_map_name_cannot_be_read_attributes() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    read_attributes = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in read_attributes:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return read_attributes[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)


@pytest.mark.parametrize(
    "eager",
    [
        "class Eager:\n        read_attributes = fake",
        "class Eager:\n        nested = lambda read_attributes=fake: read_attributes",
        "class Eager:\n        def nested(read_attributes=fake):\n"
        "            return read_attributes",
        "class Eager:\n        if condition:\n            read_attributes = fake",
    ],
    ids=["class-assignment", "lambda-default", "def-default", "class-conditional"],
)
def test_eager_read_attributes_rebinding_retain_absence(eager: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def fake(*args):
    return {{}}

def check(raw, session, handle):
    {eager}
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    if "lambda read_attributes" in eager or "def nested" in eager:
        assert _violations(source) == []
    else:
        assert "child_evidence_contract" in _kinds(source)


@pytest.mark.parametrize(
    "intervening",
    [
        "marker = object()",
        "class Eager:\n        pass",
        "touch()",
    ],
    ids=["assignment", "class", "call"],
)
def test_guarded_map_must_be_immediately_before_guard(intervening: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    {intervening}
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)


@pytest.mark.parametrize(
    "try_shape",
    [
        """try:
        attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
        pass
    except LookupError:
        return None""",
        """try:
        attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    except LookupError:
        pass""",
        """try:
        attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    except LookupError:
        if condition:
            return None
        return None""",
    ],
    ids=["body-extra", "handler-pass", "handler-conditional"],
)
def test_guarded_map_try_shape_is_structurally_terminal(try_shape: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    {try_shape}
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)


def test_guarded_map_try_must_be_immediately_before_guard() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    try:
        attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    except LookupError:
        return None
    marker = object()
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)


@pytest.mark.parametrize(
    "nested",
    [
        "def writer():\n        global CKA_MODULUS\n        CKA_MODULUS = fake\n    writer()",
        "def writer():\n        global read_attributes\n"
        "        read_attributes = fake\n    writer()",
    ],
    ids=["global-key", "global-reader"],
)
def test_nested_outward_global_writer_retain_absence(nested: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def fake(*args):
    return {{}}

def check(raw, session, handle):
    {nested}
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)


def test_nested_nonlocal_context_and_map_retain_absence() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def outer():
    case = "decrypt:pkcs:random"
    attrs = None
    def check(raw, session, handle, case):
        def writer():
            nonlocal case, attrs
            case = "bad"
            attrs = None
        writer()
        attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
        if CKA_MODULUS not in attrs:
            from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
            emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
            return
        return attrs[CKA_MODULUS]
    return check
"""

    assert "child_evidence_contract" in _kinds(source)


def test_nested_unrelated_local_writer_is_safe() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def writer(local):
        local = None
        return local
    writer(object())
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


@pytest.mark.parametrize(
    "access",
    [
        "p.testcases._probes._attribute_facts.emit_missing_attribute",
    ],
    ids=["package-alias"],
)
def test_noncanonical_parent_helper_paths_emit_contract(access: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS
import pkcs11_check as p

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        {access}(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_unrelated_sibling_module_reference_is_baseline_clean() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS
import pkcs11_check.testcases._probes.session as session

def check(raw, session_handle, handle):
    attrs = read_attributes(raw, session_handle, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


def test_adapter_definition_without_module_ownership_is_not_a_contract_reference() -> None:
    source = """
def emit_missing_attribute(attribute, *, protocol, context):
    return None
"""

    assert _violations(source) == []


def test_attribute_facts_adapter_implementation_has_no_contract_diagnostic() -> None:
    path = (
        Path(__file__).parents[1]
        / "src"
        / "pkcs11_check"
        / "testcases"
        / "_probes"
        / "_attribute_facts.py"
    )

    assert "child_evidence_contract" not in {violation.kind for violation in analyze_file(path)}


@pytest.mark.parametrize(
    "binding",
    [
        "def inner(emit_missing_attribute):\n        return emit_missing_attribute",
        "def inner(*emit_missing_attribute):\n        return emit_missing_attribute",
        "def inner(**emit_missing_attribute):\n        return emit_missing_attribute",
        "emit_missing_attribute = value",
        "del emit_missing_attribute",
        "global emit_missing_attribute",
        "def inner():\n        nonlocal emit_missing_attribute",
        "try:\n    pass\nexcept Exception as emit_missing_attribute:\n    pass",
        "match value:\n    case emit_missing_attribute:\n        pass",
        "for emit_missing_attribute in values:\n    pass",
        "with manager() as emit_missing_attribute:\n    pass",
        "if (emit_missing_attribute := value):\n    pass",
        "match value:\n    case [*emit_missing_attribute]:\n        pass",
        "match value:\n    case {**emit_missing_attribute}:\n        pass",
    ],
)
def test_owned_helper_binding_forms_are_rejected(binding: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]

{binding}
"""

    assert "child_evidence_contract" in _kinds(source)


@pytest.mark.parametrize(
    "preamble",
    [
        "",
        "from pkcs11_check.raw.types_std import CKA_MODULUS as MODULUS",
        "from another_module import CKA_MODULUS",
        "CKA_MODULUS = 1",
        "def CKA_MODULUS():\n    return None",
    ],
    ids=["missing", "aliased", "competing-import", "assignment", "definition"],
)
def test_key_spelling_without_module_owned_identity_retain_absence(preamble: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
{preamble}

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


@pytest.mark.parametrize(
    "guard_control",
    [
        "def check(CKA_MODULUS, raw, session, handle):",
        "for CKA_MODULUS in values:\n    pass",
        "with manager() as CKA_MODULUS:\n    pass",
        "try:\n    pass\nexcept Exception as CKA_MODULUS:\n    pass",
        "match value:\n    case CKA_MODULUS:\n        pass",
    ],
)
def test_key_scope_binders_retain_absence(guard_control: str) -> None:
    if guard_control.startswith("def check(CKA_MODULUS"):
        source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

{guard_control}
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""
    else:
        source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS
{guard_control}

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


@pytest.mark.parametrize("declaration", ["global CKA_MODULUS", "nonlocal CKA_MODULUS"])
def test_key_global_and_nonlocal_declarations_retain_absence(declaration: str) -> None:
    nesting = (
        "def check(raw, session, handle):"
        if declaration.startswith("global")
        else "def outer():\n    CKA_MODULUS = 1\n\n    def check(raw, session, handle):"
    )
    indent = "    " if declaration.startswith("global") else "        "
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

{nesting}
{indent}{declaration}
{indent}attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
{indent}if CKA_MODULUS not in attrs:
{indent}    from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
{indent}    emit_missing_attribute(
{indent}        CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random"
{indent}    )
{indent}    return
{indent}return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


@pytest.mark.parametrize(
    ("protocol", "context"),
    [
        ("RSA_ATTRIBUTE", '"decrypt:pkcs:other"'),
        ("RSA_ATTRIBUTE", '"verify:pkcs:random"'),
        ("EC_SETUP", '"other"'),
        ("UAF", '"other"'),
    ],
)
def test_child_context_literals_are_finite(protocol: str, context: str) -> None:
    key = "CKA_MODULUS" if protocol == "RSA_ATTRIBUTE" else "CKA_EC_POINT"
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import {key}

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [{key}])
    if {key} not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute({key}, protocol="{protocol}", context={context})
        return
    return attrs[{key}]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_dynamic_rsa_context_accepts_only_top_level_ordinary_parameter() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


@pytest.mark.parametrize(
    "function_head",
    [
        "@decorator\ndef check(raw, session, handle, case):",
        "def check(raw, session, handle, case='decrypt:pkcs:random'):",
        "def check(raw, session, handle, *case):",
        "def check(raw, session, handle, **case):",
    ],
)
def test_dynamic_rsa_context_wrappers_defaults_and_decorators_retain_absence(
    function_head: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

{function_head}
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_dynamic_rsa_context_nested_wrapper_retain_absence() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def outer(raw, session, handle):
    def check(raw, session, handle, case):
        attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
        if CKA_MODULUS not in attrs:
            from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
            emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
            return
        return attrs[CKA_MODULUS]
    return check
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_membership_facts_join_conservatively() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if condition:
        if CKA_VALUE in attrs:
            pass
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_membership_fact_is_not_assumed_after_loop() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    while CKA_VALUE in attrs:
        value = attrs[CKA_VALUE]
        break
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_assert_membership_and_positive_get_are_safe() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    assert CKA_VALUE in attrs
    return attrs.get(CKA_VALUE)
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_attr_or_record_is_structured_absence_path() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    if value is MISSING_ATTRIBUTE:
        return None
    return value
"""

    assert _violations(source) == []


def test_attr_or_record_without_absence_branch_is_reported() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    return value + b"!"
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_tainted_mapping_escape_in_container_is_reported() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    values = [attrs]
    return values
"""

    assert _kinds(source) == ["taint_escape"]


def test_violation_sorting_and_source_identity_are_stable() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    first = attrs[CKA_VALUE]
    second = attrs.get(CKA_LABEL)
    return first, second
"""

    violations = _violations(source, path="pkg/caller.py")

    assert violations == sorted(violations)
    assert [violation.line for violation in violations] == [6, 7]
    assert [violation.column for violation in violations] == sorted(
        violation.column for violation in violations
    )
    assert all(violation.path == "pkg/caller.py" for violation in violations)
    assert violations[0].code == violations[0].kind
    assert violations[0].lineno == violations[0].line


def test_file_entry_point_uses_path_as_provenance(tmp_path: Path) -> None:
    path = tmp_path / "caller.py"
    path.write_text(
        "from pkcs11_check.raw.recipes import read_attributes\n"
        "attrs = read_attributes(raw, session, handle, [CKA_VALUE])\n"
        "value = attrs[CKA_VALUE]\n",
        encoding="utf-8",
    )

    violations = analyze_file(path)

    assert len(violations) == 1
    assert violations[0].path == str(path)


def test_different_read_attributes_is_not_tainted() -> None:
    source = """
from another_package import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return attrs[CKA_VALUE]
"""

    assert _violations(source) == []


@pytest.mark.parametrize(
    "source",
    [
        """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs and attrs[CKA_VALUE]:
        return attrs[CKA_VALUE]
    return None
""",
        """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        raise LookupError("missing")
    return attrs[CKA_VALUE]
""",
    ],
)
def test_compound_presence_guards_are_safe(source: str) -> None:
    assert _kinds(source) == ["unstructured_absence"]


def test_recursive_helpers_are_bounded_and_deterministic() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def loop(value):
    return loop(value)

def check(raw, session, handle):
    attrs = loop(read_attributes(raw, session, handle, [CKA_VALUE]))
    return attrs[CKA_VALUE]
"""

    first = _violations(source)
    second = _violations(source)

    assert first == second
    assert [violation.kind for violation in first] == ["taint_escape"]


def test_positive_guard_with_silent_absence_return_is_not_reviewed() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs:
        return attrs[CKA_VALUE]
    else:
        return None
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_non_terminal_else_v_none_absence_branch_is_flagged() -> None:
    """BRANCH-REVIEW M4 guard-bypass fix: ``if K in attrs: v = attrs[K] else: v = None`` is the
    exact shape verified to silently bypass the guard before the fix (the
    early return on a non-terminal absence branch skipped emission entirely).
    """
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs:
        v = attrs[CKA_VALUE]
    else:
        v = None
    return v
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_non_terminal_else_v_none_absence_branch_is_flagged_not_in_order() -> None:
    """Same BRANCH-REVIEW M4 bypass shape with the membership test inverted (`not in`), so the
    fabricated default lives in the if-body rather than the else-clause.
    """
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        v = None
    else:
        v = attrs[CKA_VALUE]
    return v
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_non_terminal_else_pass_absence_branch_is_flagged() -> None:
    """BRANCH-REVIEW M4 guard-bypass fix: ``else: pass`` is a non-terminal absence branch that
    silently falls through without recording anything; it must be flagged the
    same as ``else: v = None``.
    """
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs:
        v = attrs[CKA_VALUE]
        return v
    else:
        pass
    return None
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_non_terminal_bare_record_as_else_is_flagged() -> None:
    """BRANCH-REVIEW M4 guard-bypass fix: a bare ``record_as(...)`` call in the else-clause that
    does not terminate is still a non-terminal absence branch -- recording the
    observation is not enough on its own; the guard requires the record_as call
    to be followed by terminal code (``_structured_absence``), not silence.
    """
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs:
        v = attrs[CKA_VALUE]
        return v
    else:
        record_as("honest_deviation", operation="C_GetAttributeValue", detail="CKA_VALUE")
    return None
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_structured_record_as_absence_branch_is_accepted() -> None:
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        record_as(
            "honest_deviation",
            operation="C_GetAttributeValue",
            detail="CKA_VALUE was not returned",
        )
        return None
    return attrs[CKA_VALUE]
"""

    assert _violations(source) == []


@pytest.mark.parametrize(
    "record_call",
    [
        'record_as("honest_deviation", operation="C_GetAttributeValue", detail="CKA_LABEL")',
        'record_as("honest_deviation", operation="C_GetAttributeValue", '
        'detail="CKA_VALUE", actual_ckr=None)',
        'record_as("honest_deviation", operation="C_GetSlotList", detail="CKA_VALUE")',
    ],
)
def test_structured_absence_requires_exact_attribute_evidence(record_call: str) -> None:
    source = f"""
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        {record_call}
        return None
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_nonterminating_record_as_does_not_prove_presence() -> None:
    """A record_as() call that does not terminate is itself unstructured absence
    handling (see the BRANCH-REVIEW M4 guard-bypass fix): it no longer silently exempts the
    if-statement, and the later unconditional subscript is still unsafe too."""
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        record_as("honest_deviation", operation="C_GetAttributeValue", detail="CKA_VALUE")
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_reviewed_spec_default_helper_is_explicit_and_attribute_specific() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def trust_or_default(attrs):
    if CKA_TRUST_XXX not in attrs:
        return CKT_TRUST_UNKNOWN
    return attrs[CKA_TRUST_XXX]

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_TRUST_XXX])
    return trust_or_default(attrs)
"""

    assert (
        _violations(
            source,
        )
        != []
    )
    assert (
        _violations(
            source,
            reviewed_optional_helpers={"trust_or_default"},
            optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
        )
        == []
    )


def test_reviewed_helper_certification_refuses_unreachable_present_path() -> None:
    """A helper whose "present" branch never actually reaches the provider
    subscript must not certify. Here the subscript sits inside a dead
    ``if False:`` block and the helper always raises instead -- if
    certification only checked "does this subscript appear anywhere in the
    syntax tree", this dead code would be accepted and the guard would treat
    a helper that never returns the provider-backed value as reviewed."""
    source = """
from pkcs11_check.raw.recipes import read_attributes

def trust_or_default(attrs):
    if CKA_TRUST_XXX not in attrs:
        return CKT_TRUST_UNKNOWN
    if False:
        return attrs[CKA_TRUST_XXX]
    raise RuntimeError("never actually returns the mapping value")

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_TRUST_XXX])
    return trust_or_default(attrs)
"""

    assert _kinds(
        source,
        reviewed_optional_helpers={"trust_or_default"},
        optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
    ) == ["unstructured_absence"]


def test_unreviewed_or_wrong_spec_default_is_not_optional() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def trust_or_default(attrs):
    if CKA_VALIDATION_MODULE_ID not in attrs:
        return None
    return attrs[CKA_VALIDATION_MODULE_ID]

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALIDATION_MODULE_ID])
    return trust_or_default(attrs)
"""

    assert _kinds(source) == ["unstructured_absence"]
    assert _kinds(
        source,
        reviewed_optional_helpers={"trust_or_default"},
        optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
    ) == ["unstructured_absence"]


def test_spec_default_policy_allows_only_exact_trust_pair() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_TRUST_XXX])
    return attrs.get(CKA_TRUST_XXX, CKT_TRUST_UNKNOWN)
"""

    assert (
        _violations(
            source,
            optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
        )
        == []
    )


def test_required_validation_attribute_cannot_use_trust_default_policy() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALIDATION_MODULE_ID])
    return attrs.get(CKA_VALIDATION_MODULE_ID, CKT_TRUST_UNKNOWN)
"""

    assert _kinds(
        source,
        optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
    ) == ["unsafe_get"]


def test_negative_presence_oracle_requires_an_explicit_reviewed_summary() -> None:
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def absent_is_ok(attrs):
    if CKA_VALUE in attrs:
        record_as("self_contradiction", kind="metadata", detail="CKA_VALUE was present")
        return False
    return True

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return absent_is_ok(attrs)
"""

    assert _kinds(source) == ["unstructured_absence"]
    assert (
        _violations(
            source,
            reviewed_negative_oracles={"absent_is_ok"},
        )
        == []
    )


def test_copy_and_dict_map_construction_preserve_provider_provenance() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    copied = attrs.copy()
    cloned = dict(attrs)
    return copied[CKA_VALUE], cloned[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript", "unsafe_subscript"]


def test_direct_provider_map_destructuring_is_an_escape() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    key, value = attrs
    return key, value
"""

    assert _kinds(source) == ["taint_escape"]


def test_provider_map_augmented_assignment_is_mutation() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    attrs |= {CKA_LABEL: b"label"}
"""

    assert _kinds(source) == ["taint_escape"]


def test_nested_function_discovery_analyzes_new_function() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def outer(raw, session, handle):
    def inner(raw, session, handle):
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]
    return None
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_all_testcase_sources_are_analyzable() -> None:
    testcase_root = Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases"
    source_files = sorted(testcase_root.rglob("*.py"))

    assert source_files
    violations = analyze_paths(source_files)

    assert violations == sorted(violations)
    assert all(violation.path in {str(path) for path in source_files} for violation in violations)


def test_all_testcase_sources_have_zero_attribute_access_violations() -> None:
    """Release gate: F7 routed every provider-attribute read through the presence helper.

    This is the acceptance gate, not just the analyzability check above: it asserts
    ``violations == []`` across every testcase source, with no ``optional_defaults``
    configured. An unconfigured gate is the stronger release claim - if a site genuinely
    needed a reviewed default, that would show up here as a failure to investigate, not
    something to configure away.
    """
    testcase_root = Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases"
    source_files = sorted(testcase_root.rglob("*.py"))

    assert source_files
    violations = analyze_paths(source_files)

    if violations:
        details = "\n".join(
            f"{violation.path}:{violation.line}:{violation.column}: "
            f"{violation.code}: {violation.message}"
            for violation in violations
        )
        pytest.fail(
            f"{len(violations)} unguarded provider-attribute access violation(s) "
            f"remain in src/pkcs11_check/testcases:\n{details}"
        )


def test_all_testcase_sources_are_fully_covered_by_analysis() -> None:
    """Canary for the zero-violation gate above: it must fail *because there are no
    violations*, not because a regression scoped to real-file discovery/analysis --
    an ``rglob`` exclusion, a size-cap early-out, a path filter -- silently analyzed
    nothing and reported zero for that reason instead.

    Rather than plant a canary file inside ``src/pkcs11_check/testcases/`` (a
    separate agent is actively editing that tree), this asserts per-file coverage
    directly: every file the same ``rglob`` discovers must have been handed to
    ``analyze_source`` in full. ``analyze_paths(..., coverage=...)`` records, for
    each path, the exact length of the ``source`` string the analyzer actually
    parsed -- captured at the top of ``analyze_source``, before any early return --
    so a silently skipped file is simply absent from ``coverage``, and a silently
    truncated read (e.g. a byte-size cap) shows up as a length mismatch against an
    independent on-disk read performed here, outside the analyzer.
    """
    testcase_root = Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases"
    source_files = sorted(testcase_root.rglob("*.py"))

    assert source_files
    expected_lengths = {str(path): len(path.read_text(encoding="utf-8")) for path in source_files}

    coverage: dict[str, int] = {}
    analyze_paths(source_files, coverage=coverage)

    missing = sorted(set(expected_lengths) - set(coverage))
    assert not missing, (
        f"{len(missing)} discovered testcase source file(s) were never analyzed "
        f"(a discovery/path-filter regression would show up here): {missing}"
    )
    mismatched = sorted(
        path
        for path, expected_length in expected_lengths.items()
        if coverage[path] != expected_length
    )
    assert not mismatched, (
        f"{len(mismatched)} discovered testcase source file(s) were analyzed with a "
        f"length that does not match their on-disk content (a size-cap early-out "
        f"would show up here): {mismatched}"
    )


def test_class_method_bodies_are_analyzed() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

class Checker:
    def check(self, raw, session, handle):
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_same_named_nested_helpers_keep_lexical_identity() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def first(raw, session, handle):
    def helper(raw, session, handle):
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]
    return None

def second(raw, session, handle):
    def helper(raw, session, handle):
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs.get(CKA_VALUE)
    return None
"""

    assert _kinds(source) == ["unsafe_subscript", "unsafe_get"]


def test_called_nested_wrapper_is_not_a_false_entry_point() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def outer(raw, session, handle):
    def wrapper(attrs):
        return attrs
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    wrapper(attrs)
    return None
"""

    assert _violations(source) == []


def test_terminal_try_still_analyzes_finally() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    try:
        return None
    finally:
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_terminal_try_passes_pre_return_state_to_finally() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    try:
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return None
    finally:
        return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_match_case_bodies_are_analyzed() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, selector):
    match selector:
        case 1:
            attrs = read_attributes(raw, session, handle, [CKA_VALUE])
            return attrs[CKA_VALUE]
        case _:
            return None
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_boolop_presence_facts_do_not_leak_to_false_path() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs and condition:
        return attrs[CKA_VALUE]
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_loop_else_body_is_analyzed() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    for _ in ():
        pass
    else:
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_loop_fixed_point_propagates_values_to_later_iterations() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = {}
    for _ in range(1):
        if attrs:
            return attrs[CKA_VALUE]
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return None
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_keyword_arguments_and_callable_aliases_propagate_taint() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def consume(*, attrs):
    return attrs[CKA_VALUE]

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    alias = consume
    alias(attrs=attrs)
    return None
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_lexical_shadowing_does_not_resolve_global_function() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def consume(*, attrs):
    return attrs[CKA_VALUE]

def fake(*, attrs):
    return None

def check(raw, session, handle):
    consume = fake
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    consume(attrs=attrs)
"""

    assert _violations(source) == []


def test_assignment_and_subscript_mutations_escape_provider_mapping() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

class Box:
    pass

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    box = Box()
    box.value = attrs
    attrs[CKA_VALUE] = b"replacement"
    del attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["taint_escape", "taint_escape", "taint_escape"]


def test_absence_evidence_requires_an_exact_attribute_key() -> None:
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        record_as("honest_deviation", operation="C_GetAttributeValue", detail="CKA_VALUE_LEN")
        return None
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_positive_membership_without_total_path_is_reported() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs:
        value = attrs[CKA_VALUE]
    return None
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_reviewed_optional_helper_does_not_suppress_required_attribute() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def trust_or_default(attrs):
    if CKA_VALIDATION_MODULE_ID not in attrs:
        return None
    if CKA_TRUST_XXX not in attrs:
        return CKT_TRUST_UNKNOWN
    return attrs[CKA_TRUST_XXX]

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_TRUST_XXX])
    return trust_or_default(attrs)
"""

    assert _kinds(
        source,
        reviewed_optional_helpers={"trust_or_default"},
        optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
    ) == ["unstructured_absence"]


def test_negative_oracle_rejects_shadowed_record_helper() -> None:
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def fake(*args, **kwargs):
    return None

def absent_is_ok(attrs):
    record_as = fake
    if CKA_VALUE in attrs:
        record_as("self_contradiction", kind="metadata", detail="CKA_VALUE was present")
        return False
    return True

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return absent_is_ok(attrs)
"""

    assert _kinds(source, reviewed_negative_oracles={"absent_is_ok"}) == ["unstructured_absence"]


def test_attr_or_record_truthiness_does_not_prove_presence() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    if value:
        pass
    return None
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_same_diagnostic_site_deduplicates_multiple_provider_origins() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def consume(attrs):
    return attrs[CKA_VALUE]

def check(raw, session, handle):
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = read_attributes(raw, session, handle, [CKA_VALUE])
    consume(first)
    consume(second)
    return None
"""

    violations = _violations(source)

    assert len(violations) == 1
    assert violations[0].kind == "unsafe_subscript"
    assert violations[0].provenance.startswith("provider-call:")


def test_finally_preserves_tainted_return_path_with_conditional_fallthrough() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition):
    try:
        if condition:
            attrs = read_attributes(raw, session, handle, [CKA_VALUE])
            return None
    finally:
        return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_finally_pass_keeps_unconditional_return_terminal() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    try:
        return None
    finally:
        pass
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return attrs[CKA_VALUE]
"""

    assert _violations(source) == []


def test_loop_widening_reports_reverse_propagation_beyond_iteration_cap() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    tenth = {}
    for _ in range(20):
        tenth = ninth
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    return tenth[CKA_VALUE]
"""

    first = _violations(source)
    second = _violations(source)

    assert first == second
    assert _kinds(source) == ["unsafe_subscript"]


def test_loop_widening_rechecks_body_after_dependency_closed_state() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    for _ in range(20):
        ninth[CKA_VALUE]
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    return None
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_loop_widening_excludes_else_assignments_from_carried_dependencies() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import attr_or_record

def check(raw, session, handle):
    x = b""
    y = b""
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    for _ in range(20):
        x = y
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    else:
        y = attr_or_record({}, CKA_VALUE, label="value")
    return x + b"!"
"""

    assert _violations(source) == []


@pytest.mark.parametrize("terminal", ["break", "continue", "return"])
def test_loop_widening_ignores_assignment_after_terminal_flow(terminal: str) -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, stop):
    value = {}
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    for _ in range(20):
        if stop:
            TERMINAL
            value = first
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    return value[CKA_VALUE]
""".replace("TERMINAL", terminal)

    assert _violations(source) == []


def test_loop_widening_ignores_unreachable_try_else_assignment() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, stop):
    value = {}
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    for _ in range(20):
        value[CKA_VALUE]
        if stop:
            try:
                break
            except Exception:
                break
            else:
                value = first
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    return None
"""

    assert _violations(source) == []


def test_loop_widening_composes_try_else_terminal_paths() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, stop):
    value = {}
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    for _ in range(20):
        value[CKA_VALUE]
        if stop:
            try:
                pass
            except Exception:
                break
            else:
                break
            value = first
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    return None
"""

    assert _violations(source) == []


def test_loop_widening_keeps_with_suppressed_flow_reachable() -> None:
    source = """
from contextlib import suppress
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, stop):
    value = {}
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    for _ in range(20):
        value[CKA_VALUE]
        if stop:
            with suppress(RuntimeError):
                raise RuntimeError
            value = ninth
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    return None
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_loop_widening_keeps_with_break_terminal() -> None:
    source = """
from contextlib import nullcontext
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, stop):
    value = {}
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    for _ in range(20):
        value[CKA_VALUE]
        if stop:
            with nullcontext():
                break
            value = first
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    return None
"""

    assert _violations(source) == []


def test_loop_widening_does_not_recheck_one_shot_for_iterable() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    iterable = {}
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    for _ in iterable[CKA_VALUE]:
        iterable = ninth
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    return None
"""

    assert _violations(source) == []


def test_guarded_optional_value_can_be_passed_to_unknown_callable() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    if value is MISSING_ATTRIBUTE:
        return
    consume(value, checked=value)
"""

    assert _violations(source) == []


def test_unguarded_optional_value_passed_to_unknown_callable_is_reported() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    consume(value)
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_optional_name_rebinding_invalidates_presence_refinement() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE, CKA_LABEL])
    value = attr_or_record(attrs, CKA_VALUE, label="first")
    if value is MISSING_ATTRIBUTE:
        return
    consume(((value := attr_or_record(attrs, CKA_LABEL, label="second")), None)[1], value)
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_later_argument_rebinding_does_not_invalidate_earlier_argument() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    if value is MISSING_ATTRIBUTE:
        return
    consume(value, (value := None))
"""

    assert _violations(source) == []


@pytest.mark.parametrize(
    "assignment",
    [
        "value = value",
        "alias = value\n    value = alias",
        "(value,) = (value,)",
    ],
)
def test_optional_identity_preserving_assignment_keeps_presence(assignment: str) -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    if value is MISSING_ATTRIBUTE:
        return
    ASSIGNMENT
    consume(value)
""".replace("ASSIGNMENT", assignment)

    assert _violations(source) == []


def test_optional_tuple_swap_uses_pre_assignment_presence_snapshot() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    first = attr_or_record(attrs, CKA_VALUE, label="value")
    if first is MISSING_ATTRIBUTE:
        return
    second = None
    first, second = second, first
    consume(second)
"""

    assert _violations(source) == []


def test_optional_tuple_rhs_keeps_proof_captured_before_later_walrus() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    if value is MISSING_ATTRIBUTE:
        return
    first, value = value, (value := None)
    consume(first)
"""

    assert _violations(source) == []


def test_distinct_local_wrapper_calls_get_distinct_optional_identities() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def load(attrs):
    return attr_or_record(attrs, CKA_VALUE, label="value")

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    first = load(attrs)
    if first is MISSING_ATTRIBUTE:
        return
    second = load(attrs)
    consume(second)
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_distinct_tuple_wrapper_calls_rebase_nested_optional_identities() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def load(attrs):
    return (attr_or_record(attrs, CKA_VALUE, label="value"),)

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    (first,) = load(attrs)
    if first is MISSING_ATTRIBUTE:
        return
    (second,) = load(attrs)
    consume(second)
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_local_identity_wrapper_preserves_guarded_optional_identity() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def identity(value):
    return value

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    if value is MISSING_ATTRIBUTE:
        return
    same = identity(value)
    consume(same)
"""

    assert _violations(source) == []


def test_tuple_argument_identity_wrapper_preserves_guarded_optional_identity() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def head(values):
    return values[0]

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    if value is MISSING_ATTRIBUTE:
        return
    same = head((value,))
    consume(same)
"""

    assert _violations(source) == []


def test_nested_conditional_terminal_does_not_prove_positive_membership_total() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs:
        if condition:
            return attrs[CKA_VALUE]
    return None
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_nested_optional_helper_cannot_prove_outer_required_attribute() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def trust_or_default(attrs):
    def fake(attrs):
        if CKA_TRUST_XXX not in attrs:
            return CKT_TRUST_UNKNOWN
        return attrs[CKA_TRUST_XXX]
    if CKA_TRUST_XXX not in attrs:
        return None
    return attrs[CKA_TRUST_XXX]

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_TRUST_XXX])
    return trust_or_default(attrs)
"""

    assert _kinds(
        source,
        reviewed_optional_helpers={"trust_or_default", "trust_or_default.fake"},
        optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
    ) == ["unstructured_absence"]


def test_nested_negative_oracle_cannot_prove_outer_helper_summary() -> None:
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def absent_is_ok(attrs):
    def fake(attrs):
        if CKA_VALUE in attrs:
            record_as("self_contradiction", kind="metadata", detail="CKA_VALUE was present")
            return False
        return True
    if CKA_VALUE in attrs:
        return False
    return False

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return absent_is_ok(attrs)
"""

    assert _kinds(source, reviewed_negative_oracles={"absent_is_ok"}) == ["unstructured_absence"]


def test_conditional_optional_default_does_not_prove_absence_path() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def trust_or_default(attrs, condition):
    if CKA_TRUST_XXX not in attrs:
        if condition:
            return CKT_TRUST_UNKNOWN
        return None
    return attrs[CKA_TRUST_XXX]

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_TRUST_XXX])
    return trust_or_default(attrs, condition)
"""

    assert _kinds(
        source,
        reviewed_optional_helpers={"trust_or_default"},
        optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
    ) == ["unstructured_absence"]


def test_conditional_negative_oracle_does_not_prove_present_path_terminal() -> None:
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def absent_is_ok(attrs, condition):
    if CKA_VALUE in attrs:
        if condition:
            record_as("self_contradiction", kind="metadata", detail="CKA_VALUE was present")
            return False
    return True

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return absent_is_ok(attrs, condition)
"""

    assert _kinds(source, reviewed_negative_oracles={"absent_is_ok"}) == [
        "unstructured_absence",
        "unstructured_absence",
    ]


def test_presence_or_short_circuit_refines_rhs_only() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs or attrs[CKA_VALUE]:
        return None
"""

    assert _violations(source) == []


def test_negated_presence_or_matches_plain_spelling() -> None:
    """``not (K in m) or m[K]`` is the safe-presence-or shape, negated."""
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if not (CKA_VALUE in attrs) or attrs[CKA_VALUE]:
        return None
"""

    assert _violations(source) == []


def test_presence_or_short_circuit_reports_unsafe_rhs_variant() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs or condition:
        return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_finally_return_override_discards_tainted_try_return() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    try:
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs
    finally:
        return {}
"""

    assert _violations(source) == []


def test_finally_normal_path_preserves_only_reachable_tainted_return() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition, override):
    try:
        if condition:
            attrs = read_attributes(raw, session, handle, [CKA_VALUE])
            return attrs
    finally:
        if override:
            return {}
    return None
"""

    assert _kinds(source) == ["taint_escape"]


@pytest.mark.parametrize(
    "imports, call",
    [
        (
            "from pkcs11_check.classification import fail_as",
            'fail_as("accepted_invalid", label="missing")',
        ),
        (
            "import pkcs11_check.classification as classification",
            'classification.xfail_as("not_operational", label="missing")',
        ),
        (
            "from pkcs11_check.classification import xfail_as as stop",
            'stop("not_operational", label="missing")',
        ),
    ],
)
def test_resolved_terminal_classification_helpers_make_missing_branch_structured(
    imports: str, call: str
) -> None:
    source = f"""
{imports}
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        {call}
    return attrs[CKA_VALUE]
"""

    assert _violations(source) == []


def test_both_terminal_classification_branches_make_join_unreachable() -> None:
    source = """
from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        fail_as("accepted_invalid", label="missing")
    else:
        xfail_as("not_operational", label="present")
    return attrs[CKA_VALUE]
"""

    assert _violations(source) == []


def test_shadowed_fail_as_returning_function_is_not_terminal() -> None:
    source = """
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes

def fail_as(*args, **kwargs):
    return None

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        fail_as("accepted_invalid", label="missing")
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_assert_correct_is_not_a_terminal_summary() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        assert_correct(actual=None, expected=b"value", label="missing")
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


@pytest.mark.parametrize(
    "guarded, expected",
    [
        (True, []),
        (False, ["unstructured_absence"]),
    ],
)
def test_optional_value_materializes_through_local_helper(
    guarded: bool, expected: list[str]
) -> None:
    guard = (
        "if value is not MISSING_ATTRIBUTE:\n        consume(value)"
        if guarded
        else "consume(value)"
    )
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def consume(value):
    unknown(value)

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    {guard}
"""

    assert _kinds(source) == expected


@pytest.mark.parametrize(
    "guarded, expected",
    [
        (True, []),
        (False, ["unstructured_absence"]),
    ],
)
def test_optional_value_materializes_through_formatted_expression(
    guarded: bool, expected: list[str]
) -> None:
    guard = (
        'if value is not MISSING_ATTRIBUTE:\n        consume(f"value={value!r}")'
        if guarded
        else 'consume(f"value={value!r}")'
    )
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    {guard}
"""

    assert _kinds(source) == expected


def test_closure_captured_reader_is_provider_tainted() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes as outer_reader

def outer(raw, session, handle):
    read_attributes = outer_reader

    def inner():
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    return inner()
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_closure_shadowed_reader_stays_clean() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes as outer_reader

def outer(raw, session, handle):
    read_attributes = outer_reader

    def inner():
        def read_attributes(raw, session, handle, names):
            return {name: None for name in names}

        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    return inner()
"""

    assert _violations(source) == []


@pytest.mark.parametrize("guarded_alias", ["a", "b"])
def test_optional_presence_proof_isolated_between_aliases(guarded_alias: str) -> None:
    other = "b" if guarded_alias == "a" else "a"
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE, CKA_LABEL])
    a = attr_or_record(attrs, CKA_VALUE, label="value")
    b = attr_or_record(attrs, CKA_LABEL, label="label")
    if {guarded_alias} is not MISSING_ATTRIBUTE:
        consume({guarded_alias}, {other})
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_finally_mixed_override_keeps_tainted_and_clean_return_summaries() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def wrapper(raw, session, handle, override):
    try:
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs
    finally:
        if override:
            return {}

def check(raw, session, handle, override):
    attrs = wrapper(raw, session, handle, override)
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_loop_widening_preserves_optional_values_across_more_than_eight_shifts() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import attr_or_record

def check(raw, session, handle):
    value = attr_or_record({}, CKA_VALUE, label="value")
    first = value
    second = {}
    third = {}
    fourth = {}
    fifth = {}
    sixth = {}
    seventh = {}
    eighth = {}
    ninth = {}
    tenth = {}
    for _ in range(20):
        tenth = ninth
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    return tenth
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_loop_widening_preserves_callable_mapping_and_elements() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def consume(attrs):
    return attrs[CKA_VALUE]

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    callback = consume
    first = (attrs, callback)
    second = ()
    for _ in range(20):
        second = first
        first = second
    current_attrs, current_callback = second
    current_callback(current_attrs)
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_non_exhaustive_match_has_an_implicit_fallthrough_path() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, selector):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE in attrs:
        match selector:
            case 1:
                return attrs[CKA_VALUE]
    return None
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_nested_optional_definition_is_not_evidence_for_outer_helper() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def trust_or_default(attrs):
    if CKA_TRUST_XXX not in attrs:
        return CKT_TRUST_UNKNOWN
    def decoy():
        return attrs[CKA_TRUST_XXX]
    return None

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_TRUST_XXX])
    return trust_or_default(attrs)
"""

    assert _kinds(
        source,
        reviewed_optional_helpers={"trust_or_default"},
        optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
    ) == ["unstructured_absence"]


def test_nested_negative_definition_is_not_evidence_for_outer_oracle() -> None:
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def emit(*args, **kwargs):
    return None

def absent_is_ok(attrs):
    if CKA_VALUE in attrs:
        emit("self_contradiction", kind="metadata", detail="CKA_VALUE was present")
        def decoy():
            record_as("self_contradiction", kind="metadata", detail="CKA_VALUE was present")
            return False
        return False
    return True

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    return absent_is_ok(attrs)
"""

    assert _kinds(source, reviewed_negative_oracles={"absent_is_ok"}) == ["unstructured_absence"]


def test_finally_override_does_not_prove_reviewed_optional_default() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def trust_or_default(attrs):
    if CKA_TRUST_XXX not in attrs:
        try:
            return CKT_TRUST_UNKNOWN
        finally:
            return None
    return attrs[CKA_TRUST_XXX]

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_TRUST_XXX])
    return trust_or_default(attrs)
"""

    assert _kinds(
        source,
        reviewed_optional_helpers={"trust_or_default"},
        optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
    ) == ["unstructured_absence"]


def test_presence_or_requires_same_evaluated_mapping_object() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def get_attrs(raw, session, handle):
    return read_attributes(raw, session, handle, [CKA_VALUE])

def check(raw, session, handle):
    if CKA_VALUE not in get_attrs(raw, session, handle) or get_attrs(
        raw, session, handle
    )[CKA_VALUE]:
        return None
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_presence_or_requires_same_stable_key_expression() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def key_factory():
    return CKA_VALUE

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if key_factory() not in attrs or attrs[key_factory()]:
        return None
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_loop_widening_keeps_optional_tuple_elements_with_unrelated_tuple_width() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import attr_or_record

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    value = attr_or_record(attrs, CKA_VALUE, label="value")
    first = ((value, b""), b"")
    second = ()
    third = ()
    fourth = ()
    fifth = ()
    sixth = ()
    seventh = ()
    eighth = ()
    ninth = ()
    tenth = ()
    unrelated = (None,)
    for _ in range(20):
        tenth = ninth
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
        unused, = unrelated
    (current, _), _ = tenth
    return current + b"x"
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_loop_widening_does_not_pollute_unknown_callback_with_unrelated_callable() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.testcases._attribute_values import attr_or_record

def safe(attrs):
    return None

def check(raw, session, handle, callback):
    known = safe
    cb1 = callback
    cb2 = None
    first = attr_or_record({}, CKA_VALUE, label="value")
    second = None
    third = None
    fourth = None
    fifth = None
    sixth = None
    seventh = None
    eighth = None
    ninth = None
    tenth = None
    for _ in range(20):
        tenth = ninth
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
        cb2 = cb1
    current = cb2
    current(read_attributes(raw, session, handle, [CKA_VALUE]))
"""

    assert _kinds(source) == ["taint_escape"]


def test_loop_widening_applies_tuple_construction_to_delayed_optional_input() -> None:
    source = """
from pkcs11_check.testcases._attribute_values import attr_or_record

def check():
    first = attr_or_record({}, CKA_VALUE, label="value")
    second = None
    third = None
    fourth = None
    fifth = None
    sixth = None
    seventh = None
    eighth = None
    ninth = None
    tenth = ()
    for _ in range(20):
        tenth = (ninth,)
        ninth = eighth
        eighth = seventh
        seventh = sixth
        sixth = fifth
        fifth = fourth
        fourth = third
        third = second
        second = first
    current, = tenth
    return current + b"x"
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_mixed_tuple_widths_preserve_nested_optional_elements() -> None:
    source = """
from pkcs11_check.testcases._attribute_values import attr_or_record

def check(condition):
    value = attr_or_record({}, CKA_VALUE, label="value")
    selected = (b"", (b"", value)) if condition else (b"", (b"",))
    _, (_, current) = selected
    return current + b"x"
"""

    assert _kinds(source) == ["unstructured_absence"]


@pytest.mark.parametrize(
    "absence_body",
    [
        "match selector:\n    case 1:\n        return None\nreturn CKT_TRUST_UNKNOWN",
        "try:\n    return CKT_TRUST_UNKNOWN\nfinally:\n"
        "    match selector:\n        case 1:\n            return None",
        "for item in selector:\n    return None\nreturn CKT_TRUST_UNKNOWN",
        "try:\n    return CKT_TRUST_UNKNOWN\nfinally:\n"
        "    for item in selector:\n        return None",
        "for item in selector:\n    match item:\n        case 1:\n"
        "            return None\nreturn CKT_TRUST_UNKNOWN",
    ],
    ids=["match", "finally-match", "loop", "finally-loop", "loop-match"],
)
@pytest.mark.parametrize(
    ("branch_value", "expected_kinds"),
    [("None", ["unstructured_absence"]), ("CKT_TRUST_UNKNOWN", [])],
    ids=["wrong-return", "reviewed-return"],
)
def test_optional_default_proof_checks_explicit_match_and_loop_returns(
    absence_body: str, branch_value: str, expected_kinds: list[str]
) -> None:
    absence_body = absence_body.replace("return None", f"return {branch_value}")
    indented_body = "\n".join(f"        {line}" for line in absence_body.splitlines())
    source = f"""
from pkcs11_check.raw.recipes import read_attributes

def trust_or_default(attrs, selector):
    if CKA_TRUST_XXX not in attrs:
{indented_body}
    return attrs[CKA_TRUST_XXX]

def check(raw, session, handle, selector):
    attrs = read_attributes(raw, session, handle, [CKA_TRUST_XXX])
    return trust_or_default(attrs, selector)
"""

    assert (
        _kinds(
            source,
            reviewed_optional_helpers={"trust_or_default"},
            optional_defaults={"CKA_TRUST_XXX": "CKT_TRUST_UNKNOWN"},
        )
        == expected_kinds
    )


def test_nested_mapping_union_does_not_recover_one_alternative_identity() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, choose_first, choose_selected):
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = read_attributes(raw, session, handle, [CKA_VALUE])
    selected = first if choose_first else second
    combined = selected if choose_selected else first
    if CKA_VALUE not in combined or first[CKA_VALUE]:
        return None
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_mapping_union_membership_does_not_prove_each_origin_present() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, choose_first):
    first = read_attributes(raw, session, handle, [CKA_VALUE])
    second = read_attributes(raw, session, handle, [CKA_VALUE])
    selected = first if choose_first else second
    if CKA_VALUE not in selected or first[CKA_VALUE]:
        return None
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_conditional_boolean_terminal_call_keeps_fallthrough_live() -> None:
    source = """
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    condition and fail_as("accepted_invalid", label="conditional")
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


@pytest.mark.parametrize(
    "assignment",
    [
        'result = fail_as("accepted_invalid", label="assignment")',
        'result: object = fail_as("accepted_invalid", label="annotation")',
    ],
)
def test_definitely_terminal_assignment_stops_following_flow(assignment: str) -> None:
    source = f"""
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    {assignment}
    return attrs[CKA_VALUE]
"""

    assert _violations(source) == []


def test_conditional_only_terminal_with_silent_return_is_unstructured() -> None:
    source = """
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        if condition:
            fail_as("accepted_invalid", label="conditional")
        return None
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_local_returning_helper_does_not_count_as_terminal_absence_evidence() -> None:
    source = """
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes

def benign(*args, **kwargs):
    return None

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        benign("accepted_invalid", label="missing")
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_shadowed_terminal_name_with_silent_return_is_unstructured() -> None:
    source = """
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes

def fail_as(*args, **kwargs):
    return None

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        fail_as("accepted_invalid", label="shadowed")
        return None
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence"]


def test_terminal_assignment_does_not_use_boolean_or_taint() -> None:
    source = """
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    result = condition and fail_as("accepted_invalid", label="conditional")
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_terminal_wrapper_summary_requires_every_path_to_terminate() -> None:
    source = """
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes

def maybe_stop(condition):
    if condition:
        fail_as("accepted_invalid", label="conditional")
    return None

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        maybe_stop(condition)
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


def test_recursive_terminal_wrapper_does_not_gain_terminal_summary() -> None:
    source = """
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import read_attributes

def recursive(condition):
    if condition:
        fail_as("accepted_invalid", label="terminal")
    return recursive(condition)

def check(raw, session, handle, condition):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        recursive(condition)
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unstructured_absence", "unsafe_subscript"]


@pytest.mark.parametrize(
    "rebinding",
    [
        "reader = benign\n    reader = provider_reader",
        "reader = provider_reader\n    reader = benign",
    ],
    ids=["benign-then-provider", "provider-then-benign"],
)
def test_returned_closure_uses_lexical_cell_rebinding(rebinding: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes as provider_reader

def benign(raw, session, handle, names):
    return {{name: None for name in names}}

def factory(raw, session, handle):
    reader = benign

    def inner():
        attrs = reader(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    {rebinding}
    return inner

def check(raw, session, handle):
    helper = factory(raw, session, handle)
    return helper()
"""

    expected = ["unsafe_subscript"] if "provider_reader" in rebinding.splitlines()[-1] else []
    assert _kinds(source) == expected


def test_joined_same_nested_provider_closures_keep_provider_state() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes as provider_reader

def factory(raw, session, handle):
    reader = provider_reader

    def inner():
        attrs = reader(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    return inner

def check(raw, session, handle, condition):
    first = factory(raw, session, handle)
    second = factory(raw, session, handle)
    helper = first if condition else second
    return helper()
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_joined_same_nested_benign_closures_ignore_caller_shadow() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes as provider_reader

def benign(raw, session, handle, names):
    return {name: None for name in names}

def factory(raw, session, handle):
    read_attributes = benign

    def inner():
        attrs = read_attributes(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    return inner

def check(raw, session, handle, condition):
    read_attributes = provider_reader
    first = factory(raw, session, handle)
    second = factory(raw, session, handle)
    helper = first if condition else second
    return helper()
"""

    assert _violations(source) == []


def test_distinct_benign_closures_do_not_cross_pair_callable_state() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes as provider_reader

def benign(raw, session, handle, names):
    return {name: None for name in names}

def factory_a(raw, session, handle):
    reader_a = benign
    reader_b = provider_reader

    def inner_a():
        attrs = reader_a(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    return inner_a

def factory_b(raw, session, handle):
    reader_a = provider_reader
    reader_b = benign

    def inner_b():
        attrs = reader_b(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    return inner_b

def check(raw, session, handle, condition):
    first = factory_a(raw, session, handle)
    second = factory_b(raw, session, handle)
    helper = first if condition else second
    return helper()
"""

    assert _violations(source) == []


def test_distinct_callable_closure_pairing_keeps_only_correct_unsafe_path() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes as provider_reader

def benign(raw, session, handle, names):
    return {name: None for name in names}

def factory_a(raw, session, handle):
    reader_a = benign
    reader_b = provider_reader

    def inner_a():
        attrs = reader_a(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    return inner_a

def factory_b(raw, session, handle):
    reader_a = provider_reader
    reader_b = provider_reader

    def inner_b():
        attrs = reader_b(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    return inner_b

def check(raw, session, handle, condition):
    first = factory_a(raw, session, handle)
    second = factory_b(raw, session, handle)
    helper = first if condition else second
    return helper()
"""

    violations = _violations(source)
    assert [violation.kind for violation in violations] == ["unsafe_subscript"]
    assert violations[0].line == 23


def test_same_name_branch_closures_keep_benign_reader_pairing() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes as provider_reader

def benign(raw, session, handle, names):
    return {name: None for name in names}

def factory(raw, session, handle, condition):
    if condition:
        reader_a = benign
        reader_b = provider_reader
        def inner():
            attrs = reader_a(raw, session, handle, [CKA_VALUE])
            return attrs[CKA_VALUE]
        return inner
    else:
        reader_a = provider_reader
        reader_b = benign
        def inner():
            attrs = reader_b(raw, session, handle, [CKA_VALUE])
            return attrs[CKA_VALUE]
        return inner

def check(raw, session, handle, condition):
    helper = factory(raw, session, handle, condition)
    return helper()
"""

    assert _violations(source) == []


@pytest.mark.parametrize("provider_first", [True, False], ids=["first", "last"])
def test_same_name_branch_closures_retain_the_provider_definition(provider_first: bool) -> None:
    first_reader, second_reader = (
        ("provider_reader", "benign") if provider_first else ("benign", "provider_reader")
    )
    source = f"""
from pkcs11_check.raw.recipes import read_attributes as provider_reader

def benign(raw, session, handle, names):
    return {{name: None for name in names}}

def factory(raw, session, handle, condition):
    if condition:
        reader_a = {first_reader}
        reader_b = benign
        def inner():
            attrs = reader_a(raw, session, handle, [CKA_VALUE])
            return attrs[CKA_VALUE]
        return inner
    else:
        reader_a = benign
        reader_b = {second_reader}
        def inner():
            attrs = reader_b(raw, session, handle, [CKA_VALUE])
            return attrs[CKA_VALUE]
        return inner

def check(raw, session, handle, condition):
    helper = factory(raw, session, handle, condition)
    return helper()
"""

    violations = _violations(source)
    assert [violation.kind for violation in violations] == ["unsafe_subscript"]
    assert violations[0].line == (13 if provider_first else 20)


def test_unknown_callable_join_does_not_fall_back_to_one_known_closure() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes as provider_reader

def benign(raw, session, handle, names):
    return {name: None for name in names}

def check(raw, session, handle, condition):
    helper = benign if condition else None
    attrs = helper(raw, session, handle, [CKA_VALUE])
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


@pytest.mark.parametrize("provider_last", [True, False], ids=["last", "first"])
def test_same_function_closure_join_widens_past_eight_alternatives(
    provider_last: bool,
) -> None:
    readers = [
        "provider_reader" if (index == 8) == provider_last else "benign" for index in range(9)
    ]
    assignments = [
        f"    closure_{index} = factory({reader})" for index, reader in enumerate(readers)
    ]
    helper = "closure_0"
    for index in range(1, 9):
        helper = f"{helper} if condition_{index} else closure_{index}"
    source = f"""
from pkcs11_check.raw.recipes import read_attributes as provider_reader

def benign(raw, session, handle, names):
    return {{name: None for name in names}}

def factory(reader):
    def inner():
        attrs = reader(raw, session, handle, [CKA_VALUE])
        return attrs[CKA_VALUE]

    return inner

def check(raw, session, handle, {", ".join(f"condition_{index}" for index in range(1, 9))}):
{chr(10).join(assignments)}
    helper = {helper}
    return helper()
"""

    assert _kinds(source) == ["unsafe_subscript"]


def test_helper_alias_inventory_rejects_helper_reaching_nested_alternative() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

import pkcs11_check.testcases._probes._attribute_facts as facts

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]

def unrelated_scope():
    import json as facts
    return facts._attribute_facts.emit_missing_attribute
"""

    assert "child_evidence_contract" in _kinds(source)


def test_nested_local_parameter_bindings_do_not_invalidate_outer_certificate() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    def unused(CKA_MODULUS, attrs, read_attributes):
        return CKA_MODULUS, attrs, read_attributes
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


def test_unrelated_module_alias_use_does_not_become_contract_reference() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS
import json as j
import pkcs11_check.testcases._probes.session as sibling

def consume(value):
    return value

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return consume(j), consume(sibling), attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


def test_helper_free_reflection_remains_baseline_clean() -> None:
    source = """
def check(obj, name):
    return getattr(obj, name, None), obj.__class__
"""

    assert _violations(source) == []


def test_direct_module_helper_use_activates_without_candidate() -> None:
    source = """
import pkcs11_check.testcases._probes._attribute_facts as facts

def check(attribute):
    return facts.emit_missing_attribute(
        attribute, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random"
    )
"""

    assert "child_evidence_contract" in _kinds(source)


def test_noncanonical_helper_import_activates_without_candidate() -> None:
    source = """
from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute as emit

def check(attribute):
    return emit(attribute, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
"""

    assert "child_evidence_contract" in _kinds(source)


def test_canonical_helper_import_without_candidate_activates_contract() -> None:
    source = """
from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute

def check(attribute):
    return attribute
"""

    assert "child_evidence_contract" in _kinds(source)


def test_canonical_reader_and_key_comparison_do_not_activate_contract() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, attrs):
    if CKA_MODULUS in attrs:
        read_attributes(raw, session, handle, [CKA_MODULUS])
    return None
"""

    assert _violations(source) == []


def test_ordinary_reflection_keeps_canonical_certificate_behavior() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, obj):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    getattr(obj, "unrelated", None)
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


def test_module_wide_global_binder_invalidates_key_ownership() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def writer():
    global CKA_MODULUS
    CKA_MODULUS = 1

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    assert "child_evidence_contract" in _kinds(source)
    assert "unstructured_absence" in _kinds(source)


def test_nested_local_binders_do_not_invalidate_outer_key_or_context() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def local(CKA_MODULUS, case):
        return CKA_MODULUS, case
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


def test_helper_free_self_alias_analysis_is_bounded() -> None:
    """A helper-free self-alias must terminate without unbounded path growth."""
    source = """
import pkcs11_check.raw.recipes as reader
reader = reader.read_attributes
"""
    code = (
        "from tests._attribute_access_guard import analyze_source\n"
        f"print(analyze_source({source!r}, path='synthetic.py'))\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        check=True,
        text=True,
        encoding="utf-8",
        timeout=2,
    )

    assert completed.stdout.strip() == "[]"


@pytest.mark.parametrize(
    "branch",
    [
        """if condition:
    nonlocal case
    case = 'mutated'""",
        """try:
    nonlocal case
    case = 'mutated'
except ValueError:
    pass""",
        """match condition:
    case True:
        nonlocal case
        case = 'mutated'""",
    ],
    ids=["if", "try", "match"],
)
def test_nested_nonlocal_context_writer_in_compound_block_rejects_certificate(
    branch: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case, condition):
    def writer():
{textwrap.indent(textwrap.dedent(branch), "        ")}
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


def test_nested_global_writer_does_not_invalidate_outer_context() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case, condition):
    def writer():
        if condition:
            global case
            case = 'mutated'
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


@pytest.mark.parametrize(
    "binder",
    [
        "from another_module import CKA_MODULUS",
        "def CKA_MODULUS():\n        return None",
        "class CKA_MODULUS:\n        pass",
        "try:\n        pass\n    except Exception as CKA_MODULUS:\n        pass",
        "match object():\n        case CKA_MODULUS:\n            pass",
        "CKA_MODULUS = object()",
        "del CKA_MODULUS",
        "global CKA_MODULUS\n    CKA_MODULUS = object()",
    ],
    ids=["import", "function", "class", "exception", "match", "assignment", "delete", "global"],
)
def test_rsa_candidate_key_binders_retain_diagnostics(binder: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    {binder}
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


@pytest.mark.parametrize(
    "binder",
    [
        "from another_module import case",
        "def case():\n        return None",
        "class case:\n        pass",
        "try:\n        pass\n    except Exception as case:\n        pass",
        "match object():\n        case case:\n            pass",
        "case = 'bad'",
        "del case",
        "global case\n    case = 'bad'",
    ],
    ids=["import", "function", "class", "exception", "match", "assignment", "delete", "global"],
)
def test_rsa_candidate_context_binders_retain_diagnostics(binder: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    {binder}
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


def test_module_wide_nonlocal_binder_invalidates_key_ownership() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def outer():
    CKA_MODULUS = 1
    def writer():
        nonlocal CKA_MODULUS
        CKA_MODULUS = 2
    return writer

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random")
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


def _ec_pair_source(pair: str, *, read: str = "[CKA_EC_POINT, CKA_EC_PARAMS]") -> str:
    return f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_EC_PARAMS

def check(raw, sh, handle):
    attrs = read_attributes(raw, sh, handle, {read})
    from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute
    {pair}
    return point_value, params_value
"""


def test_canonical_ec_observer_pair_filters_only_observer_taint() -> None:
    source = _ec_pair_source(
        'point_value = observe_ec_attribute(attrs, CKA_EC_POINT, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '")\n'
        '    params_value = observe_ec_attribute(attrs, CKA_EC_PARAMS, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '")'
    )

    assert _violations(source) == []


def test_canonical_ec_observer_pair_try_reader_is_not_an_admitted_proof() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_EC_PARAMS

def check(raw, sh, handle):
    try:
        attrs = read_attributes(raw, sh, handle, [CKA_EC_POINT, CKA_EC_PARAMS])
    except LookupError:
        return None
    from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute
    point = observe_ec_attribute(
        attrs, CKA_EC_POINT, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    )
    params = observe_ec_attribute(
        attrs, CKA_EC_PARAMS, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    )
    return point, params
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds


@pytest.mark.parametrize(
    "pair",
    [
        'params_value = observe_ec_attribute(attrs, CKA_EC_PARAMS, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '")\n'
        '    point_value = observe_ec_attribute(attrs, CKA_EC_POINT, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '")',
        'point_value = observe_ec_attribute(attrs, CKA_EC_POINT, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '")\n'
        "    marker = object()\n"
        '    params_value = observe_ec_attribute(attrs, CKA_EC_PARAMS, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '")',
        "point_value = observe_ec_attribute(attrs, CKA_EC_POINT, context=case)\n"
        '    params_value = observe_ec_attribute(attrs, CKA_EC_PARAMS, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '")',
        'point_value = observe_ec_attribute(attrs, CKA_EC_POINT, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '", extra=True)\n'
        '    params_value = observe_ec_attribute(attrs, CKA_EC_PARAMS, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '")',
        'point_value = observe_ec_attribute(attrs, CKA_EC_POINT, context="'
        + "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        + '")',
    ],
    ids=["reversed", "intervening", "dynamic-context", "extra-keyword", "partial"],
)
def test_malformed_ec_observer_pair_retains_taint_and_contract(pair: str) -> None:
    source = _ec_pair_source(pair)
    kinds = _kinds(source)

    assert "child_evidence_contract" in kinds
    assert "taint_escape" in kinds


def test_scalar_ec_missing_evidence_is_not_a_pair_substitute() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_POINT

def check(raw, sh, handle):
    attrs = read_attributes(raw, sh, handle, [CKA_EC_POINT, CKA_EC_PARAMS])
    if CKA_EC_POINT not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(
            CKA_EC_POINT,
            protocol="EC_SETUP",
            context="ecdh_aes_wrap_compressed_public_key_buffer_too_small",
        )
        return
    return attrs[CKA_EC_POINT]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


@pytest.mark.parametrize(
    "reader_defect",
    [
        "def check(raw, sh, handle, read_attributes):",
        "    read_attributes = other_reader",
        "    def read_attributes(*args):\n        return {}",
        "    from another_module import read_attributes",
        "    global read_attributes",
        "        nonlocal read_attributes",
    ],
    ids=["parameter", "assignment", "definition", "import", "global", "nonlocal"],
)
def test_ec_observer_pair_reuses_scalar_reader_ownership_proof(reader_defect: str) -> None:
    if reader_defect.startswith("def check"):
        source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_EC_PARAMS

{reader_defect}
    attrs = read_attributes(raw, sh, handle, [CKA_EC_POINT, CKA_EC_PARAMS])
    from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute
    point = observe_ec_attribute(
        attrs, CKA_EC_POINT, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    )
    params = observe_ec_attribute(
        attrs, CKA_EC_PARAMS, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    )
    return point, params
"""
    elif reader_defect.startswith("        nonlocal"):
        source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_EC_PARAMS

def outer():
    read_attributes = other_reader
    def check(raw, sh, handle):
{reader_defect}
        attrs = read_attributes(raw, sh, handle, [CKA_EC_POINT, CKA_EC_PARAMS])
        from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute
        point = observe_ec_attribute(
            attrs, CKA_EC_POINT, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        )
        params = observe_ec_attribute(
            attrs, CKA_EC_PARAMS, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
        )
        return point, params
    return check
"""
    else:
        source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_EC_PARAMS

def other_reader(*args):
    return {{}}

def check(raw, sh, handle):
{reader_defect}
    attrs = read_attributes(raw, sh, handle, [CKA_EC_POINT, CKA_EC_PARAMS])
    from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute
    point = observe_ec_attribute(
        attrs, CKA_EC_POINT, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    )
    params = observe_ec_attribute(
        attrs, CKA_EC_PARAMS, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    )
    return point, params
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds


def test_ec_observer_pair_map_name_cannot_conflict_with_reader() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_EC_PARAMS

def check(raw, sh, handle):
    read_attributes = read_attributes(raw, sh, handle, [CKA_EC_POINT, CKA_EC_PARAMS])
    from pkcs11_check.testcases._probes._attribute_facts import observe_ec_attribute
    point = observe_ec_attribute(
        read_attributes,
        CKA_EC_POINT,
        context="ecdh_aes_wrap_compressed_public_key_buffer_too_small",
    )
    params = observe_ec_attribute(
        read_attributes,
        CKA_EC_PARAMS,
        context="ecdh_aes_wrap_compressed_public_key_buffer_too_small",
    )
    return point, params
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds


def test_testcases_parent_alias_direct_helper_activates_contract() -> None:
    source = """
from pkcs11_check import testcases as tc
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        tc._probes._attribute_facts.emit_missing_attribute(
            CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random"
        )
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


def test_probe_alias_assignment_direct_helper_activates_contract() -> None:
    source = """
import pkcs11_check.testcases._probes as probes
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

facts = probes._attribute_facts

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        facts.emit_missing_attribute(
            CKA_MODULUS, protocol="RSA_ATTRIBUTE", context="decrypt:pkcs:random"
        )
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


def test_probe_alias_assignment_module_reference_activates_contract() -> None:
    source = """
import pkcs11_check.testcases._probes as probes

facts = probes._attribute_facts
"""

    assert "child_evidence_contract" in _kinds(source)


def test_testcases_parent_alias_direct_observer_activates_contract() -> None:
    source = """
from pkcs11_check import testcases as tc
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_EC_PARAMS

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_EC_POINT, CKA_EC_PARAMS])
    point = tc._probes._attribute_facts.observe_ec_attribute(
        attrs, CKA_EC_POINT, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    )
    params = tc._probes._attribute_facts.observe_ec_attribute(
        attrs, CKA_EC_PARAMS, context="ecdh_aes_wrap_compressed_public_key_buffer_too_small"
    )
    return point, params
"""

    assert "child_evidence_contract" in _kinds(source)


def test_rsa_context_parameter_ignores_unrelated_module_case_binding() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

case = "module value"

def check(raw, session, handle, case):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


def test_rsa_context_parameter_ignores_unrelated_closure_nonlocal_case() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def unrelated():
    case = "unrelated"
    def writer():
        nonlocal case
        case = "changed"
    return writer

def check(raw, session, handle, case):
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


def test_rsa_context_nested_nonlocal_targeting_candidate_remains_rejected() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def writer():
        nonlocal case
        case = "changed"
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


def test_rsa_context_nested_nonlocal_shadow_cell_does_not_reject_candidate() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def outer():
        case = "shadow"
        def writer():
            nonlocal case
            case = "changed"
        return writer
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert _violations(source) == []


def test_rsa_context_nested_class_shadow_cell_does_not_reject_candidate() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def outer():
        case = "shadow"
        class Nested:
            nonlocal case
            case = "changed"
        return Nested
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert analyze_source(source) == []


@pytest.mark.parametrize(
    "intervening",
    [
        "unused = (case for case in ())",
        'unused = lambda: (case := "shadow")',
    ],
    ids=["generator", "lambda"],
)
def test_rsa_context_nested_nonlocal_ignores_inner_comprehension_and_lambda_binders(
    intervening: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def outer():
        {intervening}
        def writer():
            nonlocal case
            case = "changed"
        return writer
    outer()()
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


@pytest.mark.parametrize(
    "intervening",
    [
        'unused = lambda arg=(case := "shadow"): arg',
        'unused = [(case := "shadow") for _ in ()]',
        'unused = {(case := "shadow") for _ in ()}',
        'unused = {_: (case := "shadow") for _ in ()}',
        'unused = (case := "shadow" for _ in ())',
        'unused = [(lambda arg=(case := "shadow"): arg) for _ in ()]',
        'unused = (lambda arg=(case := "shadow"): arg for _ in ())',
    ],
    ids=[
        "lambda-default",
        "list-walrus",
        "set-walrus",
        "dict-walrus",
        "generator-walrus",
        "list-lambda-default-walrus",
        "generator-lambda-default-walrus",
    ],
)
def test_rsa_context_nested_nonlocal_respects_enclosing_walrus_binders(
    intervening: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def outer():
        {intervening}
        def writer():
            nonlocal case
            case = "changed"
        return writer
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert analyze_source(source) == []


@pytest.mark.parametrize(
    "intervening",
    [
        'unused = [lambda: (case := "shadow") for _ in ()]',
        'unused = lambda arg=(lambda: (case := "shadow")): arg',
    ],
    ids=["lambda-body-in-comprehension", "lambda-body-in-default"],
)
def test_rsa_context_nested_nonlocal_rejects_nested_lambda_binders(
    intervening: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def outer():
        {intervening}
        def writer():
            nonlocal case
            case = "changed"
        return writer
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


@pytest.mark.parametrize(
    "intervening",
    [
        "unused = [case for case in ()]",
        "unused = {case for case in ()}",
        "unused = {case: case for case in ()}",
    ],
    ids=["list-target", "set-target", "dict-target"],
)
def test_rsa_context_nested_nonlocal_respects_inlined_comprehension_cell(
    intervening: str,
) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def outer():
        {intervening}
        def writer():
            nonlocal case
            case = "changed"
        return writer
    outer()()
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert analyze_source(source) == []


@pytest.mark.parametrize(
    "intervening",
    [
        "unused = [case for case in ()]",
        "unused = {case for case in ()}",
        "unused = {case: case for case in ()}",
        "unused = (case for case in ())",
    ],
    ids=["list-target", "set-target", "dict-target", "generator-target"],
)
def test_rsa_context_nested_nonlocal_with_load_targets_candidate(intervening: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    def outer():
        before = case
        {intervening}
        def writer():
            nonlocal case
            case = "changed"
        return writer
    outer()()
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds


@pytest.mark.parametrize(
    "intervening",
    [
        "unused = [case for case in ()]",
        "unused = {case for case in ()}",
        "unused = {case: case for case in ()}",
        "unused = (case for case in ())",
        'class Nested:\n        case = "shadow"',
        "unused = lambda case: case",
        'unused = lambda: (case := "shadow")',
    ],
    ids=["list", "set", "dict", "generator", "class", "lambda-parameter", "lambda-body"],
)
def test_rsa_context_direct_nested_binders_do_not_mutate_parameter(intervening: str) -> None:
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def check(raw, session, handle, case):
    {intervening}
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    assert analyze_source(source) == []


def test_strict_compiler_syntax_error_preserves_baseline_findings() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

def unrelated():
    nonlocal unresolved

def check(raw, session, handle, case):
    unsafe = read_attributes(raw, session, handle, [CKA_MODULUS]).get(CKA_MODULUS)
    attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
    if CKA_MODULUS not in attrs:
        from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
        emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
        return
    return attrs[CKA_MODULUS]
"""

    violations = analyze_source(source)
    kinds = [violation.code for violation in violations]
    assert "unsafe_get" in kinds
    assert "unstructured_absence" in kinds
    assert "child_evidence_contract" in kinds
    assert "syntax_error" not in kinds
    assert any(
        violation.code == "child_evidence_contract" and violation.line == 11
        for violation in violations
    )


def test_helper_free_source_has_no_semantic_compiler_gate() -> None:
    source = """
from pkcs11_check.raw.recipes import read_attributes

def unrelated():
    nonlocal unresolved

def check(raw, session, handle):
    return read_attributes(raw, session, handle, [CKA_MODULUS]).get(CKA_MODULUS)
"""

    assert _kinds(source) == ["unsafe_get"]


@pytest.mark.parametrize("declaration", ["global case", "nonlocal case"])
def test_rsa_context_outward_declaration_in_candidate_retain_diagnostics(
    declaration: str,
) -> None:
    prefix = "" if declaration.startswith("global") else "def outer():\n    case = 'outer'\n\n    "
    indent = "    " if declaration.startswith("global") else "        "
    source = f"""
from pkcs11_check.raw.recipes import read_attributes
from pkcs11_check.raw.types_std import CKA_MODULUS

{prefix}def check(raw, session, handle, case):
{indent}{declaration}
{indent}attrs = read_attributes(raw, session, handle, [CKA_MODULUS])
{indent}if CKA_MODULUS not in attrs:
{indent}    from pkcs11_check.testcases._probes._attribute_facts import emit_missing_attribute
{indent}    emit_missing_attribute(CKA_MODULUS, protocol="RSA_ATTRIBUTE", context=case)
{indent}    return
{indent}return attrs[CKA_MODULUS]
"""

    kinds = _kinds(source)
    assert "child_evidence_contract" in kinds
    assert "unstructured_absence" in kinds
