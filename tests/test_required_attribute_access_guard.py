"""Synthetic contract tests for the provider-attribute access prevention guard."""

from __future__ import annotations

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
    source = """
from pkcs11_check.classification import record_as
from pkcs11_check.raw.recipes import read_attributes

def check(raw, session, handle):
    attrs = read_attributes(raw, session, handle, [CKA_VALUE])
    if CKA_VALUE not in attrs:
        record_as("honest_deviation", operation="C_GetAttributeValue", detail="CKA_VALUE")
    return attrs[CKA_VALUE]
"""

    assert _kinds(source) == ["unsafe_subscript"]


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
