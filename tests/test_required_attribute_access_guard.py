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
