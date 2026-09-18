"""Fail-closed tests for the readback-attribution effective-emitter inventory."""

from __future__ import annotations

import ast
import subprocess
from collections.abc import Iterator
from pathlib import Path
from textwrap import dedent

import pytest

from pkcs11_check import classification as classification_module
from tests._git_guard import requires_git_tracked_files
from tests._readback_attribution_inventory import (
    _CLASSIFICATION_NON_EMITTERS,
    _EMITTERS,
    C_GET_ATTRIBUTE_VALUE,
    FALSE_VALUE,
    GATE_EXCLUDED,
    GATE_GROUPING,
    GATE_REJECT,
    GATE_SAFE,
    NONE_VALUE,
    STATUS_EXPLICIT_MECHANISM_GROUPING,
    STATUS_EXPLICIT_MECHANISM_READBACK,
    STATUS_NON_READBACK,
    STATUS_SAFE_MECHANISM_FREE_READBACK,
    STATUS_UNRESOLVED,
    STATUS_UNSAFE_INHERITED_READBACK,
    TRUE_VALUE,
    UNKNOWN_OPERATION,
    CallerCoordinate,
    EffectiveState,
    EmitterFinding,
    InventoryCharacterization,
    characterize_tree,
    coordinate_census,
    corpus_digest,
    flatten_effective_states,
    format_inventory_diff,
    git_head_tree_sources,
    head_inventory_diff,
    inventory_digest,
    registered_definition_coordinates,
    scan_source,
    scan_sources,
    scan_tree,
    should_gate_readback,
)


def _scan(
    source: str,
    *,
    readback_only: bool = False,
) -> tuple[EmitterFinding, ...]:
    return scan_source(dedent(source), path="synthetic.py", readback_only=readback_only)


def _find(
    findings: tuple[EmitterFinding, ...], *, emitter: str, function: str | None = None
) -> EmitterFinding:
    matches = [finding for finding in findings if finding.emitter == emitter]
    if function is not None:
        matches = [finding for finding in matches if finding.function == function]
    assert len(matches) == 1, matches
    return matches[0]


def test_direct_emitters_distinguish_all_relational_readback_states() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def check() -> None:
            C.classify("wrong_result", operation="C_GetAttributeValue")
            C.record_as("wrong_result", operation="C_GetAttributeValue", mechanism="CKM_AES")
            C.record_as(
                "wrong_result",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
            )
            C.record_as("wrong_result", operation="C_DeriveKey", mechanism="CKM_AES")
        """
    )

    assert _find(findings, emitter="classify").status == STATUS_UNSAFE_INHERITED_READBACK
    # The two record_as sites have the same function; inspect their exact states.
    record_states = [finding.states[0] for finding in findings if finding.emitter == "record_as"]
    assert {state.status for state in record_states} == {
        STATUS_EXPLICIT_MECHANISM_READBACK,
        STATUS_SAFE_MECHANISM_FREE_READBACK,
        STATUS_EXPLICIT_MECHANISM_GROUPING,
    }
    assert any(
        finding.operations == (C_GET_ATTRIBUTE_VALUE,)
        for finding in findings
        if finding.emitter == "record_as"
    )


def test_forwarded_defaults_retain_caller_coordinate_and_effective_state() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit(
            operation: str = "C_GetAttributeValue",
            mechanism: str | None = None,
            inherit_mechanism: bool = False,
        ) -> None:
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def caller() -> None:
            emit(
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
            )
        """
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    state = finding.states[0]
    assert (state.operation, state.mechanism, state.inherit_mechanism) == (
        C_GET_ATTRIBUTE_VALUE,
        NONE_VALUE,
        FALSE_VALUE,
    )
    assert state.caller.function == "caller"
    assert state.caller.line == 17


def test_forwarded_arguments_override_helper_defaults() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit(
            operation: str = "C_GetAttributeValue",
            mechanism: str | None = None,
            inherit_mechanism: bool = False,
        ) -> None:
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def caller() -> None:
            emit(
                operation="C_DeriveKey",
                mechanism="CKM_AES",
                inherit_mechanism=True,
            )
        """
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert finding.states == (
        EffectiveState(
            operation="C_DeriveKey",
            mechanism="CKM_AES",
            inherit_mechanism=TRUE_VALUE,
            caller=CallerCoordinate("synthetic.py", 17, 4, "caller"),
            status=STATUS_EXPLICIT_MECHANISM_GROUPING,
        ),
    )


def test_comparison_operation_or_fallback_is_context_sensitive() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit(comparison_operation=None):
            C.record_as(
                "wrong_result",
                operation=comparison_operation or "C_GetAttributeValue",
            )

        def omitted() -> None:
            emit()

        def explicit() -> None:
            emit(comparison_operation="C_DeriveKey")
        """
    )

    finding = _find(findings, emitter="record_as", function="emit")
    state_by_caller = {state.caller.function: state for state in finding.states}
    assert state_by_caller["omitted"].operation == C_GET_ATTRIBUTE_VALUE
    assert state_by_caller["omitted"].status == STATUS_UNSAFE_INHERITED_READBACK
    assert state_by_caller["explicit"].operation == "C_DeriveKey"
    assert state_by_caller["explicit"].status == STATUS_NON_READBACK


def test_computed_fallback_uses_truthiness_and_does_not_add_unreachable_fallback() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification

        def truthy() -> None:
            operation = "C_DeriveKey" or "C_GetAttributeValue"
            classification.record_as("wrong_result", operation=operation)

        def falsy() -> None:
            operation = "" or "C_GetAttributeValue"
            classification.record_as("wrong_result", operation=operation)
        """
    )

    assert _find(findings, emitter="record_as", function="truthy").operations == ("C_DeriveKey",)
    assert _find(findings, emitter="record_as", function="falsy").operations == (
        C_GET_ATTRIBUTE_VALUE,
    )


def test_tuple_unpack_and_subscript_forward_operation_mechanism_and_inherit() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit(operation, mechanism, inherit_mechanism):
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def caller() -> None:
            values = ("C_GetAttributeValue", None, False)
            operation, mechanism, inherit_mechanism = values
            emit(
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )
        """
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert any(state.status == STATUS_SAFE_MECHANISM_FREE_READBACK for state in finding.states)
    assert any(state.caller.function == "caller" for state in finding.states)


def test_assert_correct_and_module_aliased_conftest_are_not_lost() -> None:
    findings = _scan(
        """
        import pkcs11_check.testcases.conftest as conftest

        def helper(operation: str | None = None) -> None:
            conftest.assert_correct(
                actual=1,
                expected=2,
                label="probe",
                operation=operation,
            )

        def direct() -> None:
            conftest.assert_correct(
                actual=1,
                expected=2,
                label="readback",
                operation="C_GetAttributeValue",
            )
        """
    )

    helper = _find(findings, emitter="assert_correct", function="helper")
    direct = _find(findings, emitter="assert_correct", function="direct")
    assert helper.status == STATUS_UNRESOLVED
    assert helper.forwarded_parameters == ("operation",)
    assert direct.status == STATUS_UNSAFE_INHERITED_READBACK


def test_self_cls_class_and_nested_sibling_edges_propagate() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        class Worker:
            def emit(self, operation="C_GetAttributeValue"):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=None,
                    inherit_mechanism=False,
                )

            def via_self(self):
                self.emit(operation="C_GetAttributeValue")

            @classmethod
            def via_cls(cls):
                cls.emit(operation="C_GetAttributeValue")

        def outer():
            def emit(operation="C_GetAttributeValue"):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=None,
                    inherit_mechanism=False,
                )

            def sibling():
                emit(operation="C_GetAttributeValue")

            sibling()
        """
    )

    worker = _find(findings, emitter="record_as", function="Worker.emit")
    nested = _find(findings, emitter="record_as", function="outer.emit")
    assert {state.caller.function for state in worker.states} == {
        "Worker.via_cls",
        "Worker.via_self",
    }
    assert {state.caller.function for state in nested.states} == {"outer.sibling"}
    assert all(state.status == STATUS_SAFE_MECHANISM_FREE_READBACK for state in worker.states)
    assert all(state.status == STATUS_SAFE_MECHANISM_FREE_READBACK for state in nested.states)


def test_descriptor_aware_positional_binding_skips_only_bound_receivers() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        class Worker:
            def instance(self, operation, mechanism=None, inherit_mechanism=False):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=mechanism,
                    inherit_mechanism=inherit_mechanism,
                )

            @classmethod
            def class_method(cls, operation, mechanism=None, inherit_mechanism=False):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=mechanism,
                    inherit_mechanism=inherit_mechanism,
                )

            @staticmethod
            def static_method(operation, mechanism=None, inherit_mechanism=False):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=mechanism,
                    inherit_mechanism=inherit_mechanism,
                )

            def call_bound(self):
                self.instance("C_GetAttributeValue", None, False)

            def call_alias(self):
                alias = self.instance
                alias("C_GetAttributeValue", None, False)

            @classmethod
            def call_class_bound(cls):
                cls.class_method("C_GetAttributeValue", None, False)

            def call_static(self):
                Worker.static_method("C_GetAttributeValue", None, False)

            def call_class_qualified(self):
                Worker.class_method("C_GetAttributeValue", None, False)
        """
    )

    for function in ("Worker.instance", "Worker.class_method", "Worker.static_method"):
        finding = _find(findings, emitter="record_as", function=function)
        assert finding.states
        assert finding.states[0].status == STATUS_SAFE_MECHANISM_FREE_READBACK
        assert finding.states[0].operation == C_GET_ATTRIBUTE_VALUE
        assert all(state.status == STATUS_SAFE_MECHANISM_FREE_READBACK for state in finding.states)
        assert all(state.operation == C_GET_ATTRIBUTE_VALUE for state in finding.states)

    class_method = _find(findings, emitter="record_as", function="Worker.class_method")
    assert {state.caller.function for state in class_method.states} == {
        "Worker.call_class_bound",
        "Worker.call_class_qualified",
    }
    instance = _find(findings, emitter="record_as", function="Worker.instance")
    assert {state.caller.function for state in instance.states} >= {
        "Worker.call_alias",
        "Worker.call_bound",
    }


def test_callable_aliases_resolve_top_level_and_nested_targets() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def top_emit(operation, mechanism=None, inherit_mechanism=False):
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        top_alias = top_emit

        def top_call():
            top_alias("C_GetAttributeValue", None, False)

        def outer():
            def nested_emit(operation, mechanism=None, inherit_mechanism=False):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=mechanism,
                    inherit_mechanism=inherit_mechanism,
                )

            nested_alias = nested_emit
            nested_alias("C_GetAttributeValue", None, False)
        """
    )

    top = _find(findings, emitter="record_as", function="top_emit")
    nested = _find(findings, emitter="record_as", function="outer.nested_emit")
    assert top.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert nested.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert top.states[0].caller.function == "top_call"
    assert nested.states[0].caller.function == "outer"


def test_ambiguous_callable_alias_assignment_is_an_explicit_gate_finding() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def first(operation="C_GetAttributeValue"):
            C.record_as("wrong_result", operation=operation)

        def second(operation="C_DeriveKey"):
            C.record_as("wrong_result", operation=operation)

        def run():
            alias = first
            alias = second
            alias()
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="run")
    assert unknown.status == STATUS_UNRESOLVED
    assert unknown.gate_action == GATE_REJECT


def test_bounded_literal_callable_containers_resolve_list_tuple_and_dict() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit(operation, mechanism=None, inherit_mechanism=False):
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def run():
            list_handlers = [emit]
            tuple_handlers = (emit,)
            dict_handlers = {"readback": emit}
            list_handlers[0]("C_GetAttributeValue", None, False)
            tuple_handlers[0]("C_GetAttributeValue", None, False)
            dict_handlers["readback"]("C_GetAttributeValue", None, False)
        """
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert {state.caller.function for state in finding.states} == {"run"}
    assert all(state.operation == C_GET_ATTRIBUTE_VALUE for state in finding.states)


def test_classification_connected_dynamic_container_selection_is_unresolved() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit(operation="C_GetAttributeValue"):
            C.record_as("wrong_result", operation=operation)

        def second(operation="C_DeriveKey"):
            C.record_as("wrong_result", operation=operation)

        def run(index):
            handlers = [emit, second]
            handlers[index](operation="C_GetAttributeValue")

        def direct(index):
            handlers = [C.record_as]
            handlers[index]("wrong_result", operation="C_GetAttributeValue")

        def mapping(key):
            handlers = {"emit": emit}
            handlers[key](operation="C_GetAttributeValue")

        def ambiguous():
            handlers = {"emit": emit, "emit": second}
            handlers["emit"](operation="C_GetAttributeValue")
        """,
        readback_only=True,
    )

    unknown = [finding for finding in findings if finding.emitter == "<unknown-call>"]
    assert {finding.function for finding in unknown} == {"run", "direct", "mapping", "ambiguous"}
    assert all(finding.status == STATUS_UNRESOLVED for finding in unknown)
    assert all(finding.gate_action == GATE_REJECT for finding in unknown)


def test_unsupported_container_selectors_are_fail_closed_without_keyword_masking() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def helper(operation="C_DeriveKey", mechanism="CKM_AES", inherit_mechanism=False):
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def dynamic(index):
            handlers = [helper]
            handlers[index]("C_GetAttributeValue", None, False)

        def out_of_range():
            handlers = [helper]
            handlers[99]("C_GetAttributeValue", None, False)

        def sliced():
            handlers = [helper]
            handlers[0:1]("C_GetAttributeValue", None, False)

        def duplicate_key():
            handlers = {"helper": helper, "helper": helper}
            handlers["helper"]("C_GetAttributeValue", None, False)
        """,
        readback_only=True,
    )

    unknown = [finding for finding in findings if finding.emitter == "<unknown-call>"]
    assert {finding.function for finding in unknown} == {
        "dynamic",
        "out_of_range",
        "sliced",
        "duplicate_key",
    }
    assert all(finding.status == STATUS_UNRESOLVED for finding in unknown)
    assert all(finding.gate_action == GATE_REJECT for finding in unknown)


def test_callable_alias_lexical_scope_honors_class_attributes_and_child_shadows() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def outer_emit(operation, mechanism=None, inherit_mechanism=False):
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def child_emit(operation, mechanism=None, inherit_mechanism=False):
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def outer():
            alias = outer_emit

            def child():
                alias = child_emit
                alias("C_DeriveKey", "CKM_AES", True)

            child()
            alias("C_GetAttributeValue", None, False)

        class Worker:
            def emit(self, operation, mechanism=None, inherit_mechanism=False):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=mechanism,
                    inherit_mechanism=inherit_mechanism,
                )

            alias = emit

            def call_alias(self):
                self.alias("C_GetAttributeValue", None, False)
        """
    )

    outer_finding = _find(findings, emitter="record_as", function="outer_emit")
    child_finding = _find(findings, emitter="record_as", function="child_emit")
    class_finding = _find(findings, emitter="record_as", function="Worker.emit")
    assert outer_finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert child_finding.status == STATUS_EXPLICIT_MECHANISM_GROUPING
    assert outer_finding.states[0].caller.function == "outer"
    assert child_finding.states[0].caller.function == "outer.child"
    assert class_finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert class_finding.states[0].caller.function == "Worker.call_alias"


def test_alias_expression_resolves_names_in_definition_scope_not_child_scope() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def safe_emit(operation, mechanism=None, inherit_mechanism=False):
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def unsafe_emit(operation, mechanism=None, inherit_mechanism=False):
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def outer():
            target = safe_emit
            alias = target

            def child():
                target = unsafe_emit
                del target
                alias("C_GetAttributeValue", None, False)

            child()
        """
    )

    finding = _find(findings, emitter="record_as", function="safe_emit")
    assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert finding.states[0].caller.function == "outer.child"
    unsafe = _find(findings, emitter="record_as", function="unsafe_emit")
    assert all(state.caller.function != "outer.child" for state in unsafe.states)


def test_callable_alias_reexports_resolve_through_in_repo_assignments() -> None:
    findings = scan_sources(
        {
            "base.py": dedent(
                """
                from pkcs11_check import classification as C

                def emit(operation, mechanism=None, inherit_mechanism=False):
                    C.record_as(
                        "wrong_result",
                        operation=operation,
                        mechanism=mechanism,
                        inherit_mechanism=inherit_mechanism,
                    )
                """
            ),
            "support.py": "from base import emit\nalias = emit\n",
            "entry.py": dedent(
                """
                from support import alias

                def run():
                    alias("C_GetAttributeValue", None, False)
                """
            ),
        }
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert finding.states[0].caller.function == "run"


def test_unresolved_callable_alias_chain_is_an_explicit_gate_finding() -> None:
    findings = _scan(
        """
        alias = missing_alias

        def run():
            alias()
        """,
        readback_only=True,
    )

    unresolved = _find(findings, emitter="<unknown-call>", function="run")
    assert unresolved.status == STATUS_UNRESOLVED
    assert unresolved.gate_action == GATE_REJECT


def test_aliased_classmethod_and_staticmethod_descriptors_bind_positionals() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        cm = classmethod
        sm = staticmethod

        class Worker:
            @cm
            def class_method(cls, operation, mechanism=None, inherit_mechanism=False):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=mechanism,
                    inherit_mechanism=inherit_mechanism,
                )

            @sm
            def static_method(operation, mechanism=None, inherit_mechanism=False):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=mechanism,
                    inherit_mechanism=inherit_mechanism,
                )

            @classmethod
            def call_class(cls):
                cls.class_method("C_GetAttributeValue", None, False)

            def call_static(self):
                Worker.static_method("C_GetAttributeValue", None, False)
        """
    )

    for function in ("Worker.class_method", "Worker.static_method"):
        finding = _find(findings, emitter="record_as", function=function)
        assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
        assert finding.states
        assert all(state.operation == C_GET_ATTRIBUTE_VALUE for state in finding.states)


def test_unrecognized_binding_decorator_fails_closed() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def wraps_binding(function):
            return function

        class Worker:
            @wraps_binding
            def emit(self, operation="C_GetAttributeValue"):
                C.record_as("wrong_result", operation=operation)

            def call(self):
                Worker.emit("C_GetAttributeValue")
        """,
        readback_only=True,
    )

    finding = _find(findings, emitter="record_as", function="Worker.emit")
    assert finding.status == STATUS_UNRESOLVED
    assert finding.gate_action == GATE_REJECT


def test_unexpanded_star_arguments_make_resolved_helper_transitively_unresolved() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit(operation="C_GetAttributeValue"):
            C.record_as("wrong_result", operation=operation)

        def forward(*args, **kwargs):
            emit(*args, **kwargs)

        def caller():
            forward("C_GetAttributeValue")
        """,
        readback_only=True,
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert finding.status == STATUS_UNRESOLVED
    assert any(state.status == STATUS_UNRESOLVED for state in finding.states)


def test_unexpanded_direct_emitter_arguments_are_explicitly_unresolved() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def caller(*args, **kwargs):
            C.record_as(
                "wrong_result",
                *args,
                operation="C_GetAttributeValue",
                **kwargs,
            )
            C.record_as("wrong_result", operation="C_DeriveKey", **kwargs)
        """
    )

    finding = next(
        item
        for item in findings
        if item.function == "caller" and item.operations == (C_GET_ATTRIBUTE_VALUE,)
    )
    assert finding.status == STATUS_UNRESOLVED
    assert finding.operations == (C_GET_ATTRIBUTE_VALUE,)
    assert finding.uncertain is True
    derived = [item for item in findings if item.operations == ("C_DeriveKey",)]
    assert len(derived) == 1
    assert derived[0].status == STATUS_UNRESOLVED
    assert derived[0].gate_action == GATE_REJECT


def test_cross_module_forwarding_and_module_alias_resolution() -> None:
    findings = scan_sources(
        {
            "support.py": dedent(
                """
                from pkcs11_check import classification as C

                def emit(operation="C_GetAttributeValue", mechanism=None, inherit_mechanism=False):
                    C.record_as(
                        "wrong_result",
                        operation=operation,
                        mechanism=mechanism,
                        inherit_mechanism=inherit_mechanism,
                    )
                """
            ),
            "entry.py": dedent(
                """
                from support import emit as forward

                def run():
                    forward(
                        operation="C_GetAttributeValue",
                        mechanism=None,
                        inherit_mechanism=False,
                    )
                """
            ),
        },
        readback_only=True,
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert finding.states[0].caller == type(finding.states[0].caller)("entry.py", 5, 4, "run")


def test_cross_module_reexport_keeps_helper_call_resolved() -> None:
    findings = scan_sources(
        {
            "conftest.py": dedent(
                """
                from pkcs11_check import classification as C

                def helper(operation="C_GetAttributeValue"):
                    C.record_as("wrong_result", operation=operation)
                """
            ),
            "support.py": "from pkcs11_check.testcases.conftest import helper\n",
            "entry.py": dedent(
                """
                from support import helper

                def run():
                    helper()
                """
            ),
        },
        readback_only=True,
    )

    finding = _find(findings, emitter="record_as", function="helper")
    assert finding.status == STATUS_UNSAFE_INHERITED_READBACK
    assert finding.states[0].caller.function == "run"


def test_reexported_scanned_class_preserves_classmethod_and_staticmethod_binding() -> None:
    findings = scan_sources(
        {
            "base.py": dedent(
                """
                from pkcs11_check import classification as C

                class Worker:
                    @classmethod
                    def class_method(cls, operation, mechanism=None, inherit_mechanism=False):
                        C.record_as(
                            "wrong_result",
                            operation=operation,
                            mechanism=mechanism,
                            inherit_mechanism=inherit_mechanism,
                        )

                    @staticmethod
                    def static_method(operation, mechanism=None, inherit_mechanism=False):
                        C.record_as(
                            "wrong_result",
                            operation=operation,
                            mechanism=mechanism,
                            inherit_mechanism=inherit_mechanism,
                        )
                """
            ),
            "support.py": "from base import Worker\n",
            "entry.py": dedent(
                """
                import base
                from support import Worker as ImportedWorker

                def run():
                    ImportedWorker.class_method("C_GetAttributeValue", None, False)
                    ImportedWorker.static_method("C_GetAttributeValue", None, False)
                    base.Worker.class_method("C_GetAttributeValue", None, False)
                """
            ),
        },
        readback_only=True,
    )

    for function in ("Worker.class_method", "Worker.static_method"):
        finding = _find(findings, emitter="record_as", function=function)
        assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
        assert finding.states
        assert all(state.operation == C_GET_ATTRIBUTE_VALUE for state in finding.states)
        assert all(state.caller.function == "run" for state in finding.states)


def test_bound_classmethod_alias_reexport_preserves_receiver_provenance() -> None:
    findings = scan_sources(
        {
            "base.py": dedent(
                """
                from pkcs11_check import classification as C

                class Worker:
                    @classmethod
                    def class_method(cls, operation, mechanism=None, inherit_mechanism=False):
                        C.record_as(
                            "wrong_result",
                            operation=operation,
                            mechanism=mechanism,
                            inherit_mechanism=inherit_mechanism,
                        )
                """
            ),
            "support.py": "from base import Worker\nclass_alias = Worker.class_method\n",
            "entry.py": dedent(
                """
                from support import class_alias

                def run():
                    class_alias("C_GetAttributeValue", None, False)
                """
            ),
        },
        readback_only=True,
    )

    finding = _find(findings, emitter="record_as", function="Worker.class_method")
    assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert finding.states[0].caller.function == "run"


def test_decorator_alias_binding_uses_definition_time_snapshot() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        cm = classmethod

        class Worker:
            @cm
            def early(cls, operation, mechanism=None, inherit_mechanism=False):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=mechanism,
                    inherit_mechanism=inherit_mechanism,
                )

            cm = staticmethod

            @cm
            def late(operation, mechanism=None, inherit_mechanism=False):
                C.record_as(
                    "wrong_result",
                    operation=operation,
                    mechanism=mechanism,
                    inherit_mechanism=inherit_mechanism,
                )

            def call(self):
                Worker.early("C_GetAttributeValue", None, False)
                Worker.late("C_GetAttributeValue", None, False)
        """
    )

    early = _find(findings, emitter="record_as", function="Worker.early")
    late = _find(findings, emitter="record_as", function="Worker.late")
    assert early.status == STATUS_SAFE_MECHANISM_FREE_READBACK
    assert late.status == STATUS_SAFE_MECHANISM_FREE_READBACK


def test_unsupported_classification_callee_shapes_are_fail_closed() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def run():
            getattr(C, "record_as")("wrong_result")
            emitters = {"record_as": C.record_as}
            emitters["record_as"]("wrong_result")
            name = "record_as"
            getattr(C, name)("wrong_result")
        """,
        readback_only=True,
    )

    unknown = [finding for finding in findings if finding.function == "run"]
    assert len(unknown) == 3
    assert all(finding.emitter == "<unknown-call>" for finding in unknown)
    assert all(finding.status == STATUS_UNRESOLVED for finding in unknown)
    assert all(finding.gate_action == GATE_REJECT for finding in unknown)


def test_inherit_mechanism_requires_an_exact_boolean_literal_or_value() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def check():
            C.record_as(
                "wrong_result",
                operation="C_GetAttributeValue",
                mechanism="CKM_AES",
                inherit_mechanism=None,
            )
            C.record_as(
                "wrong_result",
                operation="C_GetAttributeValue",
                mechanism="CKM_AES",
                inherit_mechanism=1,
            )
            C.record_as(
                "wrong_result",
                operation="C_GetAttributeValue",
                mechanism="CKM_AES",
                inherit_mechanism="False",
            )
        """
    )

    records = [finding for finding in findings if finding.emitter == "record_as"]
    assert len(records) == 3
    assert all(finding.status == STATUS_UNRESOLVED for finding in records)
    assert all(finding.gate_action == GATE_REJECT for finding in records)


def test_exact_stripped_prefix_import_wins_over_same_suffix_modules() -> None:
    findings = scan_sources(
        {
            "conftest.py": dedent(
                """
                from pkcs11_check import classification as C

                def helper(operation="C_GetAttributeValue"):
                    C.record_as("wrong_result", operation=operation)
                """
            ),
            "acvp/aes/conftest.py": dedent(
                """
                from pkcs11_check import classification as C

                def helper(operation="C_DeriveKey"):
                    C.record_as("wrong_result", operation=operation)
                """
            ),
            "entry.py": dedent(
                """
                from pkcs11_check.testcases.conftest import helper

                def run():
                    helper()
                """
            ),
        },
        readback_only=True,
    )

    helpers = [
        finding
        for finding in findings
        if finding.emitter == "record_as" and finding.function == "helper"
    ]
    assert len(helpers) == 1
    assert helpers[0].path == "conftest.py"
    assert helpers[0].operations == (C_GET_ATTRIBUTE_VALUE,)


def test_ambiguous_scanned_repo_import_is_unresolved_without_operation_args() -> None:
    findings = scan_sources(
        {
            "a/conftest.py": "def helper():\n    return None\n",
            "b/conftest.py": "def helper():\n    return None\n",
            "entry.py": dedent(
                """
                from pkcs11_check.testcases.conftest import helper

                def run():
                    helper()
                """
            ),
        },
        readback_only=True,
    )

    unresolved = _find(findings, emitter="<unknown-call>", function="run")
    assert unresolved.status == STATUS_UNRESOLVED


def test_missing_symbol_in_exact_scanned_repo_import_is_unresolved() -> None:
    findings = scan_sources(
        {
            "conftest.py": "def helper():\n    return None\n",
            "entry.py": dedent(
                """
                from pkcs11_check.testcases.conftest import missing

                def run():
                    missing()
                """
            ),
        },
        readback_only=True,
    )

    unresolved = _find(findings, emitter="<unknown-call>", function="run")
    assert unresolved.status == STATUS_UNRESOLVED


def test_resolved_scanned_class_import_is_not_an_unresolved_call_edge() -> None:
    findings = scan_sources(
        {
            "conftest.py": "class Helper:\n    pass\n",
            "entry.py": dedent(
                """
                from pkcs11_check.testcases.conftest import Helper

                def run():
                    Helper()
                """
            ),
        },
        readback_only=True,
    )

    assert not any(finding.function == "run" for finding in findings)


def test_shadowed_aliases_are_unknown_gate_findings_not_false_emitters() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def check(C):
            C.record_as("wrong_result", operation="C_GetAttributeValue")
        """
    )

    assert not any(finding.emitter == "record_as" for finding in findings)
    assert any(
        finding.emitter == "<unknown-call>" and finding.status == STATUS_UNRESOLVED
        for finding in findings
    )


def test_local_alias_shadowing_and_local_imports_are_lexically_resolved() -> None:
    findings = _scan(
        """
        def local_import() -> None:
            import pkcs11_check.classification as C
            C.record_as("wrong_result", operation="C_GetAttributeValue")

        def local_shadow() -> None:
            import pkcs11_check.classification as C
            C = object()
            C.record_as("wrong_result", operation="C_GetAttributeValue")
        """
    )

    imported = _find(findings, emitter="record_as", function="local_import")
    assert imported.status == STATUS_UNSAFE_INHERITED_READBACK
    assert not any(
        finding.emitter == "record_as" and finding.function == "local_shadow"
        for finding in findings
    )
    assert any(
        finding.emitter == "<unknown-call>"
        and finding.function == "local_shadow"
        and finding.status == STATUS_UNRESOLVED
        for finding in findings
    )


def test_unsupported_expression_and_unresolved_call_remain_in_readback_inventory() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def operation_factory():
            return "C_GetAttributeValue"

        def check():
            C.record_as("wrong_result", operation=operation_factory())
            external(operation="C_GetAttributeValue")
        """
    )

    assert (
        len(
            _scan(
                """
        from pkcs11_check import classification as C
        def check():
            C.record_as("wrong_result", operation=object())
        """,
                readback_only=True,
            )
        )
        == 1
    )
    assert any(finding.status == STATUS_UNRESOLVED for finding in findings)
    assert any(finding.emitter == "<unknown-call>" for finding in findings)
    assert any(
        finding.status == STATUS_UNRESOLVED
        for finding in _scan(
            """
        from pkcs11_check import classification as C
        def check():
            C.record_as("wrong_result", operation=object())
        """,
            readback_only=True,
        )
    )


def test_recursive_helper_cycle_reaches_fixed_point_without_recursing_forever() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def first(operation="C_GetAttributeValue"):
            C.record_as("wrong_result", operation=operation)
            second(operation=operation)

        def second(operation="C_GetAttributeValue"):
            C.record_as("wrong_result", operation=operation)
            first(operation=operation)

        first(operation="C_GetAttributeValue")
        """,
        readback_only=True,
    )

    for function in ("first", "second"):
        finding = _find(findings, emitter="record_as", function=function)
        assert finding.states
        assert all(state.operation == C_GET_ATTRIBUTE_VALUE for state in finding.states)
        assert all(state.status == STATUS_UNSAFE_INHERITED_READBACK for state in finding.states)


def test_worklist_converges_beyond_sixty_four_call_edges() -> None:
    functions = []
    for index in range(70):
        next_call = (
            f"f{index + 1}(operation=operation)"
            if index < 69
            else ('C.record_as("wrong_result", operation=operation)')
        )
        functions.append(f"def f{index}(operation):\n    {next_call}")
    source = "from pkcs11_check import classification as C\n\n" + "\n\n".join(functions)
    source += '\n\nf0(operation="C_GetAttributeValue")\n'

    findings = _scan(source, readback_only=True)
    finding = _find(findings, emitter="record_as", function="f69")
    assert any(state.operation == C_GET_ATTRIBUTE_VALUE for state in finding.states)
    assert any(state.caller.function == "f68" for state in finding.states)


def test_gate_partition_is_conservative_and_keeps_explicit_grouping_separate() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def check():
            C.record_as(
                "wrong_result",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
            )
            C.record_as("wrong_result", operation="C_GetAttributeValue")
            C.record_as(
                "wrong_result",
                operation="C_GetAttributeValue",
                mechanism="CKM_AES",
            )
            C.record_as("wrong_result", operation="C_DeriveKey", mechanism="CKM_AES")
            C.record_as("wrong_result", operation="C_DeriveKey")
            C.record_as("wrong_result", operation=object())
        """
    )

    by_status = {finding.status: finding for finding in findings}
    assert should_gate_readback(by_status[STATUS_SAFE_MECHANISM_FREE_READBACK]) is False
    assert by_status[STATUS_SAFE_MECHANISM_FREE_READBACK].gate_action == GATE_SAFE
    assert should_gate_readback(by_status[STATUS_UNSAFE_INHERITED_READBACK]) is True
    assert by_status[STATUS_UNSAFE_INHERITED_READBACK].gate_action == GATE_REJECT
    assert by_status[STATUS_EXPLICIT_MECHANISM_READBACK].gate_action == GATE_GROUPING
    assert by_status[STATUS_EXPLICIT_MECHANISM_GROUPING].gate_action == GATE_EXCLUDED
    assert by_status[STATUS_NON_READBACK].gate_action == GATE_EXCLUDED
    assert by_status[STATUS_UNRESOLVED].gate_action == GATE_REJECT


def test_gate_rejects_mixed_readback_and_non_readback_states() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit(operation):
            C.record_as("wrong_result", operation=operation, mechanism="CKM_AES")

        def readback():
            emit("C_GetAttributeValue")

        def grouping():
            emit("C_DeriveKey")
        """
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert {state.status for state in finding.states} == {
        STATUS_EXPLICIT_MECHANISM_GROUPING,
        STATUS_EXPLICIT_MECHANISM_READBACK,
    }
    assert finding.gate_action == GATE_REJECT


def test_flattened_effective_states_preserve_finding_identity_and_relation() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def check():
            C.record_as(
                "wrong_result",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
            )
        """
    )

    flattened = flatten_effective_states(findings)
    assert len(flattened) == 1
    assert flattened[0].finding is findings[0]
    assert flattened[0].state.operation == C_GET_ATTRIBUTE_VALUE
    assert flattened[0].state.mechanism == NONE_VALUE
    assert flattened[0].state.inherit_mechanism == FALSE_VALUE


def test_source_ast_corpus_digest_is_independent_from_finding_digest() -> None:
    source = "from pkcs11_check import classification as C\n"
    source_digest = corpus_digest({"synthetic.py": source})
    findings = scan_source(source)
    assert source_digest != inventory_digest(findings)
    assert source_digest != corpus_digest({"synthetic.py": source + "# comment\n"})


# H4 attribution-rule fixes. Each rule carries synthetic regression tests here plus
# a tree-level zero-assertion next to the characterization gate below.


def test_decorated_direct_literal_emitter_is_certain() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def deco(function):
            return function

        class Worker:
            @deco
            def check(self):
                C.record_as(
                    "wrong_result",
                    operation="C_GetAttributeValue",
                    mechanism=None,
                    inherit_mechanism=False,
                )
        """
    )

    finding = _find(findings, emitter="record_as", function="Worker.check")
    assert finding.uncertain is False
    assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK


def test_decorated_forwarded_emitter_stays_uncertain() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def deco(function):
            return function

        class Worker:
            @deco
            def emit(self, operation):
                C.record_as("wrong_result", operation=operation)
        """
    )

    finding = _find(findings, emitter="record_as", function="Worker.emit")
    assert finding.uncertain is True
    assert finding.status == STATUS_UNRESOLVED


def test_star_arg_caller_leaves_literal_emitter_certain() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit():
            C.record_as(
                "wrong_result",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
            )

        def forward(*args):
            emit(*args)

        def caller():
            forward()
        """
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert finding.uncertain is False
    assert finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK


def test_star_arg_caller_keeps_transitively_forwarded_emitter_uncertain() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def emit(operation):
            resolved = operation
            C.record_as("wrong_result", operation=resolved)

        def forward(*args):
            emit(*args)

        def caller():
            forward()
        """
    )

    finding = _find(findings, emitter="record_as", function="emit")
    assert finding.uncertain is True
    assert finding.status == STATUS_UNRESOLVED


def test_external_module_attribute_alias_is_not_an_unknown_call() -> None:
    findings = _scan(
        """
        import ctypes

        def probe():
            c_ulong = ctypes.c_ulong
            byref = ctypes.byref
            out_len = c_ulong(64)
            return byref(out_len)
        """,
        readback_only=True,
    )

    assert findings == ()


def test_emitter_alias_through_classification_module_stays_unknown_call() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C

        def check():
            emit = C.record_as
            emit("wrong_result", operation="C_DeriveKey")
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_emitter_named_foreign_attribute_alias_stays_unknown_call() -> None:
    findings = _scan(
        """
        import foreign

        def check():
            emit = foreign.record_as
            emit("wrong_result")
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_mixed_external_and_local_alias_stays_unknown_call() -> None:
    findings = _scan(
        """
        import ctypes

        def local(operation):
            return operation

        def check():
            handler = ctypes.c_ulong
            handler = local
            handler("C_DeriveKey")
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_external_alias_with_attribution_kwarg_stays_unknown_call() -> None:
    findings = _scan(
        """
        import ctypes

        def check():
            make = ctypes.c_ulong
            make(operation="C_DeriveKey")
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_factory_call_root_alias_stays_unknown_call() -> None:
    findings = _scan(
        """
        import helper

        def check():
            handler = factory().helper
            handler()
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_subscript_root_alias_stays_unknown_call() -> None:
    findings = _scan(
        """
        import helper

        def check():
            handler = items[0].helper
            handler()
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_conflicting_double_import_alias_stays_unknown_call() -> None:
    findings = _scan(
        """
        def check():
            try:
                import helper_mod as backend
            except ImportError:
                import ctypes as backend
            handler = backend.c_ulong
            handler(64)
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_top_level_conflicting_import_alias_stays_unknown_call() -> None:
    findings = _scan(
        """
        import helper_mod as backend
        import ctypes as backend

        def check():
            handler = backend.c_ulong
            handler(64)
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_unresolvable_testcases_prefixed_alias_stays_unknown_call() -> None:
    findings = _scan(
        """
        import pkcs11_check.testcases.typo as helpers

        def check():
            run = helpers.run
            run()
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_classification_context_setter_is_not_an_unknown_call() -> None:
    findings = _scan(
        """
        from pkcs11_check.classification import set_mechanism

        def replay():
            set_mechanism("CKM_AES", operation="C_Encrypt", expect_success=True)
        """,
        readback_only=True,
    )

    assert findings == ()


def test_classification_record_constructor_is_not_an_unknown_call() -> None:
    findings = _scan(
        """
        from pkcs11_check.classification import Classification

        def build():
            return Classification(
                reason="wrong_result",
                outcome="fail",
                severity="high",
                kind="metadata",
                label="probe",
                summary="probe",
                operation="C_Digest",
            )
        """,
        readback_only=True,
    )

    assert findings == ()


def test_dotted_classification_context_setter_is_not_an_unknown_call() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification

        def replay():
            classification.set_mechanism("CKM_AES", operation="C_Encrypt")
        """,
        readback_only=True,
    )

    assert findings == ()


def test_unknown_classification_member_with_operation_stays_unknown_call() -> None:
    findings = _scan(
        """
        from pkcs11_check.classification import warn_as

        def check():
            warn_as("wrong_result", operation="C_Digest")
        """,
        readback_only=True,
    )

    unknown = _find(findings, emitter="<unknown-call>", function="check")
    assert unknown.status == STATUS_UNRESOLVED


def test_local_shadow_named_like_context_setter_still_resolves() -> None:
    findings = _scan(
        """
        from pkcs11_check import classification as C
        from pkcs11_check.classification import set_mechanism

        def set_mechanism(operation):
            C.record_as("wrong_result", operation=operation)

        def check():
            set_mechanism(operation="C_DeriveKey")
        """
    )

    finding = _find(findings, emitter="record_as", function="set_mechanism")
    assert finding.operations == ("C_DeriveKey",)
    assert not any(item.emitter == "<unknown-call>" for item in findings)


def _classification_exempted_member_calls(module_path: Path) -> set[str]:
    """Callee names reachable from the B2-exempted members' runtime behavior.

    Covers direct calls, delegation through module-level helpers (transitive),
    ``__post_init__``, new methods, and ``default_factory`` targets including
    lambdas. The whole class body is a root — over-approx, fail-closed.
    """
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
    assert "set_mechanism" in functions, "set_mechanism renamed or removed"
    assert "Classification" in classes, "Classification renamed or removed"
    roots: list[ast.AST] = [functions["set_mechanism"], classes["Classification"]]
    called: set[str] = set()
    seen: set[int] = set()
    stack = list(roots)
    while stack:
        root = stack.pop()
        if id(root) in seen:
            continue
        seen.add(id(root))
        for node in ast.walk(root):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg == "default_factory"
                    and isinstance(keyword.value, ast.Name)
                    and keyword.value.id in functions
                ):
                    called.add(keyword.value.id)
                    stack.append(functions[keyword.value.id])
            if isinstance(node.func, ast.Name):
                called.add(node.func.id)
                target = functions.get(node.func.id)
                if target is not None:
                    stack.append(target)
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)
    return called


def test_classification_non_emitter_exemption_matches_live_module() -> None:
    """Pin the B2 exemption: names exist, are not emitters, and cannot emit.

    The analyzer exempts calls bound to the classification module's
    ``set_mechanism``/``Classification`` members. If either is renamed, gains
    emitter behavior (direct calls, delegation, ``__post_init__``, emitting
    factories), or stops being a plain context setter / record, this fails so
    the exemption is re-reviewed instead of silently widening.
    """
    module_path = Path(__file__).resolve().parents[1] / "src/pkcs11_check/classification.py"
    for name in sorted(_CLASSIFICATION_NON_EMITTERS):
        assert callable(getattr(classification_module, name)), f"{name} renamed or removed"
    assert _CLASSIFICATION_NON_EMITTERS.isdisjoint(_EMITTERS)
    assert not (_classification_exempted_member_calls(module_path) & set(_EMITTERS))
    assert not (set(classification_module.set_mechanism.__code__.co_names) & set(_EMITTERS))

    record_type = classification_module.Classification
    assert isinstance(record_type, type)
    init_code = record_type.__init__.__code__
    assert init_code.co_filename == "<string>", "Classification gained a hand-written __init__"
    assert not (set(init_code.co_names) & set(_EMITTERS))


def test_exempted_member_oracle_catches_post_init_emission(tmp_path: Path) -> None:
    module = tmp_path / "classification.py"
    module.write_text(
        "def set_mechanism() -> None:\n"
        "    pass\n"
        "\n"
        "class Classification:\n"
        "    def __post_init__(self) -> None:\n"
        '        classify("x")\n',
        encoding="utf-8",
    )

    assert _classification_exempted_member_calls(module) == {"classify"}


def test_exempted_member_oracle_catches_delegated_emission(tmp_path: Path) -> None:
    module = tmp_path / "classification.py"
    module.write_text(
        "def _helper() -> None:\n"
        '    record_as("x")\n'
        "\n"
        "def set_mechanism() -> None:\n"
        "    _helper()\n"
        "\n"
        "class Classification:\n"
        "    pass\n",
        encoding="utf-8",
    )

    assert _classification_exempted_member_calls(module) == {"_helper", "record_as"}


def test_exempted_member_oracle_catches_factory_emission(tmp_path: Path) -> None:
    module = tmp_path / "classification.py"
    module.write_text(
        "def _make() -> list:\n"
        '    return [fail_as("x")]\n'
        "\n"
        "def set_mechanism() -> None:\n"
        "    pass\n"
        "\n"
        "class Classification:\n"
        "    items: list = field(default_factory=_make)\n"
        "    other: list = field(default_factory=lambda: [xfail_as('y')])\n",
        encoding="utf-8",
    )

    assert _classification_exempted_member_calls(module) == {
        "field",
        "_make",
        "fail_as",
        "xfail_as",
    }


def _assert_characterization_pins(characterization: InventoryCharacterization, root: Path) -> None:
    """Fail once with a HEAD diff when any pinned characterization value drifts.

    Layout contract: the repin script (workspace scripts/repin-readback-inventory.py)
    matches the ("name", "<64-hex>") digest tuples below, so keep that shape.
    """
    pins: list[tuple[str, object, object]] = [
        ("total", 1537, characterization.total),
        ("candidate_total", 1351, characterization.candidate_total),
        ("file_total", 244, characterization.file_total),
        (
            "statuses",
            (
                ("explicit_mechanism_grouping", 536),
                ("explicit_mechanism_readback", 61),
                ("non_readback", 186),
                ("safe_mechanism_free_readback", 63),
                ("unresolved", 595),
                ("unsafe_inherited_readback", 96),
            ),
            characterization.statuses,
        ),
        (
            "digest",
            "bf3e8b820a70418279ac7ccfd25819196ec61e317a5bab6d9f20f74efaf10d34",
            characterization.digest,
        ),
        (
            "candidate_digest",
            "d14e513bf8414d3af7985d1a94e98a2ed5d4e65a404f4214ed9415614ba716b8",
            characterization.candidate_digest,
        ),
        (
            "state_statuses",
            (
                ("explicit_mechanism_grouping", 1231),
                ("explicit_mechanism_readback", 358),
                ("non_readback", 352),
                ("safe_mechanism_free_readback", 1359),
                ("unresolved", 2516),
                ("unsafe_inherited_readback", 254),
            ),
            characterization.state_statuses,
        ),
        ("mixed_unsafe_states", 22, characterization.mixed_unsafe_states),
        (
            "corpus_digest",
            "d64bb8a883d6b8bcf00c2ad04fafe38d47806c1852d1286202c08f20eebe4986",
            characterization.corpus_digest,
        ),
        (
            "direct_emitter_census",
            (
                ("assert_correct", 268),
                ("classify", 533),
                ("fail_as", 194),
                ("record_as", 257),
                ("xfail_as", 155),
            ),
            characterization.direct_emitter_census,
        ),
    ]
    mismatches = [(name, expected, actual) for name, expected, actual in pins if expected != actual]
    if not mismatches:
        return
    lines = [f"characterization drift: {len(mismatches)} pinned values differ"]
    for name, expected, actual in mismatches:
        lines.append(f"  {name}: expected {expected!r} but got {actual!r}")
    lines.extend(["", head_inventory_diff(root, scan_tree(root))])
    pytest.fail("\n".join(lines))


def test_current_tree_characterization_is_non_vacuous_pinned_and_not_zero_gate() -> None:
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
    characterization = characterize_tree(root)

    assert root.is_dir()
    _assert_characterization_pins(characterization, root)

    # These are exact sentinels for the current source tree.  The conftest slice is
    # still outstanding work (characterized, not zero); the provisioning slice was
    # fixed by the H4 uncertainty rule and now asserts its resolved form.
    all_findings = scan_tree(root)
    provisioning = [
        finding
        for finding in all_findings
        if finding.path == "_provisioning.py" and finding.emitter == "record_as"
    ]
    assert provisioning
    assert any(
        finding.line == 114
        and finding.status == STATUS_SAFE_MECHANISM_FREE_READBACK
        and finding.uncertain is False
        and all(state.status == STATUS_SAFE_MECHANISM_FREE_READBACK for state in finding.states)
        for finding in provisioning
    )
    assert any(
        finding.line == 114
        and finding.function == "_attribute_refusal"
        and finding.uncertain is False
        and finding.operations == (C_GET_ATTRIBUTE_VALUE,)
        and finding.mechanisms == (NONE_VALUE,)
        for finding in provisioning
    )
    conftest = [
        finding
        for finding in all_findings
        if finding.path == "conftest.py" and finding.function == "assert_correct"
    ]
    assert conftest
    assert any(
        finding.line == 1287
        and finding.status == STATUS_UNRESOLVED
        and finding.operations == (UNKNOWN_OPERATION,)
        for finding in conftest
    )
    assert any(
        finding.line == 1287
        and finding.emitter == "classify"
        and finding.forwarded_parameters == ("mechanism", "operation")
        for finding in conftest
    )

    # Exact class and nested-helper sentinels exercise lexical ownership and caller
    # coordinates in the real tree, not only in the synthetic scanner fixtures.
    class_finding = [
        finding
        for finding in all_findings
        if (
            finding.path == "test_access_control.py"
            and finding.line == 162
            and finding.function == "TestPrivateAttribute.test_private_key_default_is_private"
            and finding.emitter == "classify"
        )
    ]
    assert len(class_finding) == 1
    assert class_finding[0].status == STATUS_NON_READBACK
    nested = [
        finding
        for finding in all_findings
        if finding.path == "_attribute_values.py"
        and finding.line == 93
        and finding.function == "attr_or_record"
        and finding.emitter == "record_as"
    ]
    assert len(nested) == 1
    assert any(
        state.caller.path == "_provisioning.py"
        and state.caller.line == 1002
        and state.caller.function == "_configured_rsa_pub_der._pub_from"
        for state in nested[0].states
    )

    # Cross-module forwarding is a real-tree invariant: the shared helper is in
    # _attribute_values.py while one caller is in _aes_operability.py.
    assert any(
        state.caller.path == "_aes_operability.py"
        and state.caller.line == 328
        and state.caller.function == "kw_unwrap_operability.probe"
        for state in nested[0].states
    )
    unknown = [
        finding
        for finding in all_findings
        if finding.path == "_probes/_attribute_facts.py"
        and finding.line == 81
        and finding.function == "emit_uaf_setup_fact"
        and finding.emitter == "<unknown-call>"
    ]
    assert len(unknown) == 1
    assert unknown[0].status == STATUS_UNRESOLVED
    assert unknown[0].operations == (C_GET_ATTRIBUTE_VALUE,)


def test_no_uncertain_finding_has_uniform_resolved_states() -> None:
    """Tree-hygiene zero-assertion for the H4 uncertainty rule.

    Caller-context uncertainty only poisons emitters whose attribution kwargs
    transitively read parameters — but the rule deliberately still poisons two
    uniform patterns (star-args at the emitter always taint; single-literal-
    caller param forwarding stays uncertain). This bans all such shapes from
    the tree, so adding one fails loudly for conscious review instead of
    silently re-widening the blind spot.
    """
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
    offenders = []
    for finding in scan_tree(root):
        if not finding.uncertain:
            continue
        statuses = {state.status for state in finding.states}
        if statuses and STATUS_UNRESOLVED not in statuses:
            offenders.append((finding.path, finding.line, finding.function, finding.emitter))
    assert offenders == []


def _tree_unknown_call_callee_names(root: Path) -> dict[str, int]:
    """Map unknown-call findings to callee spellings via an independent re-parse.

    Unmapped findings count under "<unmapped>" so helper drift fails loudly
    instead of silently shrinking the zero-assertion below.
    """
    spellings: dict[tuple[str, int, int], str] = {}
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name):
                spelling: str | None = node.func.id
            elif isinstance(node.func, ast.Attribute):
                spelling = node.func.attr
            else:
                spelling = None
            if spelling is not None:
                spellings[(path.relative_to(root).as_posix(), node.lineno, node.col_offset)] = (
                    spelling
                )
    counts: dict[str, int] = {}
    for finding in scan_tree(root):
        if finding.emitter != "<unknown-call>":
            continue
        spelling = spellings.get((finding.path, finding.line, finding.column), "<unmapped>")
        counts[spelling] = counts.get(spelling, 0) + 1
    return counts


def test_no_unknown_call_targets_exempted_callees() -> None:
    """Zero-assertion for the H4 unknown-call rules: exempted names never flag.

    External-module attribute aliases (``c_ulong``/``byref``-shaped) and
    classification-module non-emitters (``set_mechanism``/``Classification``)
    are not unknown-call findings. The generic rules are pinned synthetically
    above; this pins the fixed tree vocabulary (definition sites are pinned
    separately so a rename cannot evade the spelling match).
    """
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
    counts = _tree_unknown_call_callee_names(root)

    assert counts, "expected remaining unknown-call findings"
    assert "<unmapped>" not in counts
    assert not (set(counts) & {"c_ulong", "byref", "set_mechanism", "Classification"})


def _tree_bare_ctypes_aliases(root: Path) -> dict[str, set[str]]:
    """Map alias spellings to targets for bare ``alias = ctypes.<attr>`` defs."""
    aliases: dict[str, set[str]] = {}
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        for node in ast.walk(tree):
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
                value = node.value
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
                value = node.value
            if not (
                isinstance(value, ast.Attribute)
                and isinstance(value.value, ast.Name)
                and value.value.id == "ctypes"
            ):
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    aliases.setdefault(target.id, set()).add(value.attr)
    return aliases


def test_ctypes_alias_vocabulary_is_pinned() -> None:
    """Pin the ctypes alias spellings the B1 exemption relies on.

    The unknown-call zero-assertion matches by callee spelling, so a renamed
    alias (``ulong = ctypes.c_ulong``) would evade its vocabulary. Pinning the
    definition sites forces a conscious vocabulary review on any rename, while
    characterization pins backstop exemption regressions.
    """
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
    assert _tree_bare_ctypes_aliases(root) == {
        "byref": {"byref"},
        "c_ubyte": {"c_ubyte"},
        "c_ulong": {"c_ulong"},
        "c_void_p": {"c_void_p"},
        "_CK_RV": {"c_ulong"},
    }


def test_independent_coordinate_census_covers_all_live_definitions_and_emitters() -> None:
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
    census = coordinate_census(root)
    registered = set(registered_definition_coordinates(root))

    # These 22 definitions were the exact compound-statement misses before the
    # registration walk became recursive.  The expected list is source/AST data,
    # not a count or coordinate set obtained from the analyzer under test.
    compound_definition_misses = {
        CallerCoordinate(
            "_probes/ckr_raw_buffer.py",
            1024,
            12,
            "_aes_cbc_pad_encrypt_final_buffer_too_small.decrypt_ciphertext",
        ),
        CallerCoordinate(
            "acvp/test_acvp_rsa.py",
            222,
            12,
            "TestRsaPkcs15.test_rsa_pkcs15_sign_verify._local",
        ),
        CallerCoordinate(
            "acvp/test_acvp_rsa.py",
            290,
            12,
            "TestRsaPss.test_rsa_pss_sign_verify._local",
        ),
        CallerCoordinate(
            "test_gost.py",
            358,
            12,
            "TestGOST28147Encryption.test_cbc_roundtrip._do",
        ),
        CallerCoordinate(
            "test_gost.py",
            320,
            12,
            "TestGOST28147Encryption.test_ecb_different_keys_produce_different_ciphertext._do",
        ),
        CallerCoordinate(
            "test_gost.py",
            230,
            12,
            "TestGOST28147Encryption.test_ecb_rfc8891_magma_tc26_z_vector._do",
        ),
        CallerCoordinate(
            "test_gost.py",
            215,
            12,
            "TestGOST28147Encryption.test_ecb_rfc8891_magma_tc26_z_vector._setup",
        ),
        CallerCoordinate(
            "test_gost.py",
            289,
            12,
            "TestGOST28147Encryption.test_ecb_roundtrip._do",
        ),
        CallerCoordinate(
            "test_gost.py",
            521,
            12,
            "TestGOST28147KeyWrap.test_key_wrap_rfc7836_tc26_z_vector._do",
        ),
        CallerCoordinate(
            "test_gost.py",
            493,
            12,
            "TestGOST28147KeyWrap.test_key_wrap_rfc7836_tc26_z_vector._setup",
        ),
        CallerCoordinate(
            "test_gost.py",
            415,
            12,
            "TestGOST28147MAC.test_mac_rfc7836_tc26_z_vector._do",
        ),
        CallerCoordinate(
            "test_gost.py",
            400,
            12,
            "TestGOST28147MAC.test_mac_rfc7836_tc26_z_vector._setup",
        ),
        CallerCoordinate(
            "test_gost.py",
            469,
            12,
            "TestGOST28147MAC.test_mac_sign_verify._do",
        ),
        CallerCoordinate(
            "test_gost.py",
            574,
            12,
            "TestGOSTR3410Signature.test_sign_verify_raw._do",
        ),
        CallerCoordinate(
            "test_gost.py",
            598,
            12,
            "TestGOSTR3410Signature.test_sign_verify_with_hash._do",
        ),
        CallerCoordinate(
            "test_gost.py",
            696,
            12,
            "TestGOSTR3411Digest.test_hmac_sign_verify._do",
        ),
        CallerCoordinate(
            "test_session_op_race.py",
            257,
            12,
            "TestSameSessionInitRace.test_digest_init_then_sign_init_other_thread.sign_init_attempt",
        ),
        CallerCoordinate(
            "test_session_op_race.py",
            172,
            12,
            "TestSameSessionInitRace.test_encrypt_init_race.init_encrypt",
        ),
        CallerCoordinate(
            "test_session_op_race.py",
            212,
            12,
            "TestSameSessionInitRace.test_init_during_update_returns_operation_active.reinit_attempt",
        ),
        CallerCoordinate("test_session_op_race.py", 95, 8, "_race_inits.racer"),
        CallerCoordinate(
            "test_x942_dh.py",
            1649,
            16,
            "TestX942DHDerive.test_x942_dh_derive_rfc5114_value_len_truncation.derive_requested_len",
        ),
        CallerCoordinate("x509/conftest.py", 392, 8, "verify_attribute_parity.to_der_int"),
    }
    assert len(compound_definition_misses) == 22
    assert compound_definition_misses <= set(census.definition_coordinates)
    assert compound_definition_misses <= registered
    assert len(census.definition_coordinates) == 4403
    assert set(census.definition_coordinates) == registered

    direct_findings = scan_tree(root)
    actual_emitters = {
        (
            CallerCoordinate(finding.path, finding.line, finding.column, finding.function),
            finding.emitter,
        )
        for finding in direct_findings
        if finding.emitter in {"classify", "record_as", "fail_as", "xfail_as", "assert_correct"}
    }
    assert len(census.emitter_coordinates) == 1407
    assert len(actual_emitters) == 1407
    assert set(census.emitter_coordinates) == actual_emitters
    compound_emitter_misses = {
        (
            CallerCoordinate(
                "test_gost.py", 292, 16, "TestGOST28147Encryption.test_ecb_roundtrip._do"
            ),
            "assert_correct",
        ),
        (
            CallerCoordinate(
                "test_gost.py",
                324,
                20,
                "TestGOST28147Encryption.test_ecb_different_keys_produce_different_ciphertext._do",
            ),
            "classify",
        ),
        (
            CallerCoordinate(
                "test_gost.py", 375, 16, "TestGOST28147Encryption.test_cbc_roundtrip._do"
            ),
            "assert_correct",
        ),
        (
            CallerCoordinate(
                "acvp/test_acvp_rsa.py", 302, 20, "TestRsaPss.test_rsa_pss_sign_verify._local"
            ),
            "xfail_as",
        ),
        (
            CallerCoordinate(
                "acvp/test_acvp_rsa.py", 313, 20, "TestRsaPss.test_rsa_pss_sign_verify._local"
            ),
            "xfail_as",
        ),
    }
    assert len(compound_emitter_misses) == 5
    assert compound_emitter_misses <= set(census.emitter_coordinates)
    assert compound_emitter_misses <= actual_emitters


def test_inventory_digest_changes_when_a_relational_state_changes() -> None:
    safe = _scan(
        """
        from pkcs11_check import classification as C
        def check():
            C.record_as(
                "wrong_result",
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
            )
        """
    )
    unsafe = _scan(
        """
        from pkcs11_check import classification as C
        def check():
            C.record_as("wrong_result", operation="C_GetAttributeValue")
        """
    )

    assert inventory_digest(safe) != inventory_digest(unsafe)


def test_format_inventory_diff_separates_coordinate_moves_from_status_changes() -> None:
    header = "from pkcs11_check import classification as C\n"
    body = 'def check() -> None:\n    C.record_as("x", operation="C_GetAttributeValue")\n'
    before = scan_source(header + body, path="moved.py")
    after = scan_source(header + "\n\n" + body, path="moved.py")

    moved = format_inventory_diff(before, after)
    assert "coordinate-only moves (1):" in moved
    assert "moved.py check record_as: (3,4) -> (5,4)" in moved
    assert "status/content changes (0):" in moved

    safe = scan_source(
        header
        + "def check() -> None:\n"
        + '    C.record_as("x", operation="C_GetAttributeValue",'
        + " mechanism=None, inherit_mechanism=False)\n",
        path="changed.py",
    )
    unsafe = scan_source(
        header
        + "def check() -> None:\n"
        + '    C.record_as("x", operation="C_GetAttributeValue")\n',
        path="changed.py",
    )

    changed = format_inventory_diff(safe, unsafe)
    assert "status/content changes (1):" in changed
    assert "safe_mechanism_free_readback -> unsafe_inherited_readback" in changed
    assert "coordinate-only moves (0):" in changed

    identical = format_inventory_diff(before, before)
    assert "coordinate-only moves (0):" in identical
    assert "status/content changes (0):" in identical
    assert "added (0):" in identical
    assert "removed (0):" in identical


def test_format_inventory_diff_reports_paths_emitters_and_added_removed() -> None:
    header = "from pkcs11_check import classification as C\n"
    classify_src = (
        header + "def check() -> None:\n" + '    C.classify("x", operation="C_DeriveKey")\n'
    )
    record_src = (
        header + "def check() -> None:\n" + '    C.record_as("x", operation="C_DeriveKey")\n'
    )
    before = scan_sources({"staying.py": classify_src, "gone.py": record_src})
    after = scan_sources({"staying.py": classify_src, "fresh.py": record_src})

    diff = format_inventory_diff(before, after)
    assert "paths: +1 -1" in diff
    assert "  + fresh.py" in diff
    assert "  - gone.py" in diff
    assert "emitters: unchanged" in diff
    assert "coordinate-only moves (0):" in diff
    assert "added (1):" in diff
    assert "removed (1):" in diff

    grown = scan_sources(
        {"staying.py": classify_src, "fresh.py": record_src, "extra.py": record_src}
    )
    emitter_delta = format_inventory_diff(after, grown)
    assert "record_as: 1 -> 2 (+1)" in emitter_delta


def test_head_inventory_diff_degrades_outside_a_checkout(tmp_path: Path) -> None:
    assert head_inventory_diff(tmp_path, ()).startswith("<inventory diff unavailable:")


@requires_git_tracked_files
def test_git_head_tree_sources_reads_head_python_files() -> None:
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
    sources = git_head_tree_sources(root)

    assert len(sources) > 200
    assert "conftest.py" in sources
    assert all(path.endswith(".py") and not path.startswith("/") for path in sources)


def test_tree_scans_share_the_corpus_digest_cached_analyzer() -> None:
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
    first = scan_tree(root)
    characterization = characterize_tree(root)

    assert characterization.total == len(first)
    assert scan_tree(root) is first
    registered_definition_coordinates(root)
    assert scan_tree(root) is first
    filtered = scan_tree(root, readback_only=True)
    assert filtered == tuple(finding for finding in first if finding.is_readback)
    assert scan_tree(root, readback_only=True) is filtered


def test_format_inventory_diff_matches_moved_findings_across_a_removal() -> None:
    header = "from pkcs11_check import classification as C\n"
    calls = (
        '    C.record_as("a", operation="C_Encrypt")\n'
        '    C.record_as("b", operation="C_Decrypt")\n'
        '    C.record_as("c", operation="C_Digest")\n'
    )
    before = scan_source(header + "def check() -> None:\n" + calls, path="shrunk.py")
    after = scan_source(
        header
        + "def check() -> None:\n"
        + '    C.record_as("a", operation="C_Encrypt")\n'
        + '    C.record_as("c", operation="C_Digest")\n',
        path="shrunk.py",
    )
    assert len(before) == 3
    assert len(after) == 2

    diff = format_inventory_diff(before, after)

    assert "status/content changes (0):" in diff
    assert "removed (1):" in diff
    assert "shrunk.py:4 check record_as [non_readback]" in diff
    assert "coordinate-only moves (1):" in diff


def test_format_inventory_diff_pairs_a_lone_edit_among_unchanged_peers() -> None:
    header = "from pkcs11_check import classification as C\n"
    before = scan_source(
        header
        + "def check() -> None:\n"
        + '    C.record_as("a", operation="C_Encrypt")\n'
        + '    C.record_as("b", operation="C_Decrypt")\n',
        path="edited.py",
    )
    after = scan_source(
        header
        + "def check() -> None:\n"
        + '    C.record_as("a", operation="C_Encrypt")\n'
        + '    C.record_as("b", operation="C_Digest")\n',
        path="edited.py",
    )

    diff = format_inventory_diff(before, after)

    assert "status/content changes (1):" in diff
    assert "ops ('C_Decrypt',) -> ('C_Digest',)" in diff
    assert "coordinate-only moves (0):" in diff
    assert "added (0):" in diff
    assert "removed (0):" in diff


def test_format_inventory_diff_change_detail_falls_back_to_content_changed() -> None:
    emit = (
        "from pkcs11_check import classification as C\n"
        "\n"
        "def emit(\n"
        '    operation: str = "C_GetAttributeValue",\n'
        "    mechanism: str | None = None,\n"
        "    inherit_mechanism: bool = False,\n"
        ") -> None:\n"
        "    C.record_as(\n"
        '        "wrong_result",\n'
        "        operation=operation,\n"
        "        mechanism=mechanism,\n"
        "        inherit_mechanism=inherit_mechanism,\n"
        "    )\n"
    )

    def _caller(name: str) -> str:
        return (
            f"\ndef {name}() -> None:\n"
            "    emit(\n"
            '        operation="C_GetAttributeValue",\n'
            "        mechanism=None,\n"
            "        inherit_mechanism=False,\n"
            "    )\n"
        )

    before = scan_source(emit + _caller("caller_a") + _caller("caller_b"), path="shrunk.py")
    after = scan_source(emit + _caller("caller_a"), path="shrunk.py")
    assert before[0].status == after[0].status
    assert before[0].operations == after[0].operations

    diff = format_inventory_diff(before, after)

    assert "status/content changes (1):" in diff
    assert "content changed" in diff


def test_format_inventory_diff_change_detail_omits_an_unchanged_status() -> None:
    header = "from pkcs11_check import classification as C\n"
    derive = scan_source(
        header + "def check() -> None:\n" + '    C.record_as("x", operation="C_DeriveKey")\n',
        path="changed.py",
    )
    encrypt = scan_source(
        header + "def check() -> None:\n" + '    C.record_as("x", operation="C_Encrypt")\n',
        path="changed.py",
    )

    diff = format_inventory_diff(derive, encrypt)

    assert "status/content changes (1):" in diff
    assert "status non_readback -> non_readback" not in diff
    assert "ops ('C_DeriveKey',) -> ('C_Encrypt',)" in diff


def test_format_inventory_diff_reports_caller_only_moves() -> None:
    before = _scan(
        """
        from pkcs11_check import classification as C

        def emit(
            operation: str = "C_GetAttributeValue",
            mechanism: str | None = None,
            inherit_mechanism: bool = False,
        ) -> None:
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )

        def caller() -> None:
            emit(
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
            )
        """
    )
    after = _scan(
        """
        from pkcs11_check import classification as C

        def emit(
            operation: str = "C_GetAttributeValue",
            mechanism: str | None = None,
            inherit_mechanism: bool = False,
        ) -> None:
            C.record_as(
                "wrong_result",
                operation=operation,
                mechanism=mechanism,
                inherit_mechanism=inherit_mechanism,
            )


        def caller() -> None:
            emit(
                operation="C_GetAttributeValue",
                mechanism=None,
                inherit_mechanism=False,
            )
        """
    )

    diff = format_inventory_diff(before, after)

    assert "coordinate-only moves (1):" in diff
    assert "callers moved" in diff
    assert "status/content changes (0):" in diff


def test_format_inventory_diff_caps_long_path_lists() -> None:
    header = "from pkcs11_check import classification as C\n"
    body = header + "def check() -> None:\n" + '    C.record_as("x", operation="C_DeriveKey")\n'
    after = scan_sources({f"file_{index:02d}.py": body for index in range(60)})

    diff = format_inventory_diff((), after)

    assert "paths: +60 -0" in diff
    paths_block, _, _ = diff.partition("emitters:")
    assert "... +10 more" in paths_block
    assert "  + file_59.py" not in paths_block


@requires_git_tracked_files
@pytest.mark.parametrize("kind", ["none", "scalar", "raising"])
def test_head_inventory_diff_never_raises_on_unformattable_input(kind: str) -> None:
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"

    def _raising() -> Iterator[EmitterFinding]:
        raise RuntimeError("boom")
        yield from ()

    current: object = {"none": None, "scalar": 123, "raising": _raising()}[kind]
    assert head_inventory_diff(root, current).startswith("<inventory diff unavailable:")  # type: ignore[arg-type]


@requires_git_tracked_files
def test_git_head_tree_sources_reads_a_toplevel_tree(tmp_path: Path) -> None:
    (tmp_path / "top.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "mod.py").write_text("VALUE = 2\n", encoding="utf-8")
    for args in (
        ["init"],
        ["-c", "user.email=t@t", "-c", "user.name=t", "add", "."],
        ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "t"],
    ):
        proc = subprocess.run(
            ["git", *args], cwd=tmp_path, capture_output=True, text=True, encoding="utf-8"
        )
        assert proc.returncode == 0, proc.stderr

    sources = git_head_tree_sources(tmp_path)

    assert sources == {"top.py": "VALUE = 1\n", "nested/mod.py": "VALUE = 2\n"}
