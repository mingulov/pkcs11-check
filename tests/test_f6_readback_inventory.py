"""Fail-closed tests for the F6 effective-emitter inventory."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from tests._f6_readback_inventory import (
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
    characterize_tree,
    coordinate_census,
    corpus_digest,
    flatten_effective_states,
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


def test_direct_emitters_distinguish_all_relational_f6_states() -> None:
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


def test_current_tree_characterization_is_non_vacuous_pinned_and_not_zero_gate() -> None:
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
    characterization = characterize_tree(root)

    assert root.is_dir()
    assert characterization.total == 1679
    assert characterization.candidate_total == 1507
    assert characterization.file_total == 246
    assert characterization.statuses == (
        ("explicit_mechanism_grouping", 512),
        ("explicit_mechanism_readback", 46),
        ("non_readback", 172),
        ("safe_mechanism_free_readback", 59),
        ("unresolved", 799),
        ("unsafe_inherited_readback", 91),
    )
    assert characterization.digest == (
        "8ce6f97e1a19b7b2342d22e1417cead12f21fa8a19c89b23e101720621de8dce"
    )
    assert characterization.candidate_digest == (
        "4d78d449ecf0f684dd638c884b769168cd6fca94a3ba875480ad4d50c76244e2"
    )
    assert characterization.state_statuses == (
        ("explicit_mechanism_grouping", 1233),
        ("explicit_mechanism_readback", 339),
        ("non_readback", 352),
        ("safe_mechanism_free_readback", 1380),
        ("unresolved", 2658),
        ("unsafe_inherited_readback", 254),
    )
    assert characterization.mixed_unsafe_states == 27
    assert characterization.corpus_digest == (
        "e0dc40590c7cdaf4ec3a4ea90a186bcd85a102802f917ed3c561edca721425ed"
    )
    assert characterization.direct_emitter_census == (
        ("assert_correct", 268),
        ("classify", 533),
        ("fail_as", 194),
        ("record_as", 257),
        ("xfail_as", 155),
    )

    # These are exact sentinels for the current source tree.  They intentionally characterize
    # outstanding work instead of asserting zero until the reviewed source slices are fixed.
    all_findings = scan_tree(root)
    provisioning = [
        finding
        for finding in all_findings
        if finding.path == "_provisioning.py" and finding.emitter == "record_as"
    ]
    assert provisioning
    assert any(
        finding.line == 114
        and finding.status == STATUS_UNRESOLVED
        and all(state.status == STATUS_SAFE_MECHANISM_FREE_READBACK for state in finding.states)
        for finding in provisioning
    )
    assert any(
        finding.line == 114
        and finding.function == "_attribute_refusal"
        and finding.uncertain is True
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
        finding.line == 1286
        and finding.status == STATUS_UNRESOLVED
        and finding.operations == (UNKNOWN_OPERATION,)
        for finding in conftest
    )
    assert any(
        finding.line == 1286
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
