"""Path-sensitive AST guard for provider-backed attribute mapping accesses.

This module deliberately lives under ``tests``.  It is a prevention guard for the
``read_attributes`` migration, not a replacement for the runtime helper.  The analysis is
conservative: a value is considered provider-backed only when its provenance can be traced
to ``pkcs11_check.raw.recipes.read_attributes`` (or a bounded local wrapper around it).

The optional-policy inputs are deliberately explicit.  ``optional_defaults`` accepts exact
attribute/default expression pairs only for a spec-grounded default such as
``CKA_TRUST_XXX -> CKT_TRUST_UNKNOWN``.  A helper is trusted as an optional default provider
only when its name is supplied in ``reviewed_optional_helpers`` and its body proves that pair.
Negative-presence oracles use the separate ``reviewed_negative_oracles`` summary input; an
ordinary silent return or comment is never an optionality escape hatch.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

_RECIPES_MODULE: Final = "pkcs11_check.raw.recipes"
_ATTRIBUTE_HELPER_MODULE: Final = "pkcs11_check.testcases._attribute_values"
_CLASSIFICATION_MODULE: Final = "pkcs11_check.classification"
_KNOWN_MODULES: Final = frozenset(
    {_RECIPES_MODULE, _ATTRIBUTE_HELPER_MODULE, _CLASSIFICATION_MODULE}
)
_PROVIDER_CALL: Final = "provider-call"
_PARAM_TAINT: Final = "param"
_MAX_CALL_DEPTH: Final = 8
_MAX_FLOW_ITERATIONS: Final = 8


@dataclass(frozen=True, order=True, slots=True)
class Violation:
    """One deterministic provider-attribute access finding.

    ``path``, ``line``, ``column`` and ``code`` form the stable source identity.  The
    additional expression/provenance fields make a finding useful in a release report while
    keeping equality and sorting deterministic.
    """

    path: str
    line: int
    column: int
    code: str
    message: str
    expression: str = ""
    provenance: str = ""

    @property
    def kind(self) -> str:
        """Alias used by callers that call diagnostic codes ``kind``."""
        return self.code

    @property
    def col(self) -> int:
        """Short alias for the one-based source column."""
        return self.column

    @property
    def lineno(self) -> int:
        """Alias matching :mod:`ast` naming."""
        return self.line

    @property
    def source(self) -> str:
        """The analyzed source path, retained as a named provenance alias."""
        return self.path


@dataclass(frozen=True, slots=True)
class _Value:
    taint: frozenset[str] = frozenset()
    optional: bool = False
    callable_kind: str | None = None
    elements: tuple[_Value, ...] = ()
    mapping: bool = False


@dataclass
class _State:
    env: dict[str, _Value] = field(default_factory=dict)
    bindings: dict[str, str] = field(default_factory=dict)
    facts: set[tuple[str, str, str]] = field(default_factory=set)
    present_values: set[str] = field(default_factory=set)
    missing_values: set[str] = field(default_factory=set)

    def copy(self) -> _State:
        return _State(
            env=dict(self.env),
            bindings=dict(self.bindings),
            facts=set(self.facts),
            present_values=set(self.present_values),
            missing_values=set(self.missing_values),
        )


@dataclass
class _Flow:
    state: _State | None
    returns: list[_Value] = field(default_factory=list)
    terminal_states: list[_State] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _Function:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    qualified_name: str


def _value_union(values: list[_Value]) -> _Value:
    if not values:
        return _Value()
    taint: set[str] = set()
    optional = False
    callables = {value.callable_kind for value in values}
    elements: tuple[_Value, ...] = ()
    if all(value.elements for value in values):
        width = len(values[0].elements)
        if all(len(value.elements) == width for value in values):
            elements = tuple(
                _value_union([value.elements[index] for value in values]) for index in range(width)
            )
    for value in values:
        taint.update(value.taint)
        optional |= value.optional
    callable_kind = next(iter(callables)) if len(callables) == 1 else None
    return _Value(
        taint=frozenset(taint),
        optional=optional,
        callable_kind=callable_kind,
        elements=elements,
        mapping=any(value.mapping for value in values),
    )


def _merge_states(states: list[_State]) -> _State | None:
    if not states:
        return None
    names = set().union(*(state.env for state in states))
    env = {
        name: _value_union([state.env.get(name, _Value()) for state in states]) for name in names
    }
    binding_names = set().union(*(state.bindings for state in states))
    bindings = {
        name: states[0].bindings[name]
        for name in binding_names
        if all(state.bindings.get(name) == states[0].bindings.get(name) for state in states)
        and name in states[0].bindings
    }
    facts = set.intersection(*(state.facts for state in states))
    present = set.intersection(*(state.present_values for state in states))
    missing = set.intersection(*(state.missing_values for state in states))
    return _State(env, bindings, facts, present, missing)


def _expr_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return type(node).__name__


def _key_text(node: ast.AST) -> str:
    return _expr_text(node).strip()


class _Analyzer:
    def __init__(self, source: str, path: str) -> None:
        self.source = source
        self.path = path
        self.violations: dict[tuple[str, int, int, str, str], Violation] = {}
        self.functions: dict[str, _Function] = {}
        self.function_names_by_node: dict[int, str] = {}
        self.global_bindings: dict[str, str] = {}
        self.called_functions: set[str] = set()
        self.reviewed_optional_helpers: frozenset[str] = frozenset()
        self.reviewed_negative_oracles: frozenset[str] = frozenset()
        self.optional_defaults: dict[str, str] = {}

    def analyze(
        self,
        tree: ast.Module,
        *,
        reviewed_optional_helpers: Iterable[str] = (),
        reviewed_negative_oracles: Iterable[str] = (),
        optional_defaults: Mapping[str, str] | None = None,
    ) -> list[Violation]:
        self.reviewed_optional_helpers = frozenset(reviewed_optional_helpers)
        self.reviewed_negative_oracles = frozenset(reviewed_negative_oracles)
        self.optional_defaults = dict(optional_defaults or {})
        self._index_module(tree)
        self.called_functions = set()
        module_state = _State(bindings=dict(self.global_bindings))
        module_state.env.update(
            {
                function.qualified_name.rsplit(".", 1)[-1]: _Value(
                    callable_kind=f"function:{function.qualified_name}"
                )
                for function in self.functions.values()
                if "." not in function.qualified_name
            }
        )
        executable = [
            node
            for node in tree.body
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self._exec_block(executable, module_state, call_stack=(), top_level=True)
        pending = list(self.functions.values())
        scheduled = {function.qualified_name for function in pending}
        index = 0
        while index < len(pending):
            function = pending[index]
            index += 1
            self._analyze_function(
                function,
                {},
                call_stack=(),
                top_level=False,
            )
            for discovered in tuple(self.functions.values()):
                if discovered.qualified_name not in scheduled:
                    pending.append(discovered)
                    scheduled.add(discovered.qualified_name)
        for function in pending:
            if function.qualified_name not in self.called_functions:
                self._analyze_function(function, {}, call_stack=(), top_level=True)
        return sorted(self.violations.values())

    def _index_module(self, tree: ast.Module) -> None:
        self.functions.clear()
        self.function_names_by_node.clear()
        self._collect_functions(tree, ())
        bindings: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".", 1)[0]
                    if alias.name == _RECIPES_MODULE:
                        module_path = alias.name if alias.asname else bound
                        bindings[bound] = f"module:{module_path}"
                    elif alias.name == _ATTRIBUTE_HELPER_MODULE:
                        module_path = alias.name if alias.asname else bound
                        bindings[bound] = f"module:{module_path}"
                    elif alias.name == _CLASSIFICATION_MODULE:
                        module_path = alias.name if alias.asname else bound
                        bindings[bound] = f"module:{module_path}"
                    else:
                        bindings[bound] = "unknown"
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    bound = alias.asname or alias.name
                    imported_module = f"{module}.{alias.name}"
                    if imported_module in _KNOWN_MODULES:
                        bindings[bound] = f"module:{imported_module}"
                    elif module == _RECIPES_MODULE and alias.name == "read_attributes":
                        bindings[bound] = "direct"
                    elif module == _ATTRIBUTE_HELPER_MODULE:
                        if alias.name == "attr_or_record":
                            bindings[bound] = "helper"
                        elif alias.name == "MISSING_ATTRIBUTE":
                            bindings[bound] = "sentinel"
                    elif module == _CLASSIFICATION_MODULE and alias.name == "record_as":
                        bindings[bound] = "record"
                    else:
                        bindings[bound] = "unknown"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bindings.pop(node.name, None)
            else:
                for name in self._assigned_names(node):
                    bindings.pop(name, None)
        self.global_bindings = bindings

    def _collect_functions(self, node: ast.AST, scope: tuple[str, ...]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified_name = ".".join((*scope, node.name))
            self.functions[qualified_name] = _Function(node, qualified_name)
            self.function_names_by_node[id(node)] = qualified_name
            for child in node.body:
                self._collect_functions(child, (*scope, node.name))
            return
        if isinstance(node, ast.ClassDef):
            class_scope = (*scope, node.name)
            for child in node.body:
                self._collect_functions(child, class_scope)
            return
        for child_node in ast.iter_child_nodes(node):
            self._collect_functions(child_node, scope)

    @staticmethod
    def _assigned_names(node: ast.AST) -> set[str]:
        names: set[str] = set()

        def collect(current: ast.AST) -> None:
            if current is not node and isinstance(
                current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                names.add(current.name)
                return
            if isinstance(current, ast.Name) and isinstance(current.ctx, ast.Store):
                names.add(current.id)
            elif isinstance(current, ast.Import):
                names.update(alias.asname or alias.name.split(".", 1)[0] for alias in current.names)
            elif isinstance(current, ast.ImportFrom):
                names.update(alias.asname or alias.name for alias in current.names)
            for child in ast.iter_child_nodes(current):
                collect(child)

        collect(node)
        return names

    def _local_names(self, function: _Function) -> set[str]:
        names = self._assigned_names(function.node)
        arguments = function.node.args
        names.update(
            arg.arg for arg in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
        )
        if arguments.vararg is not None:
            names.add(arguments.vararg.arg)
        if arguments.kwarg is not None:
            names.add(arguments.kwarg.arg)
        return names

    def _resolve_function(self, name: str, call_stack: tuple[str, ...]) -> _Function | None:
        scope = call_stack[-1].split(".") if call_stack else []
        for length in range(len(scope), -1, -1):
            qualified_name = ".".join((*scope[:length], name))
            function = self.functions.get(qualified_name)
            if function is not None:
                return function
        return None

    def _resolve_called_function(
        self,
        node: ast.expr,
        callable_value: _Value,
        state: _State,
        call_stack: tuple[str, ...],
    ) -> _Function | None:
        if callable_value.callable_kind is not None:
            prefix = "function:"
            if callable_value.callable_kind.startswith(prefix):
                return self.functions.get(callable_value.callable_kind.removeprefix(prefix))
            return None
        if isinstance(node, ast.Name) and node.id not in state.env:
            return self._resolve_function(node.id, call_stack)
        return None

    def _analyze_function(
        self,
        function: _Function,
        argument_values: dict[str, _Value],
        *,
        call_stack: tuple[str, ...],
        top_level: bool,
    ) -> _Value:
        if len(call_stack) >= _MAX_CALL_DEPTH or function.qualified_name in call_stack:
            return _Value()
        local_names = self._local_names(function)
        bindings = {
            name: kind for name, kind in self.global_bindings.items() if name not in local_names
        }
        state = _State(env=dict(argument_values), bindings=bindings)
        for name in local_names:
            state.env.setdefault(name, _Value())
        reviewed = self._is_reviewed_optional_helper(function)
        flow = self._exec_block(
            list(function.node.body),
            state,
            call_stack=(*call_stack, function.qualified_name),
            top_level=top_level,
        )
        result = _value_union(flow.returns)
        if reviewed and result.taint:
            self._check_taint_escape(
                function.node, result, "reviewed optional helper returned provider mapping"
            )
        return result

    def _exec_block(
        self,
        statements: list[ast.stmt],
        state: _State,
        *,
        call_stack: tuple[str, ...],
        top_level: bool,
    ) -> _Flow:
        current: _State | None = state
        returns: list[_Value] = []
        terminal_states: list[_State] = []
        for statement in statements:
            if current is None:
                break
            result = self._exec_stmt(statement, current, call_stack=call_stack, top_level=top_level)
            current = result.state
            returns.extend(result.returns)
            terminal_states.extend(result.terminal_states)
        return _Flow(current, returns, terminal_states)

    def _exec_stmt(
        self,
        node: ast.stmt,
        state: _State,
        *,
        call_stack: tuple[str, ...],
        top_level: bool,
    ) -> _Flow:
        if isinstance(node, ast.Return):
            value = self._eval_expr(node.value, state, call_stack=call_stack)
            if top_level:
                if node.value is not None:
                    self._check_optional(node.value, value, state)
                self._check_taint_escape(node, value, "returning provider-backed mapping")
            return _Flow(None, [value], [state.copy()])
        if isinstance(node, (ast.Raise, ast.Break, ast.Continue)):
            if isinstance(node, ast.Raise) and node.exc is not None:
                self._eval_expr(node.exc, state, call_stack=call_stack)
            return _Flow(None, terminal_states=[state.copy()])
        if isinstance(node, ast.Assign):
            value = self._eval_expr(node.value, state, call_stack=call_stack)
            for target in node.targets:
                if not isinstance(target, (ast.Name, ast.Tuple, ast.List, ast.Starred)):
                    self._check_taint_escape(target, value, "storing provider-backed mapping")
                self._assign(target, value, state, call_stack=call_stack)
            return _Flow(state)
        if isinstance(node, ast.AnnAssign):
            value = (
                self._eval_expr(node.value, state, call_stack=call_stack)
                if node.value
                else _Value()
            )
            if not isinstance(node.target, (ast.Name, ast.Tuple, ast.List, ast.Starred)):
                self._check_taint_escape(node.target, value, "storing provider-backed mapping")
            self._assign(node.target, value, state, call_stack=call_stack)
            return _Flow(state)
        if isinstance(node, ast.AugAssign):
            current = self._eval_expr(node.target, state, call_stack=call_stack)
            value = self._eval_expr(node.value, state, call_stack=call_stack)
            self._check_optional(node.value, value, state)
            self._check_optional(node.target, current, state)
            self._check_taint_escape(node.target, current, "mutating provider-backed mapping")
            self._assign(node.target, _Value(), state, call_stack=call_stack)
            return _Flow(state)
        if isinstance(node, ast.Delete):
            for target in node.targets:
                self._delete_target(target, state, call_stack=call_stack)
            return _Flow(state)
        if isinstance(node, ast.Expr):
            self._eval_expr(node.value, state, call_stack=call_stack)
            return _Flow(state)
        if isinstance(node, ast.Assert):
            probe = state.copy()
            self._eval_expr(node.test, probe, call_stack=call_stack)
            membership = self._first_provider_membership(node.test, state)
            if membership is not None:
                self._emit(
                    node,
                    "unstructured_absence",
                    "raw membership assertion does not classify an absent provider attribute",
                    membership[1],
                )
            refined = self._refine(probe, node.test, truth=True)
            return _Flow(refined)
        if isinstance(node, ast.If):
            return self._exec_if(node, state, call_stack=call_stack, top_level=top_level)
        if isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
            return self._exec_loop(node, state, call_stack=call_stack, top_level=top_level)
        if isinstance(node, ast.Match):
            return self._exec_match(node, state, call_stack=call_stack, top_level=top_level)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            with_state = state
            for item in node.items:
                self._eval_expr(item.context_expr, with_state, call_stack=call_stack)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, _Value(), with_state, call_stack=call_stack)
            return self._exec_block(
                list(node.body), with_state, call_stack=call_stack, top_level=top_level
            )
        if isinstance(node, ast.Try):
            flows: list[_Flow] = [
                self._exec_block(
                    list(node.body), state.copy(), call_stack=call_stack, top_level=top_level
                )
            ]
            for handler in node.handlers:
                handler_state = state.copy()
                if handler.name:
                    handler_state.env[handler.name] = _Value()
                flows.append(
                    self._exec_block(
                        list(handler.body),
                        handler_state,
                        call_stack=call_stack,
                        top_level=top_level,
                    )
                )
            if node.orelse:
                flows.append(
                    self._exec_block(
                        list(node.orelse), state.copy(), call_stack=call_stack, top_level=top_level
                    )
                )
            alive = _merge_states([flow.state for flow in flows if flow.state is not None])
            returns = [value for flow in flows for value in flow.returns]
            terminal_states = [state for flow in flows for state in flow.terminal_states]
            if node.finalbody:
                final_base = alive or _merge_states(terminal_states) or state.copy()
                final = self._exec_block(
                    list(node.finalbody), final_base, call_stack=call_stack, top_level=top_level
                )
                return _Flow(
                    final.state,
                    [*returns, *final.returns],
                    [*terminal_states, *final.terminal_states],
                )
            return _Flow(alive, returns, terminal_states)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            state.bindings.pop(node.name, None)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qualified_name = self.function_names_by_node.get(id(node))
                if qualified_name is not None:
                    state.env[node.name] = _Value(callable_kind=f"function:{qualified_name}")
                else:
                    state.env[node.name] = _Value()
            else:
                state.env[node.name] = _Value()
            return _Flow(state)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self._apply_import(node, state)
            return _Flow(state)
        if isinstance(node, (ast.Global, ast.Nonlocal, ast.Pass)):
            return _Flow(state)
        return _Flow(state)

    def _exec_if(
        self,
        node: ast.If,
        state: _State,
        *,
        call_stack: tuple[str, ...],
        top_level: bool,
    ) -> _Flow:
        self._check_absence_guard(node, state, call_stack=call_stack)
        true_state = state.copy()
        test_value = self._eval_expr(node.test, true_state, call_stack=call_stack)
        if not isinstance(node.test, ast.BoolOp):
            self._check_optional(node.test, test_value, true_state)
        true_state = self._refine(true_state, node.test, truth=True)
        false_state = state.copy()
        self._eval_expr(node.test, false_state, call_stack=call_stack)
        false_state = self._refine(false_state, node.test, truth=False)
        true_flow = self._exec_block(
            list(node.body), true_state, call_stack=call_stack, top_level=top_level
        )
        false_body = node.orelse
        false_flow = self._exec_block(
            list(false_body), false_state, call_stack=call_stack, top_level=top_level
        )
        alive = _merge_states(
            [flow.state for flow in (true_flow, false_flow) if flow.state is not None]
        )
        returns = [*true_flow.returns, *false_flow.returns]
        terminal_states = [*true_flow.terminal_states, *false_flow.terminal_states]
        return _Flow(alive, returns, terminal_states)

    def _check_absence_guard(
        self, node: ast.If, state: _State, *, call_stack: tuple[str, ...]
    ) -> None:
        membership = self._provider_membership(node.test, state)
        if membership is None and isinstance(node.test, ast.BoolOp):
            membership = self._first_provider_membership(node.test, state)
        if membership is None:
            return
        key, mapping, operator = membership
        if isinstance(node.test, ast.BoolOp):
            self._emit(
                node,
                "unstructured_absence",
                "compound membership guard does not classify provider-attribute absence",
                mapping,
            )
            return
        if (
            isinstance(operator, ast.In)
            and not node.orelse
            and not self._contains_terminal(node.body)
        ):
            self._emit(
                node,
                "unstructured_absence",
                "positive provider membership guard has no total absence path",
                mapping,
            )
            return
        missing_body = node.body if isinstance(operator, ast.NotIn) else node.orelse
        if not missing_body:
            return
        if not self._contains_terminal(missing_body):
            return
        if self._structured_absence(missing_body, key, state):
            return
        if self._reviewed_optional_absence_allowed(key, call_stack):
            return
        self._emit(
            node,
            "unstructured_absence",
            "silent provider-attribute absence branch; record the exact attribute "
            "or use a reviewed default",
            mapping,
        )

    def _reviewed_optional_absence_allowed(self, key: str, call_stack: tuple[str, ...]) -> bool:
        if not call_stack or key not in self.optional_defaults:
            return False
        function = self.functions.get(call_stack[-1])
        return function is not None and self._is_reviewed_optional_helper(function)

    @staticmethod
    def _contains_terminal(statements: list[ast.stmt]) -> bool:
        return any(
            isinstance(child, (ast.Return, ast.Continue, ast.Break, ast.Raise))
            for statement in statements
            for child in ast.walk(statement)
        )

    def _provider_membership(
        self, test: ast.expr, state: _State
    ) -> tuple[str, _Value, ast.cmpop] | None:
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and len(test.comparators) == 1
            and isinstance(test.ops[0], (ast.In, ast.NotIn))
        ):
            return None
        mapping = self._eval_expr(test.comparators[0], state, call_stack=())
        if not mapping.taint:
            return None
        return _key_text(test.left), mapping, test.ops[0]

    def _is_missing_sentinel(self, node: ast.expr, state: _State) -> bool:
        return isinstance(node, ast.Name) and state.bindings.get(node.id) == "sentinel"

    def _first_provider_membership(
        self, test: ast.expr, state: _State
    ) -> tuple[str, _Value, ast.cmpop] | None:
        for child in ast.walk(test):
            if isinstance(child, ast.Compare):
                membership = self._provider_membership(child, state)
                if membership is not None:
                    return membership
        return None

    def _structured_absence(self, statements: list[ast.stmt], key: str, state: _State) -> bool:
        for index, statement in enumerate(statements[:-1]):
            if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
                continue
            child = statement.value
            if self._eval_expr(child.func, state, call_stack=()).callable_kind != "record":
                continue
            operation = next(
                (keyword.value for keyword in child.keywords if keyword.arg == "operation"),
                None,
            )
            detail = next(
                (keyword.value for keyword in child.keywords if keyword.arg == "detail"),
                None,
            )
            if not (
                isinstance(operation, ast.Constant)
                and operation.value == "C_GetAttributeValue"
                and detail is not None
                and self._detail_matches_key(detail, key)
                and not any(keyword.arg in {"actual", "actual_ckr"} for keyword in child.keywords)
            ):
                continue
            if any(
                isinstance(next_statement, (ast.Return, ast.Continue, ast.Break, ast.Raise))
                for next_statement in statements[index + 1 :]
            ):
                return True
        return False

    @staticmethod
    def _detail_matches_key(detail: ast.expr, key: str) -> bool:
        if isinstance(detail, ast.Constant) and isinstance(detail.value, str):
            return re.search(rf"\b{re.escape(key)}\b", detail.value) is not None
        return _key_text(detail) == key

    def _is_reviewed_optional_helper(self, function: _Function) -> bool:
        if function.qualified_name not in self.reviewed_optional_helpers:
            return False
        for child in ast.walk(function.node):
            if not isinstance(child, ast.If) or not isinstance(child.test, ast.Compare):
                continue
            if not (
                len(child.test.ops) == 1
                and len(child.test.comparators) == 1
                and isinstance(child.test.ops[0], (ast.In, ast.NotIn))
            ):
                continue
            key = _key_text(child.test.left)
            if key not in self.optional_defaults:
                continue
            mapping = _key_text(child.test.comparators[0])
            absent_body = child.body if isinstance(child.test.ops[0], ast.NotIn) else child.orelse
            absent_returns = [
                node.value
                for statement in absent_body
                for node in ast.walk(statement)
                if isinstance(node, ast.Return) and node.value is not None
            ]
            if not any(_key_text(value) == self.optional_defaults[key] for value in absent_returns):
                continue
            if any(
                isinstance(node, ast.Subscript)
                and _key_text(node.value) == mapping
                and _key_text(node.slice) == key
                for node in ast.walk(function.node)
            ):
                return True
        return False

    def _record_call_is_resolved(self, node: ast.Call, function: _Function) -> bool:
        local_names = self._local_names(function)
        if isinstance(node.func, ast.Name):
            return (
                node.func.id == "record_as"
                and "record_as" not in local_names
                and self.global_bindings.get("record_as") == "record"
            )
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "record_as":
            return False
        if not isinstance(node.func.value, ast.Name):
            return False
        module_binding = self.global_bindings.get(node.func.value.id)
        return (
            node.func.value.id not in local_names
            and module_binding == f"module:{_CLASSIFICATION_MODULE}"
        )

    def _record_mentions_key(self, node: ast.Call, key: str) -> bool:
        detail = next((keyword.value for keyword in node.keywords if keyword.arg == "detail"), None)
        if isinstance(detail, ast.Constant) and isinstance(detail.value, str):
            return re.search(rf"\b{re.escape(key)}\b", detail.value) is not None
        return detail is not None and _key_text(detail) == key

    def _negative_oracle_summary(self, function: _Function) -> tuple[str, ast.If] | None:
        for child in ast.walk(function.node):
            if not isinstance(child, ast.If) or not isinstance(child.test, ast.Compare):
                continue
            if not (
                len(child.test.ops) == 1
                and len(child.test.comparators) == 1
                and isinstance(child.test.ops[0], (ast.In, ast.NotIn))
            ):
                continue
            key = _key_text(child.test.left)
            present_body = child.body if isinstance(child.test.ops[0], ast.In) else child.orelse
            if not any(
                isinstance(node, ast.Call)
                and (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "record_as"
                    or isinstance(node.func, ast.Attribute)
                    and node.func.attr == "record_as"
                )
                and self._record_mentions_key(node, key)
                for statement in present_body
                for node in ast.walk(statement)
            ):
                continue
            if not any(
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Constant)
                and node.value.value is False
                for statement in present_body
                for node in ast.walk(statement)
            ):
                continue
            return key, child
        return None

    def _is_reviewed_negative_oracle(self, function: _Function) -> bool:
        if function.qualified_name not in self.reviewed_negative_oracles:
            return False
        summary = self._negative_oracle_summary(function)
        if summary is None:
            return False
        _key, membership = summary
        if not isinstance(membership.test, ast.Compare):
            return False
        present_body = (
            membership.body if isinstance(membership.test.ops[0], ast.In) else membership.orelse
        )
        if not any(
            isinstance(descendant, ast.Call) and self._record_call_is_resolved(descendant, function)
            for statement in present_body
            for descendant in ast.walk(statement)
        ):
            return False
        if self._has_direct_boolean_return(membership.orelse, True):
            return True
        try:
            index = function.node.body.index(membership)
        except ValueError:
            return False
        return self._has_direct_boolean_return(function.node.body[index + 1 :], True)

    @staticmethod
    def _has_direct_boolean_return(statements: list[ast.stmt], value: bool) -> bool:
        return any(
            isinstance(statement, ast.Return)
            and isinstance(statement.value, ast.Constant)
            and statement.value.value is value
            for statement in statements
        )

    def _exec_loop(
        self,
        node: ast.While | ast.For | ast.AsyncFor,
        state: _State,
        *,
        call_stack: tuple[str, ...],
        top_level: bool,
    ) -> _Flow:
        loop_state = state.copy()
        returns: list[_Value] = []
        terminal_states: list[_State] = []
        for _ in range(_MAX_FLOW_ITERATIONS):
            body_state = loop_state.copy()
            if isinstance(node, ast.While):
                self._eval_expr(node.test, body_state, call_stack=call_stack)
                body_state = self._refine(body_state, node.test, truth=True)
            else:
                iterable = self._eval_expr(node.iter, body_state, call_stack=call_stack)
                self._check_optional(node.iter, iterable, body_state)
                self._assign(node.target, _Value(), body_state, call_stack=call_stack)
            body_flow = self._exec_block(
                list(node.body), body_state, call_stack=call_stack, top_level=top_level
            )
            next_state = _merge_states(
                [candidate for candidate in (state, body_flow.state) if candidate is not None]
            )
            returns.extend(body_flow.returns)
            terminal_states.extend(body_flow.terminal_states)
            if next_state == loop_state:
                loop_state = next_state
                break
            loop_state = next_state or state.copy()
        alive: _State | None = loop_state
        if node.orelse:
            else_base = alive or state.copy()
            else_flow = self._exec_block(
                list(node.orelse), else_base, call_stack=call_stack, top_level=top_level
            )
            alive = _merge_states(
                [candidate for candidate in (alive, else_flow.state) if candidate is not None]
            )
            returns.extend(else_flow.returns)
            terminal_states.extend(else_flow.terminal_states)
        return _Flow(alive, returns, terminal_states)

    def _exec_match(
        self,
        node: ast.Match,
        state: _State,
        *,
        call_stack: tuple[str, ...],
        top_level: bool,
    ) -> _Flow:
        subject = self._eval_expr(node.subject, state, call_stack=call_stack)
        self._check_optional(node.subject, subject, state)
        flows: list[_Flow] = [_Flow(state.copy())]
        for case in node.cases:
            case_state = state.copy()
            self._bind_pattern(case.pattern, case_state)
            if case.guard is not None:
                self._eval_expr(case.guard, case_state, call_stack=call_stack)
                case_state = self._refine(case_state, case.guard, truth=True)
            flows.append(
                self._exec_block(
                    list(case.body), case_state, call_stack=call_stack, top_level=top_level
                )
            )
        alive = _merge_states([flow.state for flow in flows if flow.state is not None])
        returns = [value for flow in flows for value in flow.returns]
        terminal_states = [candidate for flow in flows for candidate in flow.terminal_states]
        return _Flow(alive, returns, terminal_states)

    @staticmethod
    def _bind_pattern(pattern: ast.pattern, state: _State) -> None:
        for node in ast.walk(pattern):
            if isinstance(node, ast.MatchAs) and node.name is not None:
                state.env[node.name] = _Value()
                state.bindings.pop(node.name, None)
            elif isinstance(node, ast.MatchStar) and node.name is not None:
                state.env[node.name] = _Value()
                state.bindings.pop(node.name, None)
            elif isinstance(node, ast.MatchMapping) and node.rest is not None:
                state.env[node.rest] = _Value()
                state.bindings.pop(node.rest, None)

    def _apply_import(self, node: ast.Import | ast.ImportFrom, state: _State) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                state.bindings.pop(bound, None)
                if alias.name in {
                    _RECIPES_MODULE,
                    _ATTRIBUTE_HELPER_MODULE,
                    _CLASSIFICATION_MODULE,
                }:
                    module_path = alias.name if alias.asname else bound
                    state.bindings[bound] = f"module:{module_path}"
        else:
            module = node.module or ""
            for alias in node.names:
                bound = alias.asname or alias.name
                state.bindings.pop(bound, None)
                imported_module = f"{module}.{alias.name}"
                if imported_module in _KNOWN_MODULES:
                    state.bindings[bound] = f"module:{imported_module}"
                elif module == _RECIPES_MODULE and alias.name == "read_attributes":
                    state.bindings[bound] = "direct"
                elif module == _ATTRIBUTE_HELPER_MODULE:
                    if alias.name == "attr_or_record":
                        state.bindings[bound] = "helper"
                    elif alias.name == "MISSING_ATTRIBUTE":
                        state.bindings[bound] = "sentinel"
                elif module == _CLASSIFICATION_MODULE and alias.name == "record_as":
                    state.bindings[bound] = "record"
                else:
                    state.bindings[bound] = "unknown"

    def _assign(
        self, target: ast.expr, value: _Value, state: _State, *, call_stack: tuple[str, ...]
    ) -> None:
        if isinstance(target, ast.Name):
            state.env[target.id] = value
            state.bindings.pop(target.id, None)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if value.mapping:
                self._check_taint_escape(target, value, "destructuring provider-backed mapping")
            for index, element in enumerate(target.elts):
                item = value.elements[index] if index < len(value.elements) else _Value()
                self._assign(element, item, state, call_stack=call_stack)
            return
        if isinstance(target, ast.Starred):
            self._assign(target.value, value, state, call_stack=call_stack)
            return
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            base = self._eval_expr(target.value, state, call_stack=call_stack)
            self._check_optional(target.value, base, state)
            self._check_taint_escape(target, base, "writing through provider-backed mapping")

    def _delete_target(
        self, target: ast.expr, state: _State, *, call_stack: tuple[str, ...]
    ) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._delete_target(element, state, call_stack=call_stack)
            return
        if isinstance(target, ast.Starred):
            self._delete_target(target.value, state, call_stack=call_stack)
            return
        if isinstance(target, (ast.Attribute, ast.Subscript)):
            base = self._eval_expr(target.value, state, call_stack=call_stack)
            self._check_optional(target.value, base, state)
            self._check_taint_escape(target, base, "deleting from provider-backed mapping")

    def _eval_expr(
        self, node: ast.expr | None, state: _State, *, call_stack: tuple[str, ...]
    ) -> _Value:
        if node is None:
            return _Value()
        if isinstance(node, ast.Name):
            binding = state.bindings.get(node.id)
            if binding == "unknown":
                return _Value()
            if binding in {"direct", "helper", "record", "sentinel"}:
                return _Value(callable_kind=binding)
            if binding is not None and binding.startswith("module:"):
                return _Value(callable_kind=binding)
            if node.id in state.env:
                return state.env[node.id]
            function = self._resolve_function(node.id, call_stack)
            if function is not None:
                return _Value(callable_kind=f"function:{function.qualified_name}")
            return _Value()
        if isinstance(node, ast.NamedExpr):
            value = self._eval_expr(node.value, state, call_stack=call_stack)
            self._assign(node.target, value, state, call_stack=call_stack)
            return value
        if isinstance(node, ast.Constant):
            return _Value()
        if isinstance(node, ast.Attribute):
            base = self._eval_expr(node.value, state, call_stack=call_stack)
            module_name = (base.callable_kind or "").removeprefix("module:")
            if module_name == _RECIPES_MODULE and node.attr == "read_attributes":
                return _Value(callable_kind="direct")
            if module_name == _ATTRIBUTE_HELPER_MODULE and node.attr == "attr_or_record":
                return _Value(callable_kind="helper")
            if module_name == _ATTRIBUTE_HELPER_MODULE and node.attr == "MISSING_ATTRIBUTE":
                return _Value(callable_kind="sentinel")
            if module_name == _CLASSIFICATION_MODULE and node.attr == "record_as":
                return _Value(callable_kind="record")
            if node.attr == "copy" and base.taint:
                return _Value(callable_kind="tainted-copy", taint=base.taint)
            if base.callable_kind is not None and base.callable_kind.startswith("module:"):
                return _Value(callable_kind=f"module:{module_name}.{node.attr}")
            if node.attr == "get" and base.taint:
                return _Value(callable_kind="tainted-get", taint=base.taint)
            if base.taint:
                self._check_taint_escape(node, base, "accessing provider-backed mapping attribute")
            return _Value()
        if isinstance(node, ast.Call):
            return self._eval_call(node, state, call_stack=call_stack)
        if isinstance(node, ast.Subscript):
            base = self._eval_expr(node.value, state, call_stack=call_stack)
            key_node = node.slice
            if (
                base.elements
                and isinstance(key_node, ast.Constant)
                and isinstance(key_node.value, int)
            ):
                index = key_node.value
                if 0 <= index < len(base.elements):
                    return base.elements[index]
            if base.taint:
                key = _key_text(key_node)
                if not self._mapping_present(base, key, state):
                    self._emit(
                        node,
                        "unsafe_subscript",
                        "direct subscript of provider-backed attribute mapping",
                        base,
                    )
            self._check_optional(node.value, base, state)
            return _Value()
        if isinstance(node, ast.List):
            values = [
                self._eval_expr(element, state, call_stack=call_stack) for element in node.elts
            ]
            value = _Value(elements=tuple(values))
            if any(item.taint for item in values):
                self._check_taint_escape(
                    node, _value_union(values), "storing provider-backed mapping in a list"
                )
            return value
        if isinstance(node, ast.Tuple):
            tuple_values = tuple(
                self._eval_expr(element, state, call_stack=call_stack) for element in node.elts
            )
            return _Value(
                taint=frozenset().union(*(item.taint for item in tuple_values)),
                elements=tuple_values,
            )
        if isinstance(node, ast.Set):
            values = [
                self._eval_expr(element, state, call_stack=call_stack) for element in node.elts
            ]
            if any(item.taint for item in values):
                self._check_taint_escape(
                    node, _value_union(values), "storing provider-backed mapping in a set"
                )
            return _Value()
        if isinstance(node, ast.Dict):
            values = [
                self._eval_expr(value, state, call_stack=call_stack)
                for value in node.values
                if value is not None
            ]
            if any(item.taint for item in values):
                self._check_taint_escape(
                    node, _value_union(values), "storing provider-backed mapping in a dict"
                )
            return _Value()
        if isinstance(node, ast.BinOp):
            left = self._eval_expr(node.left, state, call_stack=call_stack)
            right = self._eval_expr(node.right, state, call_stack=call_stack)
            self._check_optional(node.left, left, state)
            self._check_optional(node.right, right, state)
            return _Value()
        if isinstance(node, ast.BoolOp):
            bool_values: list[_Value] = []
            eval_state = state.copy()
            for part in node.values:
                value = self._eval_expr(part, eval_state, call_stack=call_stack)
                self._check_optional(part, value, state)
                bool_values.append(value)
                if isinstance(node.op, ast.And):
                    eval_state = self._refine(eval_state, part, truth=True)
            return _value_union(bool_values)
        if isinstance(node, ast.Compare):
            left = self._eval_expr(node.left, state, call_stack=call_stack)
            for comparator in node.comparators:
                right = self._eval_expr(comparator, state, call_stack=call_stack)
                if not (
                    isinstance(node.ops[0], (ast.Is, ast.IsNot))
                    and self._is_missing_sentinel(comparator, state)
                ):
                    self._check_optional(comparator, right, state)
            if not (
                isinstance(node.ops[0], (ast.Is, ast.IsNot))
                and self._is_missing_sentinel(node.comparators[0], state)
            ):
                self._check_optional(node.left, left, state)
            return _Value()
        if isinstance(node, ast.UnaryOp):
            value = self._eval_expr(node.operand, state, call_stack=call_stack)
            self._check_optional(node.operand, value, state)
            return _Value()
        if isinstance(node, ast.IfExp):
            true_state = state.copy()
            self._eval_expr(node.test, true_state, call_stack=call_stack)
            self._refine(true_state, node.test, truth=True)
            false_state = state.copy()
            self._eval_expr(node.test, false_state, call_stack=call_stack)
            self._refine(false_state, node.test, truth=False)
            return _value_union(
                [
                    self._eval_expr(node.body, true_state, call_stack=call_stack),
                    self._eval_expr(node.orelse, false_state, call_stack=call_stack),
                ]
            )
        if isinstance(node, ast.Starred):
            return self._eval_expr(node.value, state, call_stack=call_stack)
        # Unknown expressions can carry a taint only through their children.  Visit them so
        # nested calls and walrus expressions remain visible, but do not invent an escape for
        # syntax such as comprehensions whose result is a new local container.
        values = [
            self._eval_expr(child, state, call_stack=call_stack)
            for child in ast.iter_child_nodes(node)
            if isinstance(child, ast.expr)
        ]
        return _value_union(values)

    def _eval_call(self, node: ast.Call, state: _State, *, call_stack: tuple[str, ...]) -> _Value:
        callable_value = self._eval_expr(node.func, state, call_stack=call_stack)
        args = [self._eval_expr(argument, state, call_stack=call_stack) for argument in node.args]
        kwargs = [
            self._eval_expr(keyword.value, state, call_stack=call_stack)
            for keyword in node.keywords
        ]
        values = [*args, *kwargs]

        if callable_value.callable_kind == "direct":
            token = f"{_PROVIDER_CALL}:{self.path}:{node.lineno}:{node.col_offset + 1}"
            return _Value(taint=frozenset({token}), mapping=True)
        if callable_value.callable_kind == "helper":
            return _Value(optional=True)
        if callable_value.callable_kind == "record":
            return _Value()
        if callable_value.callable_kind == "tainted-copy":
            return _Value(taint=callable_value.taint, mapping=True)
        if callable_value.callable_kind == "tainted-get":
            base_taint = callable_value.taint
            key = _key_text(node.args[0]) if node.args else "<unknown>"
            has_reviewed_default = len(node.args) >= 2 and self.optional_defaults.get(
                key
            ) == _key_text(node.args[1])
            if not has_reviewed_default and not self._mapping_present(
                _Value(taint=base_taint, mapping=True), key, state
            ):
                self._emit(
                    node,
                    "unsafe_get",
                    "direct .get() of provider-backed attribute mapping",
                    callable_value,
                )
            return _Value()

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "dict"
            and len(args) == 1
            and not node.keywords
            and args[0].taint
        ):
            return _Value(taint=args[0].taint, mapping=True)

        function = self._resolve_called_function(node.func, callable_value, state, call_stack)
        if function is not None:
            self.called_functions.add(function.qualified_name)
            if (
                any(value.taint for value in values)
                and self._negative_oracle_summary(function) is not None
            ):
                if not self._is_reviewed_negative_oracle(function):
                    self._emit(
                        node,
                        "unstructured_absence",
                        "negative-presence oracle needs an explicit reviewed helper summary",
                        _value_union(values),
                    )
            argument_values: dict[str, _Value] = {}
            positional = [
                *function.node.args.posonlyargs,
                *function.node.args.args,
            ]
            for parameter, value in zip(positional, args, strict=False):
                argument_values[parameter.arg] = value
            for keyword, value in zip(node.keywords, kwargs, strict=True):
                if keyword.arg is not None:
                    argument_values[keyword.arg] = value
            if function.node.args.vararg is not None:
                argument_values[function.node.args.vararg.arg] = _Value(
                    elements=tuple(args[len(positional) :])
                )
            if function.qualified_name in call_stack or len(call_stack) >= _MAX_CALL_DEPTH:
                tainted = _value_union(values)
                if tainted.taint:
                    self._check_taint_escape(node, tainted, "unresolved recursive helper argument")
                return _Value()
            return self._analyze_function(
                function, argument_values, call_stack=call_stack, top_level=False
            )

        for value in values:
            self._check_optional(node, value, state)
            if value.taint:
                self._check_taint_escape(
                    node, value, "passing provider-backed mapping to unknown call"
                )
        return _Value()

    def _mapping_present(self, value: _Value, key: str, state: _State) -> bool:
        return bool(value.taint) and all(
            ("present", token, key) in state.facts for token in value.taint
        )

    def _refine(self, state: _State, test: ast.expr, *, truth: bool) -> _State:
        refined = state.copy()
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._refine(refined, test.operand, truth=not truth)
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) and truth:
            for part in test.values:
                refined = self._refine(refined, part, truth=True)
            return refined
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
            op = test.ops[0]
            comparator = test.comparators[0]
            if isinstance(op, (ast.In, ast.NotIn)):
                mapping = self._eval_expr(comparator, refined, call_stack=())
                key = _key_text(test.left)
                present = truth if isinstance(op, ast.In) else not truth
                for token in mapping.taint:
                    refined.facts.discard(("present" if not present else "absent", token, key))
                    refined.facts.add(("present" if present else "absent", token, key))
            elif isinstance(op, (ast.Is, ast.IsNot)) and isinstance(test.left, ast.Name):
                right = comparator
                if self._is_missing_sentinel(right, refined):
                    missing = truth if isinstance(op, ast.Is) else not truth
                    refined.present_values.discard(test.left.id)
                    refined.missing_values.discard(test.left.id)
                    (refined.missing_values if missing else refined.present_values).add(
                        test.left.id
                    )
        return refined

    def _check_optional(self, node: ast.AST, value: _Value, state: _State) -> None:
        if not value.optional:
            return
        if isinstance(node, ast.Name) and node.id in state.present_values:
            return
        self._emit(
            node,
            "unstructured_absence",
            "attr_or_record() result used without checking MISSING_ATTRIBUTE",
            value,
        )

    def _check_taint_escape(self, node: ast.AST, value: _Value, action: str) -> None:
        if value.taint:
            self._emit(node, "taint_escape", action, value)

    def _emit(self, node: ast.AST, kind: str, detail: str, value: _Value) -> None:
        provenance = sorted(value.taint)[0] if value.taint else ""
        violation = Violation(
            path=self.path,
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 0) + 1,
            code=kind,
            message=f"{detail}; use attr_or_record() for provider-backed attributes",
            expression=_expr_text(node),
            provenance=provenance,
        )
        identity = (
            violation.path,
            violation.line,
            violation.column,
            violation.code,
            violation.message,
        )
        existing = self.violations.get(identity)
        if existing is None or violation.provenance < existing.provenance:
            self.violations[identity] = violation


def analyze_source(
    source: str,
    *,
    path: str = "<string>",
    reviewed_optional_helpers: Iterable[str] = (),
    reviewed_negative_oracles: Iterable[str] = (),
    optional_defaults: Mapping[str, str] | None = None,
) -> list[Violation]:
    """Analyze Python source and return stable, source-provenance-aware violations."""
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [
            Violation(
                path=path,
                line=exc.lineno or 1,
                column=exc.offset or 1,
                code="syntax_error",
                message=str(exc),
            )
        ]
    return _Analyzer(source, path).analyze(
        tree,
        reviewed_optional_helpers=reviewed_optional_helpers,
        reviewed_negative_oracles=reviewed_negative_oracles,
        optional_defaults=optional_defaults,
    )


def analyze_file(
    path: str | Path,
    *,
    reviewed_optional_helpers: Iterable[str] = (),
    reviewed_negative_oracles: Iterable[str] = (),
    optional_defaults: Mapping[str, str] | None = None,
) -> list[Violation]:
    """Analyze a UTF-8 Python file, retaining its exact path in every finding."""
    file_path = Path(path)
    return analyze_source(
        file_path.read_text(encoding="utf-8"),
        path=str(file_path),
        reviewed_optional_helpers=reviewed_optional_helpers,
        reviewed_negative_oracles=reviewed_negative_oracles,
        optional_defaults=optional_defaults,
    )


def analyze_paths(
    paths: Iterable[str | Path],
    *,
    reviewed_optional_helpers: Iterable[str] = (),
    reviewed_negative_oracles: Iterable[str] = (),
    optional_defaults: Mapping[str, str] | None = None,
) -> list[Violation]:
    """Analyze multiple files and return one stable, source-sorted diagnostic list."""
    violations = [
        violation
        for path in paths
        for violation in analyze_file(
            path,
            reviewed_optional_helpers=reviewed_optional_helpers,
            reviewed_negative_oracles=reviewed_negative_oracles,
            optional_defaults=optional_defaults,
        )
    ]
    return sorted(violations)


# Friendly aliases make the small test utility convenient for future migration slices.
scan_source = analyze_source
scan_file = analyze_file
find_violations = analyze_source
