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
import symtable
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Final

_RECIPES_MODULE: Final = "pkcs11_check.raw.recipes"
_ATTRIBUTE_HELPER_MODULE: Final = "pkcs11_check.testcases._attribute_values"
_ATTRIBUTE_FACTS_MODULE: Final = "pkcs11_check.testcases._probes._attribute_facts"
_ATTRIBUTE_PROBES_MODULE: Final = "pkcs11_check.testcases._probes"
_STRICT_RELEVANT_MODULE_PATHS: Final = frozenset(
    {
        "pkcs11_check",
        "pkcs11_check.testcases",
        _ATTRIBUTE_PROBES_MODULE,
        _ATTRIBUTE_FACTS_MODULE,
        f"{_ATTRIBUTE_FACTS_MODULE}.emit_missing_attribute",
        f"{_ATTRIBUTE_FACTS_MODULE}.observe_ec_attribute",
    }
)
_ATTRIBUTE_FACT_HELPER: Final = "emit_missing_attribute"
_ATTRIBUTE_OBSERVER_HELPER: Final = "observe_ec_attribute"
_TYPES_MODULE: Final = "pkcs11_check.raw.types_std"
_CLASSIFICATION_MODULE: Final = "pkcs11_check.classification"
_KNOWN_MODULES: Final = frozenset(
    {_RECIPES_MODULE, _ATTRIBUTE_HELPER_MODULE, _CLASSIFICATION_MODULE}
)
_PROVIDER_CALL: Final = "provider-call"
_PARAM_TAINT: Final = "param"
_UNKNOWN_CALLABLE: Final = "unknown-callable"
_MAX_CALL_DEPTH: Final = 8
_MAX_FLOW_ITERATIONS: Final = 8
_MAX_CLOSURE_STATES: Final = 8


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
    optional_id: str | None = None
    terminal: bool = False
    callable_kind: str | None = None
    callable_kinds: tuple[str, ...] = ()
    callable_closures: tuple[tuple[str, _State | None], ...] = ()
    callable_unknown: bool = False
    closure_state: _State | None = None
    closure_states: tuple[_State, ...] = ()
    elements: tuple[_Value, ...] = ()
    mapping: bool = False
    mapping_id: str | None = None


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
    exits: list[_Exit] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class _Exit:
    kind: str
    state: _State
    value: _Value | None = None
    node: ast.stmt | None = None


@dataclass(frozen=True, slots=True)
class _Function:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    qualified_name: str
    identity: str


def _value_union(values: list[_Value]) -> _Value:
    if not values:
        return _Value()
    taint: set[str] = set()
    optional = False
    terminal = all(value.terminal for value in values)
    callable_candidates: set[str] = set()
    for value in values:
        callable_candidates.update(value.callable_kinds)
        if value.callable_kind is not None and not value.callable_kinds:
            callable_candidates.add(value.callable_kind)
        if value.callable_unknown:
            callable_candidates.add(_UNKNOWN_CALLABLE)
    has_callable_value = bool(callable_candidates)
    callable_unknown = any(value.callable_unknown for value in values) or (
        has_callable_value
        and any(
            not (
                value.callable_kind is not None
                or value.callable_kinds
                or value.callable_closures
                or value.callable_unknown
            )
            for value in values
        )
    )
    callable_closure_candidates: list[tuple[str, _State | None]] = []
    for value in values:
        if value.callable_closures:
            callable_closure_candidates.extend(value.callable_closures)
            continue
        value_kinds = value.callable_kinds or (
            (value.callable_kind,) if value.callable_kind is not None else ()
        )
        value_states = value.closure_states or (
            (value.closure_state,) if value.closure_state is not None else (None,)
        )
        callable_closure_candidates.extend(
            (kind, closure)
            for kind in value_kinds
            if kind.startswith("function:")
            for closure in value_states
        )
    callable_closures = _widen_callable_closures(callable_closure_candidates)
    closure_candidates = [closure for _, closure in callable_closures if closure is not None]
    closure_state = closure_candidates[0] if len(closure_candidates) == 1 else None
    closure_states = tuple(closure_candidates) if len(closure_candidates) > 1 else ()
    elements: tuple[_Value, ...] = ()
    element_values = [value for value in values if value.elements]
    if element_values:
        width = max(len(value.elements) for value in element_values)
        elements = tuple(
            _value_union(
                [
                    value.elements[index] if index < len(value.elements) else _Value()
                    for value in element_values
                ]
            )
            for index in range(width)
        )
    for value in values:
        taint.update(value.taint)
        optional |= value.optional
    callable_kind = next(iter(callable_candidates)) if len(callable_candidates) == 1 else None
    callable_kinds = tuple(sorted(callable_candidates)) if len(callable_candidates) > 1 else ()
    optional_ids = {value.optional_id for value in values}
    optional_id = next(iter(optional_ids)) if len(optional_ids) == 1 else None
    mapping_ids = {value.mapping_id for value in values}
    mapping_id = next(iter(mapping_ids)) if len(mapping_ids) == 1 else None
    return _Value(
        taint=frozenset(taint),
        optional=optional,
        optional_id=optional_id,
        terminal=terminal,
        callable_kind=callable_kind,
        callable_kinds=callable_kinds,
        callable_closures=callable_closures,
        callable_unknown=callable_unknown,
        closure_state=closure_state,
        closure_states=closure_states,
        elements=elements,
        mapping=any(value.mapping for value in values),
        mapping_id=mapping_id,
    )


def _optional_ids(value: _Value) -> set[str]:
    identities = {value.optional_id} if value.optional_id is not None else set()
    for element in value.elements:
        identities.update(_optional_ids(element))
    return identities


def _callable_kinds(value: _Value) -> tuple[str, ...]:
    kinds = value.callable_kinds or (
        (value.callable_kind,) if value.callable_kind is not None else ()
    )
    if value.callable_unknown and _UNKNOWN_CALLABLE not in kinds:
        return (*kinds, _UNKNOWN_CALLABLE)
    return kinds


def _rebase_optional_ids(
    value: _Value,
    *,
    input_ids: set[str],
    call_token: str,
    path: tuple[int, ...] = (),
) -> _Value:
    optional_id = value.optional_id
    if value.optional and optional_id not in input_ids:
        suffix = optional_id or ".".join(str(index) for index in path) or "value"
        optional_id = f"{call_token}:{suffix}"
    elements = tuple(
        _rebase_optional_ids(
            element,
            input_ids=input_ids,
            call_token=call_token,
            path=(*path, index),
        )
        for index, element in enumerate(value.elements)
    )
    return _Value(
        taint=value.taint,
        optional=value.optional,
        optional_id=optional_id,
        terminal=value.terminal,
        callable_kind=value.callable_kind,
        callable_kinds=value.callable_kinds,
        callable_closures=value.callable_closures,
        callable_unknown=value.callable_unknown,
        closure_state=value.closure_state,
        closure_states=value.closure_states,
        elements=elements,
        mapping=value.mapping,
        mapping_id=value.mapping_id,
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


def _widen_callable_closures(
    alternatives: list[tuple[str, _State | None]],
) -> tuple[tuple[str, _State | None], ...]:
    """Bound closure alternatives per function without dropping a possible taint.

    Distinct nested functions must retain their identity-to-cell association.  For one
    function, once the finite alternative budget is exceeded, retain a conservative
    merged cell state in addition to a few concrete states.  State merging unions
    callable bindings and intersects facts, so a provider-backed callable remains a
    possible branch while proven guarantees are never invented.
    """
    grouped: dict[str, list[_State | None]] = {}
    for qualified_name, state in alternatives:
        states = grouped.setdefault(qualified_name, [])
        if all(state is not candidate for candidate in states):
            states.append(state)

    bounded: list[tuple[str, _State | None]] = []
    for qualified_name, states in grouped.items():
        if len(states) <= _MAX_CLOSURE_STATES:
            bounded.extend((qualified_name, state) for state in states)
            continue
        concrete_budget = _MAX_CLOSURE_STATES - 1
        concrete = states[:concrete_budget]
        merged = _merge_states([state for state in states if state is not None])
        if merged is None:
            bounded.extend((qualified_name, state) for state in concrete)
            bounded.append((qualified_name, None))
        else:
            bounded.extend((qualified_name, state) for state in concrete)
            bounded.append((qualified_name, merged))
    return tuple(bounded)


def _expr_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return type(node).__name__


def _key_text(node: ast.AST) -> str:
    return _expr_text(node).strip()


_CHILD_KEYS: Final = frozenset({"CKA_MODULUS", "CKA_EC_POINT", "CKA_EC_PARAMS"})
_RSA_CONTEXTS: Final = frozenset(
    f"decrypt:{mechanism}:{variant}"
    for mechanism in ("pkcs", "oaep")
    for variant in ("random", "truncated", "extended", "all_zeros", "all_ff")
)
_EC_CONTEXT: Final = "ecdh_aes_wrap_compressed_public_key_buffer_too_small"
_UAF_CONTEXT: Final = "derive"


@dataclass(frozen=True, slots=True)
class _ChildEvidenceContract:
    approved: frozenset[tuple[int, int]]
    violations: tuple[Violation, ...]
    observer_approved: frozenset[tuple[int, int, str]] = frozenset()


@dataclass(frozen=True, slots=True)
class _ChildCandidate:
    node: ast.If
    import_node: ast.ImportFrom
    call_node: ast.Call


@dataclass(frozen=True, slots=True)
class _EcPairCandidate:
    import_node: ast.ImportFrom
    calls: tuple[ast.Call, ast.Call]
    reader: ast.Call


def _strict_top_level_function(
    node: ast.AST, parents: Mapping[int, ast.AST]
) -> ast.FunctionDef | None:
    if not isinstance(node, ast.FunctionDef) or not isinstance(parents.get(id(node)), ast.Module):
        return None
    if (
        node.decorator_list
        or node.args.defaults
        or any(default is not None for default in node.args.kw_defaults)
        or node.args.vararg is not None
        or node.args.kwarg is not None
        or getattr(node, "type_params", [])
    ):
        return None
    return node


def _strict_is_canonical_reader_import(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.ImportFrom)
        and node.module == _RECIPES_MODULE
        and node.level == 0
        and len(node.names) == 1
        and node.names[0].name == "read_attributes"
        and node.names[0].asname is None
    )


def _strict_scope_nodes(root: ast.AST) -> Iterable[ast.AST]:
    """Walk ownership-relevant syntax without entering nested function bodies."""
    stack: list[tuple[ast.AST, bool]] = [(root, True)]
    while stack:
        node, is_root = stack.pop()
        yield node
        if not is_root and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            children: list[ast.AST] = [*node.decorator_list, *node.args.defaults]
            children.extend(default for default in node.args.kw_defaults if default is not None)
            children.extend(
                argument.annotation
                for argument in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
                if argument.annotation is not None
            )
            if node.args.vararg is not None and node.args.vararg.annotation is not None:
                children.append(node.args.vararg.annotation)
            if node.args.kwarg is not None and node.args.kwarg.annotation is not None:
                children.append(node.args.kwarg.annotation)
            if node.returns is not None:
                children.append(node.returns)
            children.extend(getattr(node, "type_params", ()))
            stack.extend((child, False) for child in children)
            continue
        if not is_root and isinstance(node, ast.Lambda):
            children = list(node.args.defaults)
            children.extend(default for default in node.args.kw_defaults if default is not None)
            stack.extend((child, False) for child in children)
            continue
        stack.extend((child, False) for child in ast.iter_child_nodes(node))


def _strict_key_owned(tree: ast.Module, function: ast.FunctionDef, key: str) -> bool:
    imports = [
        alias
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == _TYPES_MODULE and node.level == 0
        for alias in node.names
        if alias.name == key and alias.asname is None
    ]
    if len(imports) != 1:
        return False
    return _strict_name_owned(
        tree,
        function,
        key,
        canonical_aliases=frozenset({id(imports[0])}),
    )


def _strict_module_declares(tree: ast.Module, name: str) -> bool:
    """Return whether any lexical scope declares an outward binding for ``name``."""
    return any(
        isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names
        for node in ast.walk(tree)
    )


class _StrictScopeFactsIndex:
    """Index direct binder sites and declarations by AST scope identity."""

    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.declarations: dict[int, set[str]] = {}
        self.node_scopes: dict[int, int | None] = {}
        self.unsupported = False
        self._dispatch(root, None, None, None, None)

    def _new_scope(self, node: ast.AST) -> int:
        scope = id(node)
        self.declarations[scope] = set()
        return scope

    def _dispatch(
        self,
        node: ast.AST,
        scope: int | None,
        walrus_scope: int | None,
        defining_scope: int | None,
        eager_walrus_scope: int | None,
    ) -> None:
        """Dispatch every visited node with its lexical ownership context."""
        self.node_scopes[id(node)] = scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._dispatch_function(node, scope, walrus_scope)
            return
        if isinstance(node, ast.ClassDef):
            self._dispatch_class(node, scope, walrus_scope)
            return
        if isinstance(node, ast.Lambda):
            self._dispatch_lambda(node, scope, walrus_scope)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self._dispatch_comprehension(node, scope, walrus_scope)
            return
        if isinstance(node, ast.comprehension):
            self._dispatch_comprehension_clause(node, scope, walrus_scope)
            return
        if isinstance(node, ast.arguments):
            self._dispatch_arguments(node, scope, defining_scope, eager_walrus_scope)
            return
        if isinstance(node, ast.arg):
            if node.annotation is not None:
                self._dispatch(
                    node.annotation,
                    defining_scope,
                    eager_walrus_scope,
                    defining_scope,
                    eager_walrus_scope,
                )
            return
        if isinstance(node, ast.NamedExpr):
            self._dispatch(node.value, scope, walrus_scope, scope, eager_walrus_scope)
            self._dispatch(
                node.target,
                walrus_scope,
                walrus_scope,
                walrus_scope,
                walrus_scope,
            )
            return
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            if scope is not None:
                self.declarations[scope].update(node.names)
            return
        if isinstance(node, (ast.TypeVar, ast.ParamSpec, ast.TypeVarTuple)):
            for child in ast.iter_child_nodes(node):
                self._dispatch(
                    child,
                    defining_scope,
                    eager_walrus_scope,
                    defining_scope,
                    eager_walrus_scope,
                )
            return
        elif isinstance(node, ast.TypeAlias) and node.type_params:
            self.unsupported = True
        for child in ast.iter_child_nodes(node):
            self._dispatch(child, scope, walrus_scope, defining_scope, eager_walrus_scope)

    def _dispatch_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        parent: int | None,
        walrus_scope: int | None,
    ) -> None:
        scope = self._new_scope(node)
        for decorator in node.decorator_list:
            self._dispatch(decorator, parent, walrus_scope, parent, walrus_scope)
        self._dispatch(node.args, scope, scope, parent, walrus_scope)
        for type_param in getattr(node, "type_params", ()):
            self._dispatch(type_param, scope, scope, parent, walrus_scope)
        if node.returns is not None:
            self._dispatch(node.returns, parent, walrus_scope, parent, walrus_scope)
        for statement in node.body:
            self._dispatch(statement, scope, scope, scope, scope)

    def _dispatch_class(
        self,
        node: ast.ClassDef,
        parent: int | None,
        walrus_scope: int | None,
    ) -> None:
        scope = self._new_scope(node)
        for eager_expression in (*node.decorator_list, *node.bases, *node.keywords):
            self._dispatch(eager_expression, parent, walrus_scope, parent, walrus_scope)
        for type_param in getattr(node, "type_params", ()):
            self._dispatch(type_param, scope, scope, parent, walrus_scope)
        for statement in node.body:
            self._dispatch(statement, scope, scope, scope, scope)

    def _dispatch_lambda(
        self,
        node: ast.Lambda,
        parent: int | None,
        walrus_scope: int | None,
    ) -> None:
        scope = self._new_scope(node)
        self._dispatch(node.args, scope, scope, parent, walrus_scope)
        self._dispatch(node.body, scope, scope, scope, scope)

    def _dispatch_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        parent: int | None,
        walrus_scope: int | None,
    ) -> None:
        scope = self._new_scope(node)
        if isinstance(node, ast.DictComp):
            self._dispatch(node.key, scope, walrus_scope, scope, walrus_scope)
            self._dispatch(node.value, scope, walrus_scope, scope, walrus_scope)
        else:
            self._dispatch(node.elt, scope, walrus_scope, scope, walrus_scope)
        for child in node.generators:
            self._dispatch(child, scope, walrus_scope, scope, walrus_scope)

    def _dispatch_comprehension_clause(
        self,
        node: ast.comprehension,
        scope: int | None,
        walrus_scope: int | None,
    ) -> None:
        self._dispatch(node.target, scope, scope, scope, scope)
        self._dispatch(node.iter, scope, walrus_scope, scope, walrus_scope)
        for child in node.ifs:
            self._dispatch(child, scope, walrus_scope, scope, walrus_scope)

    def _dispatch_arguments(
        self,
        node: ast.arguments,
        scope: int | None,
        defining_scope: int | None,
        eager_walrus_scope: int | None,
    ) -> None:
        arguments = (
            *node.posonlyargs,
            *node.args,
            *node.kwonlyargs,
        )
        for argument in arguments:
            self._dispatch(
                argument,
                scope,
                scope,
                defining_scope,
                eager_walrus_scope,
            )
        if node.vararg is not None:
            self._dispatch(
                node.vararg,
                scope,
                scope,
                defining_scope,
                eager_walrus_scope,
            )
        if node.kwarg is not None:
            self._dispatch(
                node.kwarg,
                scope,
                scope,
                defining_scope,
                eager_walrus_scope,
            )
        for default in (*node.defaults, *(item for item in node.kw_defaults if item is not None)):
            self._dispatch(
                default,
                defining_scope,
                eager_walrus_scope,
                defining_scope,
                eager_walrus_scope,
            )

    def function_declarations(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        return self.declarations[id(function)]


class _StrictNonlocalOwnership(Enum):
    CLEAN = "clean"
    TARGETED = "targeted"
    UNKNOWN = "unknown"


def _strict_table_kind(table: symtable.SymbolTable) -> str:
    """Normalize the public 3.12 string and 3.13 enum scope types."""
    kind = table.get_type()
    return str(kind.value) if isinstance(kind, Enum) else kind


class _StrictCompilerScopes:
    """Lazily resolve explicit nonlocals using full-source compiler ownership."""

    def __init__(self, source: str, path: str) -> None:
        self.source = source
        self.path = path
        self.loaded = False
        self.module: symtable.SymbolTable | None = None

    def match(self, function: ast.FunctionDef) -> symtable.SymbolTable | None:
        if not self.loaded:
            self.loaded = True
            try:
                self.module = symtable.symtable(self.source, self.path, "exec")
            except SyntaxError:
                # AST analysis still supplies the original unsafe/absence findings.
                self.module = None
        if self.module is None:
            return None
        matches = [
            table
            for table in self.module.get_children()
            if _strict_table_kind(table) == "function"
            and table.get_name() == function.name
            and table.get_lineno() == function.lineno
        ]
        return matches[0] if len(matches) == 1 else None

    def nonlocal_ownership(self, function: ast.FunctionDef, name: str) -> _StrictNonlocalOwnership:
        table = self.match(function)
        if table is None:
            return _StrictNonlocalOwnership.UNKNOWN

        def relevant(scope: symtable.SymbolTable) -> bool:
            return name in scope.get_identifiers() or any(
                relevant(child) for child in scope.get_children()
            )

        def scan(scope: symtable.SymbolTable, candidate_owner: bool) -> _StrictNonlocalOwnership:
            result = _StrictNonlocalOwnership.CLEAN
            for child in scope.get_children():
                kind = _strict_table_kind(child)
                if kind not in {"function", "class"}:
                    if relevant(child):
                        result = _StrictNonlocalOwnership.UNKNOWN
                    continue
                child_owner = candidate_owner
                if name in child.get_identifiers():
                    symbol = child.lookup(name)
                    if symbol.is_nonlocal() and candidate_owner:
                        return _StrictNonlocalOwnership.TARGETED
                    # Classes do not supply enclosing function cells, even when
                    # their own namespace binds or declares the same spelling.
                    if kind == "function":
                        if symbol.is_global():
                            child_owner = False
                        elif symbol.is_free() or symbol.is_nonlocal():
                            child_owner = candidate_owner
                        elif symbol.is_local() or symbol.is_parameter() or symbol.is_imported():
                            child_owner = False
                        else:
                            result = _StrictNonlocalOwnership.UNKNOWN
                nested = scan(child, child_owner)
                if nested == _StrictNonlocalOwnership.TARGETED:
                    return nested
                if nested == _StrictNonlocalOwnership.UNKNOWN:
                    result = nested
            return result

        return scan(table, True)


def _strict_name_owned(
    tree: ast.Module,
    function: ast.FunctionDef,
    name: str,
    *,
    allowed_args: frozenset[int] = frozenset(),
    canonical_aliases: frozenset[int] = frozenset(),
    lexical_scope_only: bool = False,
) -> bool:
    """Check one protected simple name with bounded lexical binder coverage."""
    scope_facts = _StrictScopeFactsIndex(function) if lexical_scope_only else None
    if not lexical_scope_only and _strict_module_declares(tree, name):
        return False
    if scope_facts is not None and scope_facts.unsupported:
        return False
    if scope_facts is not None and name in scope_facts.function_declarations(function):
        return False
    scopes: tuple[Iterable[ast.AST], ...] = (
        ast.walk(function) if lexical_scope_only else _strict_scope_nodes(function),
    )
    if not lexical_scope_only:
        scopes = (*scopes, _strict_scope_nodes(tree))
    for node in (item for scope in scopes for item in scope):
        if scope_facts is not None and scope_facts.node_scopes.get(id(node)) != id(function):
            continue
        if isinstance(node, ast.arg) and node.arg == name:
            if id(node) not in allowed_args:
                return False
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if id(alias) in canonical_aliases:
                    continue
                bound = alias.asname or alias.name.split(".", 1)[0]
                if alias.name == "*" or alias.name == name or bound == name:
                    return False
        elif (
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return False
        elif isinstance(node, ast.ExceptHandler) and node.name == name:
            return False
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                return False
        elif isinstance(node, (ast.MatchAs, ast.MatchStar, ast.MatchMapping)) and (
            getattr(node, "name", None) == name or getattr(node, "rest", None) == name
        ):
            return False
    return True


def _strict_reader_owned(
    tree: ast.Module,
    function: ast.FunctionDef,
    parents: Mapping[int, ast.AST],
) -> bool:
    imports = [node for node in tree.body if _strict_is_canonical_reader_import(node)]
    if len(imports) != 1:
        return False
    canonical_import = imports[0]
    if not isinstance(canonical_import, ast.ImportFrom):
        return False
    if not _strict_name_owned(
        tree,
        function,
        "read_attributes",
        canonical_aliases=frozenset({id(canonical_import.names[0])}),
    ):
        return False
    for node in (*_strict_scope_nodes(tree), *_strict_scope_nodes(function)):
        if isinstance(node, ast.Name) and node.id == "read_attributes":
            parent = parents.get(id(node))
            if not (
                isinstance(node.ctx, ast.Load)
                and isinstance(parent, ast.Call)
                and parent.func is node
            ):
                return False
    return True


def _strict_map_owned(function: ast.FunctionDef, map_name: str, assignment: ast.Assign) -> bool:
    if map_name == "read_attributes":
        return False
    binding_count = 0
    for node in _strict_scope_nodes(function):
        if (
            isinstance(node, ast.Name)
            and node.id == map_name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            if id(node) != id(assignment.targets[0]):
                binding_count += 1
        elif isinstance(node, ast.arg) and node.arg == map_name:
            return False
        elif isinstance(node, (ast.Global, ast.Nonlocal)) and map_name in node.names:
            return False
        elif isinstance(node, ast.ExceptHandler) and node.name == map_name:
            return False
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == map_name:
                return False
        elif isinstance(node, (ast.MatchAs, ast.MatchStar, ast.MatchMapping)) and (
            getattr(node, "name", None) == map_name or getattr(node, "rest", None) == map_name
        ):
            return False
        elif isinstance(node, (ast.Import, ast.ImportFrom)) and any(
            alias.name == "*" or (alias.asname or alias.name.split(".", 1)[0]) == map_name
            for alias in node.names
        ):
            return False
    return binding_count == 0


def _strict_read_assignment(
    statement: ast.stmt,
    *,
    map_name: str,
    requested: tuple[str, ...] | None = None,
    required_key: str | None = None,
) -> tuple[ast.Assign, ast.Call] | None:
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return None
    target = statement.targets[0]
    if not isinstance(target, ast.Name) or target.id != map_name:
        return None
    call = statement.value
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "read_attributes"
        and not call.keywords
        and len(call.args) == 4
        and all(not isinstance(argument, ast.Starred) for argument in call.args)
        and isinstance(call.args[3], ast.List)
        and all(isinstance(element, ast.Name) for element in call.args[3].elts)
    ):
        return None
    requested_list = call.args[3]
    assert isinstance(requested_list, ast.List)
    names = tuple(element.id for element in requested_list.elts if isinstance(element, ast.Name))
    if requested is not None and names != requested:
        return None
    if required_key is not None and required_key not in names:
        return None
    return statement, call


def _strict_nested(statement: ast.stmt) -> bool:
    return any(
        isinstance(
            node,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Try,
                ast.TryStar,
                ast.With,
                ast.AsyncWith,
                ast.Match,
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
                ast.IfExp,
                ast.BoolOp,
                ast.NamedExpr,
                ast.Await,
                ast.Yield,
                ast.YieldFrom,
                ast.TypeAlias,
            ),
        )
        for node in ast.walk(statement)
    )


def _strict_context_is_valid(
    context: ast.expr,
    *,
    protocol: str,
    function: ast.FunctionDef,
    tree: ast.Module,
    compiler: _StrictCompilerScopes,
) -> bool:
    if protocol == "RSA_ATTRIBUTE":
        if isinstance(context, ast.Constant) and isinstance(context.value, str):
            return context.value in _RSA_CONTEXTS
        if not isinstance(context, ast.Name):
            return False
        ordinary = (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)
        matching = tuple(argument for argument in ordinary if argument.arg == context.id)
        if len(matching) != 1:
            return False
        return (
            _strict_name_owned(
                tree,
                function,
                context.id,
                allowed_args=frozenset({id(matching[0])}),
                lexical_scope_only=True,
            )
            and compiler.nonlocal_ownership(function, context.id) == _StrictNonlocalOwnership.CLEAN
        )
    expected = _UAF_CONTEXT if protocol == "UAF" else _EC_CONTEXT
    return isinstance(context, ast.Constant) and context.value == expected


def _strict_scalar_candidate(
    tree: ast.Module,
    node: ast.If,
    parents: Mapping[int, ast.AST],
    compiler: _StrictCompilerScopes,
) -> tuple[_ChildCandidate | None, str | None]:
    if not isinstance(node.test, ast.Compare) or len(node.test.ops) != 1:
        return None, None
    if not isinstance(node.test.left, ast.Name) or node.test.left.id not in _CHILD_KEYS:
        return None, None
    if len(node.test.comparators) != 1 or not isinstance(node.test.comparators[0], ast.Name):
        return None, None
    operator = node.test.ops[0]
    if not isinstance(operator, (ast.In, ast.NotIn)):
        return None, None
    branch = node.body if isinstance(operator, ast.NotIn) else node.orelse
    if not branch:
        return None, "missing branch is empty"
    key = node.test.left.id
    import_node = branch[0]
    if not (
        isinstance(import_node, ast.ImportFrom)
        and import_node.module == _ATTRIBUTE_FACTS_MODULE
        and import_node.level == 0
        and len(import_node.names) == 1
        and import_node.names[0].name == _ATTRIBUTE_FACT_HELPER
        and import_node.names[0].asname is None
    ):
        return None, None
    if (
        len(branch) < 3
        or not isinstance(branch[1], ast.Expr)
        or not isinstance(branch[1].value, ast.Call)
    ):
        return None, "missing branch does not start with a direct evidence call"
    call = branch[1].value
    if not (
        isinstance(call.func, ast.Name)
        and call.func.id == _ATTRIBUTE_FACT_HELPER
        and len(call.args) == 1
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == key
        and len(call.keywords) == 2
        and [keyword.arg for keyword in call.keywords] == ["protocol", "context"]
        and all(keyword.arg is not None for keyword in call.keywords)
    ):
        return None, "missing branch evidence call is not canonical"
    protocol_value = call.keywords[0].value
    context_value = call.keywords[1].value
    if not isinstance(protocol_value, ast.Constant) or not isinstance(protocol_value.value, str):
        return None, "evidence protocol is not a literal"
    protocol = protocol_value.value
    if key == "CKA_MODULUS":
        valid_protocol = protocol == "RSA_ATTRIBUTE"
    elif key == "CKA_EC_POINT":
        valid_protocol = protocol == "UAF"
    else:
        valid_protocol = False
    if not valid_protocol:
        return None, "evidence protocol does not match key"
    scope = _strict_scope_for(node, parents)
    function = _strict_top_level_function(scope, parents)
    if function is None or not _strict_context_is_valid(
        context_value, protocol=protocol, function=function, tree=tree, compiler=compiler
    ):
        return None, "evidence context is not canonical"
    if any(
        isinstance(statement, (ast.Return, ast.Continue, ast.Break, ast.Raise))
        or _strict_nested(statement)
        for statement in branch[2:-1]
    ) or not isinstance(branch[-1], (ast.Return, ast.Continue)):
        return None, "missing branch is not flat and terminal"
    guard_index = next((index for index, item in enumerate(function.body) if item is node), None)
    if guard_index is None or guard_index == 0:
        return None, "reader assignment does not immediately precede guard"
    map_name = node.test.comparators[0].id
    reader = _strict_read_assignment(
        function.body[guard_index - 1], map_name=map_name, required_key=key
    )
    if reader is None:
        return None, "guarded map lacks direct reader assignment"
    assignment, _reader_call = reader
    if not _strict_reader_owned(tree, function, parents):
        return None, "reader ownership is not canonical"
    if not _strict_map_owned(function, map_name, assignment):
        return None, "mapping ownership is not canonical"
    if not _strict_key_owned(tree, function, key):
        return None, "key ownership is not canonical"
    if compiler.match(function) is None:
        return None, "compiler scope ownership is unknown"
    return _ChildCandidate(node, import_node, call), None


def _strict_scope_for(node: ast.AST, parents: Mapping[int, ast.AST]) -> ast.AST:
    current = node
    while True:
        parent = parents.get(id(current))
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)):
            return parent
        if parent is None:
            return current
        current = parent


def _strict_observer_call(
    statement: ast.stmt,
    *,
    attrs_name: str,
    key: str,
    target_name: str | None,
) -> ast.Call | None:
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return None
    target = statement.targets[0]
    if not isinstance(target, ast.Name) or (target_name is not None and target.id != target_name):
        return None
    call = statement.value
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == _ATTRIBUTE_OBSERVER_HELPER
        and len(call.args) == 2
        and all(not isinstance(argument, ast.Starred) for argument in call.args)
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == attrs_name
        and isinstance(call.args[1], ast.Name)
        and call.args[1].id == key
        and len(call.keywords) == 1
        and call.keywords[0].arg == "context"
        and isinstance(call.keywords[0].value, ast.Constant)
        and call.keywords[0].value.value == _EC_CONTEXT
    ):
        return None
    return call


def _strict_pair_candidates(
    tree: ast.Module,
    parents: Mapping[int, ast.AST],
    compiler: _StrictCompilerScopes,
) -> tuple[list[_EcPairCandidate], list[tuple[ast.AST, str]]]:
    candidates: list[_EcPairCandidate] = []
    rejected: list[tuple[ast.AST, str]] = []
    for node in ast.walk(tree):
        function = _strict_top_level_function(node, parents)
        if function is None:
            continue
        body = function.body
        for index in range(len(body) - 3):
            imported = body[index + 1]
            if not (
                isinstance(imported, ast.ImportFrom)
                and imported.module == _ATTRIBUTE_FACTS_MODULE
                and imported.level == 0
                and len(imported.names) == 1
                and imported.names[0].name == _ATTRIBUTE_OBSERVER_HELPER
                and imported.names[0].asname is None
            ):
                continue
            read_statement = body[index]
            map_name = ""
            if (
                isinstance(read_statement, ast.Assign)
                and len(read_statement.targets) == 1
                and isinstance(read_statement.targets[0], ast.Name)
            ):
                map_name = read_statement.targets[0].id
            read = _strict_read_assignment(
                read_statement,
                map_name=map_name,
                requested=("CKA_EC_POINT", "CKA_EC_PARAMS"),
            )
            if read is None:
                rejected.append((imported, "observer pair lacks a direct reader assignment"))
                continue
            assignment, reader_call = read
            if len(assignment.targets) != 1 or not isinstance(assignment.targets[0], ast.Name):
                rejected.append((imported, "observer mapping target is not a simple name"))
                continue
            attrs_name = assignment.targets[0].id
            point = _strict_observer_call(
                body[index + 2],
                attrs_name=attrs_name,
                key="CKA_EC_POINT",
                target_name=None,
            )
            params = _strict_observer_call(
                body[index + 3],
                attrs_name=attrs_name,
                key="CKA_EC_PARAMS",
                target_name=None,
            )
            if point is None or params is None:
                rejected.append(
                    (imported, "observer pair is not an exact point-then-params envelope")
                )
                continue
            point_statement = body[index + 2]
            params_statement = body[index + 3]
            if not isinstance(point_statement, ast.Assign) or not isinstance(
                params_statement, ast.Assign
            ):
                rejected.append((imported, "observer targets are not assignments"))
                continue
            if len(point_statement.targets) != 1 or len(params_statement.targets) != 1:
                rejected.append((imported, "observer targets are not distinct simple names"))
                continue
            point_target = point_statement.targets[0]
            params_target = params_statement.targets[0]
            if (
                not isinstance(point_target, ast.Name)
                or not isinstance(params_target, ast.Name)
                or point_target.id == params_target.id
                or point_target.id == attrs_name
                or params_target.id == attrs_name
            ):
                rejected.append((imported, "observer targets are not distinct simple names"))
                continue
            if not _strict_reader_owned(tree, function, parents):
                rejected.append((imported, "reader ownership is not canonical"))
                continue
            if not _strict_map_owned(function, attrs_name, assignment):
                rejected.append((imported, "mapping ownership is not canonical"))
                continue
            if any(
                not _strict_key_owned(tree, function, key) for key in _CHILD_KEYS - {"CKA_MODULUS"}
            ):
                rejected.append((imported, "key ownership is not canonical"))
                continue
            if compiler.match(function) is None:
                rejected.append((imported, "compiler scope ownership is unknown"))
                continue
            candidates.append(_EcPairCandidate(imported, (point, params), reader_call))
    return candidates, rejected


def _strict_module_aliases(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    """Collect bounded package aliases without discarding same-spelling alternatives."""
    aliases: dict[str, list[str]] = {}

    def add_alias(bound: str, path: str) -> bool:
        if path not in _STRICT_RELEVANT_MODULE_PATHS:
            return False
        paths = aliases.setdefault(bound, [])
        if path in paths:
            return False
        paths.append(path)
        return True

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not (alias.name == "pkcs11_check" or alias.name.startswith("pkcs11_check.")):
                    continue
                bound = alias.asname or alias.name.split(".", 1)[0]
                add_alias(bound, alias.name if alias.asname else bound)
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("pkcs11_check"):
            module = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                add_alias(alias.asname or alias.name, f"{module}.{alias.name}")

    # A simple module assignment such as ``facts = probes._attribute_facts`` is
    # part of the finite syntax inventory.  Iterate because aliases can be
    # chained, while retaining every path for a spelling instead of letting an
    # unrelated later binding replace an identifiable helper path.
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            chain = (
                _strict_attribute_chain(node.value)
                if isinstance(node.value, ast.Attribute)
                else None
            )
            if chain is None:
                continue
            for root_path in aliases.get(chain[0], ()):
                changed |= add_alias(target.id, ".".join((root_path, *chain[1:])))

    return {bound: tuple(paths) for bound, paths in aliases.items()}


def _strict_attribute_chain(node: ast.Attribute) -> tuple[str, ...] | None:
    parts: list[str] = [node.attr]
    current: ast.expr = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return tuple(reversed(parts))


def _strict_helper_module_attribute(
    node: ast.Attribute, aliases: Mapping[str, tuple[str, ...]]
) -> bool:
    chain = _strict_attribute_chain(node)
    if chain is None:
        return False
    for root_path in aliases.get(chain[0], ()):
        path = ".".join((root_path, *chain[1:]))
        if path == _ATTRIBUTE_FACTS_MODULE:
            return node.attr == "_attribute_facts"
        if path in {
            f"{_ATTRIBUTE_FACTS_MODULE}.{_ATTRIBUTE_FACT_HELPER}",
            f"{_ATTRIBUTE_FACTS_MODULE}.{_ATTRIBUTE_OBSERVER_HELPER}",
        }:
            return True
    return False


def _strict_contract(path: str, tree: ast.Module, source: str) -> _ChildEvidenceContract:
    compiler = _StrictCompilerScopes(source, path)
    parents = {
        id(child): parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
    }
    candidates: list[_ChildCandidate] = []
    structural_rejections: list[tuple[ast.AST, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        scalar_candidate, rejection = _strict_scalar_candidate(tree, node, parents, compiler)
        if scalar_candidate is not None:
            candidates.append(scalar_candidate)
        elif rejection is not None:
            structural_rejections.append((node, rejection))
    pair_candidates, pair_rejections = _strict_pair_candidates(tree, parents, compiler)
    structural_rejections.extend(pair_rejections)

    approved_import_ids = {id(scalar.import_node) for scalar in candidates} | {
        id(observer.import_node) for observer in pair_candidates
    }
    approved_call_ids = {id(scalar.call_node) for scalar in candidates} | {
        id(call) for observer in pair_candidates for call in observer.calls
    }

    aliases = _strict_module_aliases(tree)
    references: list[tuple[ast.AST, str]] = []
    helper_seen = any(
        (
            isinstance(node, ast.Import)
            and any(alias.name == _ATTRIBUTE_FACTS_MODULE for alias in node.names)
        )
        or (
            isinstance(node, ast.ImportFrom)
            and (
                node.module == _ATTRIBUTE_FACTS_MODULE
                or (
                    node.module == _ATTRIBUTE_PROBES_MODULE
                    and any(alias.name == "_attribute_facts" for alias in node.names)
                )
            )
        )
        or (isinstance(node, ast.Attribute) and _strict_helper_module_attribute(node, aliases))
        for node in ast.walk(tree)
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == _ATTRIBUTE_FACTS_MODULE:
                    helper_seen = True
                    references.append(
                        (node, "helper module import is not owned by a canonical pair")
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module == _ATTRIBUTE_FACTS_MODULE:
                helper_seen = True
                if id(node) not in approved_import_ids:
                    references.append((node, "helper import is not owned by a canonical pair"))
            elif node.module == _ATTRIBUTE_PROBES_MODULE and any(
                alias.name == "_attribute_facts" for alias in node.names
            ):
                helper_seen = True
                references.append((node, "noncanonical _attribute_facts module import"))
        elif isinstance(node, (ast.Global, ast.Nonlocal)) and set(node.names) & {
            _ATTRIBUTE_FACT_HELPER,
            _ATTRIBUTE_OBSERVER_HELPER,
        }:
            if helper_seen:
                references.append((node, "helper binding is not permitted"))
        elif isinstance(node, ast.arg) and node.arg in {
            _ATTRIBUTE_FACT_HELPER,
            _ATTRIBUTE_OBSERVER_HELPER,
        }:
            if helper_seen:
                references.append((node, "helper binding is not permitted"))
        elif isinstance(node, ast.ExceptHandler) and node.name in {
            _ATTRIBUTE_FACT_HELPER,
            _ATTRIBUTE_OBSERVER_HELPER,
        }:
            if helper_seen:
                references.append((node, "helper binding is not permitted"))
        elif isinstance(node, (ast.MatchAs, ast.MatchStar, ast.MatchMapping)) and (
            getattr(node, "name", None) in {_ATTRIBUTE_FACT_HELPER, _ATTRIBUTE_OBSERVER_HELPER}
            or getattr(node, "rest", None) in {_ATTRIBUTE_FACT_HELPER, _ATTRIBUTE_OBSERVER_HELPER}
        ):
            if helper_seen:
                references.append((node, "helper binding is not permitted"))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (
            node.name in {_ATTRIBUTE_FACT_HELPER, _ATTRIBUTE_OBSERVER_HELPER}
        ):
            if helper_seen:
                references.append((node, "helper binding is not permitted"))
        elif isinstance(node, ast.Name) and node.id in {
            _ATTRIBUTE_FACT_HELPER,
            _ATTRIBUTE_OBSERVER_HELPER,
        }:
            if not helper_seen:
                continue
            helper_seen = True
            parent = parents.get(id(node))
            if id(parent) in approved_call_ids and isinstance(node.ctx, ast.Load):
                continue
            references.append((node, "helper name is not owned by a canonical pair"))
        elif isinstance(node, ast.Attribute) and _strict_helper_module_attribute(node, aliases):
            parent = parents.get(id(node))
            if node.attr == "_attribute_facts" and isinstance(parent, ast.Attribute):
                continue
            helper_seen = True
            references.append((node, "noncanonical module-qualified helper reference"))

    if not helper_seen:
        return _ChildEvidenceContract(frozenset(), ())

    references.extend(structural_rejections)
    approved: set[tuple[int, int]] = set()
    for scalar in candidates:
        approved.add((scalar.node.lineno, scalar.node.col_offset + 1))

    observer_approved: set[tuple[int, int, str]] = set()
    for observer in pair_candidates:
        observer_approved.update(
            (
                call.lineno,
                call.col_offset + 1,
                (
                    f"{_PROVIDER_CALL}:{path}:{observer.reader.lineno}:"
                    f"{observer.reader.col_offset + 1}"
                ),
            )
            for call in observer.calls
        )

    violations = tuple(
        sorted(
            {
                Violation(
                    path=path,
                    line=getattr(node, "lineno", 1),
                    column=getattr(node, "col_offset", 0) + 1,
                    code="child_evidence_contract",
                    message=f"{detail}; use the exact local evidence contract",
                    expression=_expr_text(node),
                )
                for node, detail in references
            }
        )
    )
    return _ChildEvidenceContract(frozenset(approved), violations, frozenset(observer_approved))


_child_evidence_contract = _strict_contract


class _Analyzer:
    def __init__(self, source: str, path: str) -> None:
        self.source = source
        self.path = path
        self.violations: dict[tuple[str, int, int, str, str], Violation] = {}
        self.functions: dict[str, _Function] = {}
        self.function_ids_by_node: dict[int, str] = {}
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
                    callable_kind=f"function:{function.identity}",
                    callable_closures=((f"function:{function.identity}", None),),
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
        scheduled = {function.identity for function in pending}
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
                if discovered.identity not in scheduled:
                    pending.append(discovered)
                    scheduled.add(discovered.identity)
        for function in pending:
            if function.identity not in self.called_functions:
                self._analyze_function(
                    function,
                    {},
                    call_stack=(),
                    top_level=True,
                )
        return sorted(self.violations.values())

    def _index_module(self, tree: ast.Module) -> None:
        self.functions.clear()
        self.function_ids_by_node.clear()
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
                    elif module == _CLASSIFICATION_MODULE and alias.name in {"fail_as", "xfail_as"}:
                        bindings[bound] = "terminal"
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

    def _collect_functions(
        self, node: ast.AST, scope: tuple[str, ...], identity_scope: tuple[str, ...] = ()
    ) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified_name = ".".join((*scope, node.name))
            # Names alone collide for definitions in different branches. Include
            # every enclosing definition's location so lexical ancestry is exact.
            local_identity = f"{node.name}@{node.lineno}:{node.col_offset}"
            identity = ".".join((*identity_scope, local_identity))
            self.functions[identity] = _Function(node, qualified_name, identity)
            self.function_ids_by_node[id(node)] = identity
            for child in node.body:
                self._collect_functions(
                    child, (*scope, node.name), (*identity_scope, local_identity)
                )
            return
        if isinstance(node, ast.ClassDef):
            class_scope = (*scope, node.name)
            class_identity_scope = (*identity_scope, f"{node.name}@{node.lineno}:{node.col_offset}")
            for child in node.body:
                self._collect_functions(child, class_scope, class_identity_scope)
            return
        for child_node in ast.iter_child_nodes(node):
            self._collect_functions(child_node, scope, identity_scope)

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
            parent_identity = ".".join(scope[:length])
            candidates = [
                function
                for function in self.functions.values()
                if function.node.name == name
                and function.identity.rpartition(".")[0] == parent_identity
            ]
            if candidates:
                # A recursive reference belongs to this lexical definition, even
                # when another branch defines a sibling with the same name.
                for function in candidates:
                    if call_stack and function.identity == call_stack[-1]:
                        return function
                return candidates[0] if len(candidates) == 1 else None
        return None

    def _resolve_callable_alternatives(
        self,
        node: ast.expr,
        callable_value: _Value,
        state: _State,
        call_stack: tuple[str, ...],
    ) -> list[tuple[_Function, _State | None]]:
        callable_closures = callable_value.callable_closures
        if callable_closures:
            alternatives: list[tuple[_Function, _State | None]] = []
            for kind, closure_state in callable_closures:
                function = self.functions.get(kind.removeprefix("function:"))
                if function is not None:
                    alternatives.append((function, closure_state))
            return alternatives
        callable_kinds = callable_value.callable_kinds or (
            (callable_value.callable_kind,) if callable_value.callable_kind is not None else ()
        )
        functions = [
            self.functions[kind.removeprefix("function:")]
            for kind in callable_kinds
            if kind.startswith("function:") and kind.removeprefix("function:") in self.functions
        ]
        if functions:
            closure_states = callable_value.closure_states or (
                (callable_value.closure_state,)
                if callable_value.closure_state is not None
                else (None,)
            )
            return [
                (function, closure_state)
                for function in functions
                for closure_state in closure_states
            ]
        if isinstance(node, ast.Name) and node.id not in state.env:
            function = self._resolve_function(node.id, call_stack)
            return [(function, None)] if function is not None else []
        return []

    def _analyze_function(
        self,
        function: _Function,
        argument_values: dict[str, _Value],
        *,
        closure_state: _State | None = None,
        call_stack: tuple[str, ...],
        top_level: bool,
    ) -> _Value:
        if len(call_stack) >= _MAX_CALL_DEPTH or function.identity in call_stack:
            return _Value()
        local_names = self._local_names(function)
        bindings = dict(self.global_bindings)
        env: dict[str, _Value] = {}
        if closure_state is not None:
            bindings.update(closure_state.bindings)
            env.update(closure_state.env)
        bindings = {name: kind for name, kind in bindings.items() if name not in local_names}
        env.update(argument_values)
        state = _State(env=env, bindings=bindings)
        for name in local_names:
            state.env.setdefault(name, _Value())
        reviewed = self._is_reviewed_optional_helper(function)
        flow = self._exec_block(
            list(function.node.body),
            state,
            call_stack=(*call_stack, function.identity),
            top_level=top_level,
        )
        return_exits = [
            exit for exit in flow.exits if exit.kind == "return" and exit.value is not None
        ]
        if top_level:
            for exit in return_exits:
                return_node = exit.node or function.node
                assert exit.value is not None
                optional_node: ast.AST = (
                    return_node.value
                    if isinstance(return_node, ast.Return) and return_node.value is not None
                    else return_node
                )
                self._check_optional(optional_node, exit.value, exit.state)
                self._check_taint_escape(
                    return_node, exit.value, "returning provider-backed mapping"
                )
        result = _value_union([exit.value for exit in return_exits if exit.value is not None])
        if (
            flow.state is None
            and flow.exits
            and all(exit.kind == "terminal" for exit in flow.exits)
        ):
            result = _Value(terminal=True)
        if reviewed and result.taint:
            self._check_taint_escape(
                function.node, result, "reviewed optional helper returned provider mapping"
            )
        return result

    @staticmethod
    def _closure_from_state(state: _State) -> _State:
        """Capture the lexical cell/import state visible to a nested function."""
        return _State(
            env={
                name: value
                for name, value in state.env.items()
                if value.callable_kind is not None
                or value.callable_kinds
                or value.callable_closures
            },
            bindings=dict(state.bindings),
        )

    @staticmethod
    def _returned_closure_from_state(state: _State) -> _State:
        """Retain all cells when a nested function escapes its defining scope."""
        return _State(
            env=dict(state.env),
            bindings=dict(state.bindings),
            facts=set(state.facts),
            present_values=set(state.present_values),
            missing_values=set(state.missing_values),
        )

    def _capture_returned_closure(
        self, value: _Value, state: _State, call_stack: tuple[str, ...]
    ) -> _Value:
        elements = tuple(
            self._capture_returned_closure(element, state, call_stack) for element in value.elements
        )
        if value.callable_closures:
            captured = self._returned_closure_from_state(state)
            closures = tuple(
                (kind, captured)
                if call_stack and kind.removeprefix("function:").startswith(f"{call_stack[-1]}.")
                else (kind, closure)
                for kind, closure in value.callable_closures
            )
            return replace(value, callable_closures=closures, elements=elements)
        if (
            value.callable_kind is not None
            and value.callable_kind.startswith("function:")
            and call_stack
            and value.callable_kind.removeprefix("function:").startswith(f"{call_stack[-1]}.")
        ):
            return replace(
                value,
                closure_state=self._returned_closure_from_state(state),
                elements=elements,
            )
        if elements != value.elements:
            return replace(value, elements=elements)
        return value

    @staticmethod
    def _closure_state_for_call(
        function: _Function,
        state: _State,
        call_stack: tuple[str, ...],
        closure_state: _State | None,
    ) -> _State | None:
        if any(function.identity.startswith(f"{scope}.") for scope in call_stack):
            return state
        return closure_state

    def _exec_block(
        self,
        statements: list[ast.stmt],
        state: _State,
        *,
        call_stack: tuple[str, ...],
        top_level: bool,
    ) -> _Flow:
        current: _State | None = state
        exits: list[_Exit] = []
        for statement in statements:
            if current is None:
                break
            result = self._exec_stmt(statement, current, call_stack=call_stack, top_level=top_level)
            current = result.state
            exits.extend(result.exits)
        return _Flow(current, exits)

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
            value = self._capture_returned_closure(value, state, call_stack)
            if value.terminal:
                return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
            return _Flow(None, [_Exit("return", state.copy(), value, node)])
        if isinstance(node, (ast.Raise, ast.Break, ast.Continue)):
            if isinstance(node, ast.Raise) and node.exc is not None:
                exception_value = self._eval_expr(node.exc, state, call_stack=call_stack)
                if exception_value.terminal:
                    return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
            return _Flow(None, exits=[_Exit(type(node).__name__.lower(), state.copy())])
        if isinstance(node, ast.Assign):
            before_rhs = self._optional_proofs(state)
            value = self._eval_expr(node.value, state, call_stack=call_stack)
            if value.terminal:
                return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
            after_rhs = self._optional_proofs(state)
            optional_proofs = (
                before_rhs[0] | after_rhs[0],
                before_rhs[1] | after_rhs[1],
            )
            for target in node.targets:
                if not isinstance(target, (ast.Name, ast.Tuple, ast.List, ast.Starred)):
                    self._check_taint_escape(target, value, "storing provider-backed mapping")
                self._assign(
                    target,
                    value,
                    state,
                    call_stack=call_stack,
                    optional_proofs=optional_proofs,
                )
            return _Flow(state)
        if isinstance(node, ast.AnnAssign):
            value = (
                self._eval_expr(node.value, state, call_stack=call_stack)
                if node.value
                else _Value()
            )
            if value.terminal:
                return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
            if not isinstance(node.target, (ast.Name, ast.Tuple, ast.List, ast.Starred)):
                self._check_taint_escape(node.target, value, "storing provider-backed mapping")
            self._assign(node.target, value, state, call_stack=call_stack)
            return _Flow(state)
        if isinstance(node, ast.AugAssign):
            current = self._eval_expr(node.target, state, call_stack=call_stack)
            if current.terminal:
                return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
            value = self._eval_expr(node.value, state, call_stack=call_stack)
            if value.terminal:
                return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
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
            value = self._eval_expr(node.value, state, call_stack=call_stack)
            if value.terminal:
                return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
            return _Flow(state)
        if isinstance(node, ast.Assert):
            probe = state.copy()
            test_value = self._eval_expr(node.test, probe, call_stack=call_stack)
            if test_value.terminal:
                return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
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
                context_value = self._eval_expr(
                    item.context_expr, with_state, call_stack=call_stack
                )
                if context_value.terminal:
                    return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, _Value(), with_state, call_stack=call_stack)
            return self._exec_block(
                list(node.body), with_state, call_stack=call_stack, top_level=top_level
            )
        if isinstance(node, ast.Try):
            body_flow = self._exec_block(
                list(node.body), state.copy(), call_stack=call_stack, top_level=top_level
            )
            if node.orelse and body_flow.state is not None:
                orelse_flow = self._exec_block(
                    list(node.orelse),
                    body_flow.state,
                    call_stack=call_stack,
                    top_level=top_level,
                )
                body_flow = _Flow(
                    orelse_flow.state,
                    [*body_flow.exits, *orelse_flow.exits],
                )
            flows: list[_Flow] = [body_flow]
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
            alive = _merge_states([flow.state for flow in flows if flow.state is not None])
            exits = [exit for flow in flows for exit in flow.exits]
            if not node.finalbody:
                return _Flow(alive, exits)

            final_states: list[_State] = []
            final_exits: list[_Exit] = []
            for flow in flows:
                if flow.state is not None:
                    final = self._exec_block(
                        list(node.finalbody),
                        flow.state.copy(),
                        call_stack=call_stack,
                        top_level=top_level,
                    )
                    if final.state is not None:
                        final_states.append(final.state)
                    final_exits.extend(final.exits)
                for exit in flow.exits:
                    final = self._exec_block(
                        list(node.finalbody),
                        exit.state.copy(),
                        call_stack=call_stack,
                        top_level=top_level,
                    )
                    if final.state is not None:
                        final_exits.append(_Exit(exit.kind, final.state, exit.value, exit.node))
                    final_exits.extend(final.exits)
            return _Flow(_merge_states(final_states), final_exits)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            state.bindings.pop(node.name, None)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                identity = self.function_ids_by_node.get(id(node))
                if identity is not None:
                    state.env[node.name] = _Value(
                        callable_kind=f"function:{identity}",
                        callable_closures=(
                            (f"function:{identity}", self._closure_from_state(state)),
                        ),
                        closure_state=self._closure_from_state(state),
                    )
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
        if test_value.terminal:
            return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
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
        exits = [*true_flow.exits, *false_flow.exits]
        return _Flow(alive, exits)

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
            if self._safe_presence_or(node.test, state):
                return
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
            and not self._all_paths_terminal(node.body, call_stack=call_stack)
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
        if not self._all_paths_terminal(missing_body, state=state, call_stack=call_stack):
            return
        if self._all_paths_classified_terminal(missing_body, state=state, call_stack=call_stack):
            return
        if self._structured_absence(missing_body, key, state, call_stack=call_stack):
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
    def _scope_walk(
        node: ast.AST, *, include_root: bool = True, root_scope: bool = False
    ) -> Iterable[ast.AST]:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and not root_scope
        ):
            return
        if include_root:
            yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            yield from _Analyzer._scope_walk(child)

    def _reachable_scope_walk(
        self, node: ast.AST, *, include_root: bool = True, root_scope: bool = False
    ) -> Iterable[ast.AST]:
        """Walk lexical children while excluding statements after terminal flow."""
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and not root_scope
        ):
            return
        if include_root:
            yield node
        if isinstance(node, ast.If):
            yield from self._scope_walk(node.test)
            yield from self._reachable_block_walk(node.body)
            yield from self._reachable_block_walk(node.orelse)
            return
        if isinstance(node, (ast.Try, ast.TryStar)):
            yield from self._reachable_block_walk(node.body)
            for handler in node.handlers:
                if handler.type is not None:
                    yield from self._scope_walk(handler.type)
                yield from self._reachable_block_walk(handler.body)
            if not self._all_paths_terminal(node.body):
                yield from self._reachable_block_walk(node.orelse)
            yield from self._reachable_block_walk(node.finalbody)
            return
        if isinstance(node, ast.Match):
            yield from self._scope_walk(node.subject)
            for case in node.cases:
                yield from self._scope_walk(case.pattern)
                if case.guard is not None:
                    yield from self._scope_walk(case.guard)
                yield from self._reachable_block_walk(case.body)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                yield from self._scope_walk(item.context_expr)
            yield from self._reachable_block_walk(node.body)
            return
        if isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
            condition = node.test if isinstance(node, ast.While) else node.iter
            yield from self._scope_walk(condition)
            yield from self._reachable_block_walk(node.body)
            yield from self._reachable_block_walk(node.orelse)
            return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            yield from self._scope_walk(child)

    def _reachable_block_walk(self, statements: list[ast.stmt]) -> Iterable[ast.AST]:
        for statement in statements:
            yield from self._reachable_scope_walk(statement)
            if self._all_paths_terminal([statement]):
                break

    def _all_paths_terminal(
        self,
        statements: list[ast.stmt],
        *,
        state: _State | None = None,
        call_stack: tuple[str, ...] = (),
    ) -> bool:
        """Return whether every path through this scope exits the enclosing flow."""
        if state is not None:
            flow = self._exec_block(
                list(statements),
                state.copy(),
                call_stack=call_stack,
                top_level=False,
            )
            return flow.state is None
        return "fallthrough" not in self._return_outcomes(
            statements, "<terminal-only>", state=state, call_stack=call_stack
        )

    def _all_paths_classified_terminal(
        self,
        statements: list[ast.stmt],
        *,
        state: _State,
        call_stack: tuple[str, ...],
    ) -> bool:
        flow = self._exec_block(
            list(statements),
            state.copy(),
            call_stack=call_stack,
            top_level=False,
        )
        return (
            flow.state is None
            and bool(flow.exits)
            and all(exit.kind == "terminal" for exit in flow.exits)
        )

    @staticmethod
    def _match_is_exhaustive(statement: ast.Match) -> bool:
        return any(
            case.guard is None
            and isinstance(case.pattern, ast.MatchAs)
            and case.pattern.pattern is None
            for case in statement.cases
        )

    def _all_paths_return_or_fallthrough(self, statements: list[ast.stmt], expected: str) -> bool:
        """Return whether a scope only returns ``expected`` or falls through."""
        return self._return_outcomes(statements, expected) <= {"expected", "fallthrough"}

    def _all_paths_return_value(self, statements: list[ast.stmt], expected: str) -> bool:
        """Return whether every path exits with the same explicit return expression."""
        return self._return_outcomes(statements, expected) == {"expected"}

    def _statement_is_terminal(
        self,
        statement: ast.stmt,
        *,
        state: _State | None = None,
        call_stack: tuple[str, ...] = (),
    ) -> bool:
        expression: ast.expr | None = None
        if isinstance(statement, ast.Expr):
            expression = statement.value
        elif isinstance(statement, ast.Assign):
            expression = statement.value
        elif isinstance(statement, ast.AnnAssign):
            expression = statement.value
        return expression is not None and self._expression_is_terminal(
            expression, state=state, call_stack=call_stack
        )

    def _expression_is_terminal(
        self,
        node: ast.expr,
        *,
        state: _State | None,
        call_stack: tuple[str, ...],
    ) -> bool:
        if state is None:
            return False
        if isinstance(node, ast.Call):
            if any(
                self._expression_is_terminal(argument, state=state, call_stack=call_stack)
                for argument in node.args
            ):
                return True
            if any(
                self._expression_is_terminal(keyword.value, state=state, call_stack=call_stack)
                for keyword in node.keywords
            ):
                return True
            return self._call_is_terminal(node, state=state, call_stack=call_stack)
        if isinstance(node, ast.NamedExpr):
            return self._expression_is_terminal(node.value, state=state, call_stack=call_stack)
        if isinstance(node, ast.BoolOp):
            if not node.values:
                return False
            first = self._expression_is_terminal(node.values[0], state=state, call_stack=call_stack)
            return first or all(
                self._expression_is_terminal(value, state=state, call_stack=call_stack)
                for value in node.values
            )
        if isinstance(node, ast.IfExp):
            return self._expression_is_terminal(
                node.body, state=state, call_stack=call_stack
            ) and self._expression_is_terminal(node.orelse, state=state, call_stack=call_stack)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return any(
                self._expression_is_terminal(element, state=state, call_stack=call_stack)
                for element in node.elts
            )
        if isinstance(node, ast.Dict):
            return any(
                value is not None
                and self._expression_is_terminal(value, state=state, call_stack=call_stack)
                for value in node.values
            ) or any(
                key is not None
                and self._expression_is_terminal(key, state=state, call_stack=call_stack)
                for key in node.keys
            )
        child_expressions = [
            child for child in ast.iter_child_nodes(node) if isinstance(child, ast.expr)
        ]
        return any(
            self._expression_is_terminal(child, state=state, call_stack=call_stack)
            for child in child_expressions
        )

    def _call_is_terminal(
        self,
        node: ast.Call,
        *,
        state: _State,
        call_stack: tuple[str, ...],
    ) -> bool:
        callable_value = self._eval_expr(node.func, state, call_stack=call_stack)
        callable_kinds = _callable_kinds(callable_value)
        function_alternatives = self._resolve_callable_alternatives(
            node.func, callable_value, state, call_stack
        )
        nonterminal_builtin_kinds = set(callable_kinds) - {"terminal"}
        if nonterminal_builtin_kinds or not callable_kinds:
            return False
        if any(function.identity in call_stack for function, _ in function_alternatives):
            return False
        summaries: list[_Value] = [_Value(terminal=True)] if "terminal" in callable_kinds else []
        summaries.extend(
            self._analyze_function(
                function,
                {},
                closure_state=self._closure_state_for_call(
                    function, state, call_stack, closure_state
                ),
                call_stack=call_stack,
                top_level=False,
            )
            for function, closure_state in function_alternatives
        )
        if not summaries:
            return False
        return all(summary.terminal for summary in summaries)

    def _return_outcomes(
        self,
        statements: list[ast.stmt],
        expected: str,
        *,
        state: _State | None = None,
        call_stack: tuple[str, ...] = (),
    ) -> set[str]:
        """Compose explicit exits and the implicit path that reaches the next statement."""
        outcomes = {"fallthrough"}
        for statement in statements:
            if "fallthrough" not in outcomes:
                break
            outcomes.remove("fallthrough")
            if isinstance(statement, ast.Return):
                if statement.value is not None and self._expression_is_terminal(
                    statement.value, state=state, call_stack=call_stack
                ):
                    outcomes.add("terminal")
                else:
                    outcomes.add(
                        "expected"
                        if statement.value is not None and _key_text(statement.value) == expected
                        else "other"
                    )
            elif isinstance(statement, (ast.Raise, ast.Break, ast.Continue)):
                outcomes.add(type(statement).__name__.lower())
            elif isinstance(statement, ast.If):
                if self._expression_is_terminal(statement.test, state=state, call_stack=call_stack):
                    outcomes.add("terminal")
                else:
                    outcomes.update(
                        self._return_outcomes(
                            statement.body, expected, state=state, call_stack=call_stack
                        )
                    )
                    outcomes.update(
                        self._return_outcomes(
                            statement.orelse, expected, state=state, call_stack=call_stack
                        )
                    )
            elif isinstance(statement, ast.Try):
                pending = self._return_outcomes(
                    statement.body, expected, state=state, call_stack=call_stack
                )
                if "fallthrough" in pending:
                    pending.remove("fallthrough")
                    pending.update(
                        self._return_outcomes(
                            statement.orelse, expected, state=state, call_stack=call_stack
                        )
                    )
                for handler in statement.handlers:
                    pending.update(
                        self._return_outcomes(
                            handler.body, expected, state=state, call_stack=call_stack
                        )
                    )
                if statement.finalbody:
                    final = self._return_outcomes(
                        statement.finalbody, expected, state=state, call_stack=call_stack
                    )
                    if "fallthrough" not in final:
                        pending.clear()
                    pending.update(final - {"fallthrough"})
                outcomes.update(pending)
            elif isinstance(statement, ast.Match):
                if self._expression_is_terminal(
                    statement.subject, state=state, call_stack=call_stack
                ):
                    outcomes.add("terminal")
                else:
                    for case in statement.cases:
                        outcomes.update(
                            self._return_outcomes(
                                case.body, expected, state=state, call_stack=call_stack
                            )
                        )
                    if not self._match_is_exhaustive(statement):
                        outcomes.add("fallthrough")
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                if any(
                    self._expression_is_terminal(
                        item.context_expr, state=state, call_stack=call_stack
                    )
                    for item in statement.items
                ):
                    outcomes.add("terminal")
                else:
                    body_outcomes = self._return_outcomes(
                        statement.body, expected, state=state, call_stack=call_stack
                    )
                    outcomes.update(body_outcomes)
                    # A context manager may suppress an exception, but it cannot suppress
                    # break, continue, or return control flow.
                    if "raise" in body_outcomes:
                        outcomes.add("fallthrough")
            elif isinstance(statement, (ast.While, ast.For, ast.AsyncFor)):
                condition = statement.test if isinstance(statement, ast.While) else statement.iter
                if self._expression_is_terminal(condition, state=state, call_stack=call_stack):
                    outcomes.add("terminal")
                else:
                    body = self._return_outcomes(
                        statement.body, expected, state=state, call_stack=call_stack
                    )
                    outcomes.update(body - {"fallthrough", "break", "continue"})
                    # Zero iterations and normal termination reach else; break bypasses it.
                    outcomes.update(
                        self._return_outcomes(
                            statement.orelse, expected, state=state, call_stack=call_stack
                        )
                    )
                    if "break" in body:
                        outcomes.add("fallthrough")
            elif self._statement_is_terminal(statement, state=state, call_stack=call_stack):
                outcomes.add("terminal")
            else:
                outcomes.add("fallthrough")
        return outcomes

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

    def _safe_presence_or(self, test: ast.BoolOp, state: _State) -> bool:
        if not isinstance(test.op, ast.Or) or len(test.values) < 2:
            return False
        first = self._provider_membership(test.values[0], state)
        if first is None or not isinstance(first[2], ast.NotIn):
            return False
        key = first[0]
        first_test = test.values[0]
        if not isinstance(first_test, ast.Compare) or not first_test.comparators:
            return False
        if not self._stable_key_expression(first_test.left):
            return False
        subscript_nodes = [
            child
            for part in test.values[1:]
            for child in ast.walk(part)
            if isinstance(child, ast.Subscript)
        ]
        if not subscript_nodes:
            return False
        mapping = first[1]
        mapping_id = mapping.mapping_id
        if mapping_id is None:
            return False
        for child in subscript_nodes:
            child_mapping = self._eval_expr(child.value, state, call_stack=())
            if (
                not self._stable_key_expression(child.slice)
                or _key_text(child.slice) != key
                or child_mapping.mapping_id != mapping_id
            ):
                return False
        return True

    @staticmethod
    def _stable_key_expression(node: ast.expr) -> bool:
        return not any(isinstance(child, ast.Call) for child in ast.walk(node))

    def _structured_absence(
        self,
        statements: list[ast.stmt],
        key: str,
        state: _State,
        *,
        call_stack: tuple[str, ...] = (),
    ) -> bool:
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
            if self._all_paths_terminal(
                statements[index + 1 :], state=state, call_stack=call_stack
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
        for child in self._scope_walk(function.node, root_scope=True):
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
            if not self._all_paths_return_value(absent_body, self.optional_defaults[key]):
                continue
            if isinstance(child.test.ops[0], ast.NotIn):
                try:
                    membership_index = function.node.body.index(child)
                except ValueError:
                    present_body = []
                else:
                    present_body = function.node.body[membership_index + 1 :]
            else:
                present_body = child.body
            if any(
                isinstance(node, ast.Subscript)
                and _key_text(node.value) == mapping
                and _key_text(node.slice) == key
                for statement in present_body
                for node in self._scope_walk(statement)
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
        for child in self._scope_walk(function.node, root_scope=True):
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
            if not self._all_paths_terminal(present_body, call_stack=(function.identity,)):
                continue
            if not any(
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and self._record_mentions_key(statement.value, key)
                for statement in present_body
            ):
                continue
            if not self._has_direct_boolean_return(present_body, False):
                continue
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
                for node in self._scope_walk(statement)
            ):
                continue
            if not any(
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Constant)
                and node.value.value is False
                for statement in present_body
                for node in self._scope_walk(statement)
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
            for descendant in self._scope_walk(statement)
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
        exits: list[_Exit] = []
        converged = False
        last_body_state: _State | None = None
        if not isinstance(node, ast.While):
            iterable = self._eval_expr(node.iter, loop_state, call_stack=call_stack)
            if iterable.terminal:
                return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
            self._check_optional(node.iter, iterable, loop_state)
        for _ in range(_MAX_FLOW_ITERATIONS):
            body_state = loop_state.copy()
            if isinstance(node, ast.While):
                test_value = self._eval_expr(node.test, body_state, call_stack=call_stack)
                if test_value.terminal:
                    return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
                body_state = self._refine(body_state, node.test, truth=True)
            else:
                self._assign(node.target, _Value(), body_state, call_stack=call_stack)
            body_flow = self._exec_block(
                list(node.body), body_state, call_stack=call_stack, top_level=top_level
            )
            last_body_state = body_flow.state
            next_state = _merge_states(
                [candidate for candidate in (state, body_flow.state) if candidate is not None]
            )
            exits.extend(body_flow.exits)
            if next_state == loop_state:
                loop_state = next_state
                converged = True
                break
            loop_state = next_state or state.copy()
        if not converged:
            loop_state = self._widen_loop_state(
                node, state, loop_state, last_body_state, call_stack=call_stack
            )
            diagnostic_state = loop_state.copy()
            if isinstance(node, ast.While):
                self._eval_expr(node.test, diagnostic_state, call_stack=call_stack)
                diagnostic_state = self._refine(diagnostic_state, node.test, truth=True)
            else:
                self._assign(node.target, _Value(), diagnostic_state, call_stack=call_stack)
            diagnostic_flow = self._exec_block(
                list(node.body),
                diagnostic_state,
                call_stack=call_stack,
                top_level=top_level,
            )
            exits.extend(diagnostic_flow.exits)
            loop_state = (
                _merge_states(
                    [
                        candidate
                        for candidate in (loop_state, diagnostic_flow.state)
                        if candidate is not None
                    ]
                )
                or loop_state
            )
        alive: _State | None = loop_state
        if node.orelse:
            else_base = alive or state.copy()
            else_flow = self._exec_block(
                list(node.orelse), else_base, call_stack=call_stack, top_level=top_level
            )
            alive = _merge_states(
                [candidate for candidate in (alive, else_flow.state) if candidate is not None]
            )
            exits.extend(else_flow.exits)
        return _Flow(alive, exits)

    def _widen_loop_state(
        self,
        node: ast.While | ast.For | ast.AsyncFor,
        initial: _State,
        loop_state: _State,
        body_state: _State | None,
        *,
        call_stack: tuple[str, ...],
    ) -> _State:
        widened = (
            _merge_states(
                [
                    candidate
                    for candidate in (initial, loop_state, body_state)
                    if candidate is not None
                ]
            )
            or initial.copy()
        )
        assignments: dict[str, list[tuple[ast.expr, ast.expr, set[str]]]] = {}
        for statement in node.body:
            for child in self._reachable_scope_walk(statement):
                targets: list[ast.expr]
                expression: ast.expr | None
                if isinstance(child, ast.Assign):
                    targets, expression = child.targets, child.value
                elif isinstance(child, (ast.AnnAssign, ast.NamedExpr)):
                    targets, expression = [child.target], child.value
                else:
                    continue
                if expression is None:
                    continue
                sources = {
                    source.id
                    for source in ast.walk(expression)
                    if isinstance(source, ast.Name) and isinstance(source.ctx, ast.Load)
                }
                for target in targets:
                    for name in self._assigned_names(target):
                        assignments.setdefault(name, []).append((target, expression, sources))

        def dependency_value(name: str, visiting: frozenset[str]) -> _Value:
            observed = widened.env.get(name, _Value())
            if name in visiting:
                return observed
            values = [observed]
            for target, expression, sources in assignments.get(name, ()):
                dependency_state = widened.copy()
                for source in sorted(sources & assignments.keys()):
                    dependency_state.env[source] = dependency_value(source, visiting | {name})
                # Apply the actual transfer so tuple construction/destructuring and helper
                # calls retain their dimensions instead of joining unrelated input shapes.
                value = self._eval_expr(expression, dependency_state, call_stack=call_stack)
                self._assign(target, value, dependency_state, call_stack=call_stack)
                values.append(dependency_state.env[name])
            # Unknown alternatives participate: callable/mapping identity is a must-property.
            return _value_union(values)

        # All roots see the same observations; sibling evaluation order cannot add identities.
        replacements = {name: dependency_value(name, frozenset()) for name in sorted(assignments)}
        widened.env.update(replacements)
        return widened

    def _exec_match(
        self,
        node: ast.Match,
        state: _State,
        *,
        call_stack: tuple[str, ...],
        top_level: bool,
    ) -> _Flow:
        subject = self._eval_expr(node.subject, state, call_stack=call_stack)
        if subject.terminal:
            return _Flow(None, [_Exit("terminal", state.copy(), node=node)])
        self._check_optional(node.subject, subject, state)
        flows: list[_Flow] = [_Flow(state.copy())]
        for case in node.cases:
            case_state = state.copy()
            self._bind_pattern(case.pattern, case_state)
            if case.guard is not None:
                guard_value = self._eval_expr(case.guard, case_state, call_stack=call_stack)
                if guard_value.terminal:
                    flows.append(_Flow(None, [_Exit("terminal", state.copy(), node=node)]))
                    continue
                case_state = self._refine(case_state, case.guard, truth=True)
            flows.append(
                self._exec_block(
                    list(case.body), case_state, call_stack=call_stack, top_level=top_level
                )
            )
        alive = _merge_states([flow.state for flow in flows if flow.state is not None])
        exits = [exit for flow in flows for exit in flow.exits]
        return _Flow(alive, exits)

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
                elif module == _CLASSIFICATION_MODULE and alias.name in {"fail_as", "xfail_as"}:
                    state.bindings[bound] = "terminal"
                elif module == _CLASSIFICATION_MODULE and alias.name == "record_as":
                    state.bindings[bound] = "record"
                else:
                    state.bindings[bound] = "unknown"

    @staticmethod
    def _optional_proofs(state: _State) -> tuple[frozenset[str], frozenset[str]]:
        present = frozenset(
            identity
            for name in state.present_values
            if (identity := state.env.get(name, _Value()).optional_id) is not None
        )
        missing = frozenset(
            identity
            for name in state.missing_values
            if (identity := state.env.get(name, _Value()).optional_id) is not None
        )
        return present, missing

    def _assign(
        self,
        target: ast.expr,
        value: _Value,
        state: _State,
        *,
        call_stack: tuple[str, ...],
        optional_proofs: tuple[frozenset[str], frozenset[str]] | None = None,
    ) -> None:
        if optional_proofs is None:
            optional_proofs = self._optional_proofs(state)
        present_ids, missing_ids = optional_proofs
        if isinstance(target, ast.Name):
            present = value.optional_id is not None and value.optional_id in present_ids
            missing = value.optional_id is not None and value.optional_id in missing_ids
            state.env[target.id] = value
            state.bindings.pop(target.id, None)
            state.present_values.discard(target.id)
            state.missing_values.discard(target.id)
            if present:
                state.present_values.add(target.id)
            if missing:
                state.missing_values.add(target.id)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if value.mapping:
                self._check_taint_escape(target, value, "destructuring provider-backed mapping")
            for index, element in enumerate(target.elts):
                item = value.elements[index] if index < len(value.elements) else _Value()
                self._assign(
                    element,
                    item,
                    state,
                    call_stack=call_stack,
                    optional_proofs=optional_proofs,
                )
            return
        if isinstance(target, ast.Starred):
            self._assign(
                target.value,
                value,
                state,
                call_stack=call_stack,
                optional_proofs=optional_proofs,
            )
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
            if binding in {"direct", "helper", "record", "sentinel", "terminal"}:
                return _Value(callable_kind=binding)
            if binding is not None and binding.startswith("module:"):
                return _Value(callable_kind=binding)
            if node.id in state.env:
                return state.env[node.id]
            function = self._resolve_function(node.id, call_stack)
            if function is not None:
                kind = f"function:{function.identity}"
                return _Value(callable_kind=kind, callable_closures=((kind, None),))
            return _Value()
        if isinstance(node, ast.NamedExpr):
            value = self._eval_expr(node.value, state, call_stack=call_stack)
            self._assign(node.target, value, state, call_stack=call_stack)
            return value
        if isinstance(node, ast.Constant):
            return _Value()
        if isinstance(node, ast.Attribute):
            base = self._eval_expr(node.value, state, call_stack=call_stack)
            if base.terminal:
                return _Value(terminal=True)
            module_name = (base.callable_kind or "").removeprefix("module:")
            if module_name == _RECIPES_MODULE and node.attr == "read_attributes":
                return _Value(callable_kind="direct")
            if module_name == _ATTRIBUTE_HELPER_MODULE and node.attr == "attr_or_record":
                return _Value(callable_kind="helper")
            if module_name == _ATTRIBUTE_HELPER_MODULE and node.attr == "MISSING_ATTRIBUTE":
                return _Value(callable_kind="sentinel")
            if module_name == _CLASSIFICATION_MODULE and node.attr in {"fail_as", "xfail_as"}:
                return _Value(callable_kind="terminal")
            if module_name == _CLASSIFICATION_MODULE and node.attr == "record_as":
                return _Value(callable_kind="record")
            if node.attr == "copy" and base.taint:
                return _Value(callable_kind="tainted-copy", taint=base.taint)
            if base.callable_kind is not None and base.callable_kind.startswith("module:"):
                return _Value(callable_kind=f"module:{module_name}.{node.attr}")
            if node.attr == "get" and base.taint:
                return _Value(
                    callable_kind="tainted-get", taint=base.taint, mapping_id=base.mapping_id
                )
            if base.taint:
                self._check_taint_escape(node, base, "accessing provider-backed mapping attribute")
            return _Value()
        if isinstance(node, ast.Call):
            return self._eval_call(node, state, call_stack=call_stack)
        if isinstance(node, ast.Subscript):
            base = self._eval_expr(node.value, state, call_stack=call_stack)
            if base.terminal:
                return _Value(terminal=True)
            key_node = node.slice
            key_value = self._eval_expr(key_node, state, call_stack=call_stack)
            if key_value.terminal:
                return _Value(terminal=True)
            self._check_optional(key_node, key_value, state)
            if (
                base.elements
                and isinstance(key_node, ast.Constant)
                and isinstance(key_node.value, int)
            ):
                index = key_node.value
                if 0 <= index < len(base.elements):
                    return base.elements[index]
            if base.taint:
                if not self._mapping_present(base, key_node, state):
                    self._emit(
                        node,
                        "unsafe_subscript",
                        "direct subscript of provider-backed attribute mapping",
                        base,
                    )
            self._check_optional(node.value, base, state)
            return _Value()
        if isinstance(node, ast.List):
            list_values: list[_Value] = []
            for element in node.elts:
                value = self._eval_expr(element, state, call_stack=call_stack)
                list_values.append(value)
                if value.terminal:
                    break
            value = _Value(
                elements=tuple(list_values), terminal=any(item.terminal for item in list_values)
            )
            if any(item.taint for item in list_values):
                self._check_taint_escape(
                    node, _value_union(list_values), "storing provider-backed mapping in a list"
                )
            return value
        if isinstance(node, ast.Tuple):
            tuple_values_list: list[_Value] = []
            for element in node.elts:
                value = self._eval_expr(element, state, call_stack=call_stack)
                tuple_values_list.append(value)
                if value.terminal:
                    break
            tuple_values = tuple(tuple_values_list)
            return _Value(
                taint=frozenset().union(*(item.taint for item in tuple_values)),
                terminal=any(item.terminal for item in tuple_values),
                elements=tuple_values,
            )
        if isinstance(node, ast.Set):
            set_values: list[_Value] = []
            for element in node.elts:
                value = self._eval_expr(element, state, call_stack=call_stack)
                set_values.append(value)
                if value.terminal:
                    break
            if any(item.taint for item in set_values):
                self._check_taint_escape(
                    node, _value_union(set_values), "storing provider-backed mapping in a set"
                )
            return _Value(terminal=any(item.terminal for item in set_values))
        if isinstance(node, ast.Dict):
            key_values: list[_Value] = []
            dict_values: list[_Value] = []
            for key, value_node in zip(node.keys, node.values, strict=True):
                if key is not None:
                    key_value = self._eval_expr(key, state, call_stack=call_stack)
                    key_values.append(key_value)
                    if key_value.terminal:
                        break
                if value_node is not None:
                    value = self._eval_expr(value_node, state, call_stack=call_stack)
                    dict_values.append(value)
                    if value.terminal:
                        break
            all_values = [*key_values, *dict_values]
            if any(item.taint for item in dict_values):
                self._check_taint_escape(
                    node, _value_union(dict_values), "storing provider-backed mapping in a dict"
                )
            return _Value(terminal=any(item.terminal for item in all_values))
        if isinstance(node, ast.JoinedStr):
            terminal = False
            for value_node in node.values:
                value = self._eval_expr(value_node, state, call_stack=call_stack)
                self._check_optional(value_node, value, state)
                terminal |= value.terminal
                if terminal:
                    break
            return _Value(terminal=terminal)
        if isinstance(node, ast.FormattedValue):
            value = self._eval_expr(node.value, state, call_stack=call_stack)
            self._check_optional(node.value, value, state)
            terminal = value.terminal
            if node.format_spec is not None and not terminal:
                terminal |= self._eval_expr(node.format_spec, state, call_stack=call_stack).terminal
            return _Value(terminal=terminal)
        if isinstance(node, ast.BinOp):
            left = self._eval_expr(node.left, state, call_stack=call_stack)
            if left.terminal:
                return _Value(terminal=True)
            right = self._eval_expr(node.right, state, call_stack=call_stack)
            if right.terminal:
                return _Value(terminal=True)
            self._check_optional(node.left, left, state)
            self._check_optional(node.right, right, state)
            return _Value()
        if isinstance(node, ast.BoolOp):
            bool_values: list[_Value] = []
            eval_state = state.copy()
            for part in node.values:
                value = self._eval_expr(part, eval_state, call_stack=call_stack)
                self._check_optional(part, value, eval_state)
                bool_values.append(value)
                if value.terminal:
                    if len(bool_values) == 1:
                        return _Value(terminal=True)
                    return _value_union(bool_values)
                if isinstance(node.op, ast.And):
                    eval_state = self._refine(eval_state, part, truth=True)
                else:
                    eval_state = self._refine(eval_state, part, truth=False)
            return _value_union(bool_values)
        if isinstance(node, ast.Compare):
            left = self._eval_expr(node.left, state, call_stack=call_stack)
            if left.terminal:
                return _Value(terminal=True)
            terminal = False
            for comparator in node.comparators:
                right = self._eval_expr(comparator, state, call_stack=call_stack)
                if right.terminal:
                    terminal = True
                    break
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
            return _Value(terminal=terminal)
        if isinstance(node, ast.UnaryOp):
            value = self._eval_expr(node.operand, state, call_stack=call_stack)
            if value.terminal:
                return _Value(terminal=True)
            self._check_optional(node.operand, value, state)
            return _Value()
        if isinstance(node, ast.IfExp):
            true_state = state.copy()
            test_value = self._eval_expr(node.test, true_state, call_stack=call_stack)
            if test_value.terminal:
                return _Value(terminal=True)
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
        child_values: list[_Value] = []
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, ast.expr):
                continue
            value = self._eval_expr(child, state, call_stack=call_stack)
            child_values.append(value)
            if value.terminal:
                break
        return _value_union(child_values)

    def _eval_call(self, node: ast.Call, state: _State, *, call_stack: tuple[str, ...]) -> _Value:
        callable_value = self._eval_expr(node.func, state, call_stack=call_stack)
        if callable_value.terminal:
            return _Value(terminal=True)
        evaluated_arguments: list[tuple[ast.expr, _Value, _State]] = []
        args: list[_Value] = []
        for argument in node.args:
            value = self._eval_expr(argument, state, call_stack=call_stack)
            args.append(value)
            evaluated_arguments.append((argument, value, state.copy()))
            if value.terminal:
                return _Value(terminal=True)
        kwargs: list[_Value] = []
        for keyword in node.keywords:
            value = self._eval_expr(keyword.value, state, call_stack=call_stack)
            kwargs.append(value)
            evaluated_arguments.append((keyword.value, value, state.copy()))
            if value.terminal:
                return _Value(terminal=True)
        values = [*args, *kwargs]

        callable_kinds = _callable_kinds(callable_value)
        builtin_results: list[_Value] = []
        if "direct" in callable_kinds:
            token = f"{_PROVIDER_CALL}:{self.path}:{node.lineno}:{node.col_offset + 1}"
            builtin_results.append(_Value(taint=frozenset({token}), mapping=True, mapping_id=token))
        if "helper" in callable_kinds:
            token = f"optional:{self.path}:{node.lineno}:{node.col_offset + 1}"
            builtin_results.append(_Value(optional=True, optional_id=token))
        if "terminal" in callable_kinds:
            builtin_results.append(_Value(terminal=True))
        if "record" in callable_kinds:
            builtin_results.append(_Value())
        if "tainted-copy" in callable_kinds:
            mapping_id = f"copy:{self.path}:{node.lineno}:{node.col_offset + 1}"
            builtin_results.append(
                _Value(taint=callable_value.taint, mapping=True, mapping_id=mapping_id)
            )
        if "tainted-get" in callable_kinds:
            key = _key_text(node.args[0]) if node.args else "<unknown>"
            has_reviewed_default = len(node.args) >= 2 and self.optional_defaults.get(
                key
            ) == _key_text(node.args[1])
            if not has_reviewed_default and not self._mapping_present(
                callable_value,
                node.args[0] if node.args else ast.Constant("<unknown>"),
                state,
            ):
                self._emit(
                    node,
                    "unsafe_get",
                    "direct .get() of provider-backed attribute mapping",
                    callable_value,
                )
            builtin_results.append(_Value())
        if _UNKNOWN_CALLABLE in callable_kinds:
            for argument, value, argument_state in evaluated_arguments:
                optional_node = argument.value if isinstance(argument, ast.Starred) else argument
                self._check_optional(optional_node, value, argument_state)
                if value.taint:
                    self._check_taint_escape(
                        node, value, "passing provider-backed mapping to unknown call"
                    )
            token = f"unknown-call:{self.path}:{node.lineno}:{node.col_offset + 1}"
            builtin_results.append(_Value(taint=frozenset({token}), mapping=True, mapping_id=token))

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "dict"
            and len(args) == 1
            and not node.keywords
            and args[0].taint
        ):
            mapping_id = f"dict:{self.path}:{node.lineno}:{node.col_offset + 1}"
            return _Value(taint=args[0].taint, mapping=True, mapping_id=mapping_id)

        function_alternatives = self._resolve_callable_alternatives(
            node.func, callable_value, state, call_stack
        )
        if function_alternatives:
            results: list[_Value] = list(builtin_results)
            input_optional_ids = set().union(*(_optional_ids(value) for value in values))
            for function, closure_state in function_alternatives:
                self.called_functions.add(function.identity)
                if any(value.taint for value in values) and (
                    self._negative_oracle_summary(function) is not None
                    or function.qualified_name in self.reviewed_negative_oracles
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
                if function.identity in call_stack or len(call_stack) >= _MAX_CALL_DEPTH:
                    tainted = _value_union(values)
                    if tainted.taint:
                        self._check_taint_escape(
                            node, tainted, "unresolved recursive helper argument"
                        )
                    results.append(_Value())
                    continue
                results.append(
                    self._analyze_function(
                        function,
                        argument_values,
                        closure_state=self._closure_state_for_call(
                            function, state, call_stack, closure_state
                        ),
                        call_stack=call_stack,
                        top_level=False,
                    )
                )
            result = _value_union(
                [
                    _rebase_optional_ids(
                        result,
                        input_ids=input_optional_ids,
                        call_token=f"optional-call:{self.path}:{node.lineno}:{node.col_offset + 1}",
                    )
                    for result in results
                ]
            )
            if result.mapping and result.taint:
                mapping_id = f"call:{self.path}:{node.lineno}:{node.col_offset + 1}"
                return _Value(
                    taint=result.taint,
                    optional=result.optional,
                    optional_id=result.optional_id,
                    terminal=result.terminal,
                    callable_kind=result.callable_kind,
                    callable_kinds=result.callable_kinds,
                    callable_closures=result.callable_closures,
                    callable_unknown=result.callable_unknown,
                    closure_state=result.closure_state,
                    closure_states=result.closure_states,
                    elements=result.elements,
                    mapping=True,
                    mapping_id=mapping_id,
                )
            return result

        if builtin_results:
            return _value_union(builtin_results)

        for argument, value, argument_state in evaluated_arguments:
            optional_node = argument.value if isinstance(argument, ast.Starred) else argument
            self._check_optional(optional_node, value, argument_state)
            if value.taint:
                self._check_taint_escape(
                    node, value, "passing provider-backed mapping to unknown call"
                )
        return _Value()

    def _mapping_present(self, value: _Value, key_node: ast.expr, state: _State) -> bool:
        key = self._key_identity(key_node)
        mapping_id = self._mapping_identity(value)
        return mapping_id is not None and ("present", mapping_id, key) in state.facts

    @staticmethod
    def _mapping_identity(value: _Value) -> str | None:
        if value.mapping_id is not None:
            return value.mapping_id
        if len(value.taint) == 1:
            return next(iter(value.taint))
        return None

    def _key_identity(self, node: ast.expr) -> str:
        key = _key_text(node)
        if self._stable_key_expression(node):
            return key
        return f"{key}@{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}"

    def _refine(self, state: _State, test: ast.expr, *, truth: bool) -> _State:
        refined = state.copy()
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._refine(refined, test.operand, truth=not truth)
        if isinstance(test, ast.BoolOp):
            if isinstance(test.op, ast.And) and truth:
                for part in test.values:
                    refined = self._refine(refined, part, truth=True)
            elif isinstance(test.op, ast.Or) and not truth:
                for part in test.values:
                    refined = self._refine(refined, part, truth=False)
            return refined
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
            op = test.ops[0]
            comparator = test.comparators[0]
            if isinstance(op, (ast.In, ast.NotIn)):
                mapping = self._eval_expr(comparator, refined, call_stack=())
                key = self._key_identity(test.left)
                present = truth if isinstance(op, ast.In) else not truth
                token = self._mapping_identity(mapping)
                if token is not None:
                    refined.facts.discard(("present" if not present else "absent", token, key))
                    refined.facts.add(("present" if present else "absent", token, key))
            elif isinstance(op, (ast.Is, ast.IsNot)) and isinstance(test.left, ast.Name):
                right = comparator
                if self._is_missing_sentinel(right, refined):
                    missing = truth if isinstance(op, ast.Is) else not truth
                    refined.present_values.discard(test.left.id)
                    refined.missing_values.discard(test.left.id)
                    if missing:
                        refined.missing_values.add(test.left.id)
                    else:
                        refined.present_values.add(test.left.id)
                        self._materialize_present(refined, test.left.id)
        return refined

    @staticmethod
    def _materialize_present(state: _State, name: str) -> None:
        value = state.env.get(name)
        if value is None or not value.optional:
            return
        state.env[name] = _Value(
            taint=value.taint,
            optional_id=value.optional_id,
            terminal=value.terminal,
            callable_kind=value.callable_kind,
            callable_kinds=value.callable_kinds,
            callable_closures=value.callable_closures,
            callable_unknown=value.callable_unknown,
            closure_state=value.closure_state,
            closure_states=value.closure_states,
            elements=value.elements,
            mapping=value.mapping,
            mapping_id=value.mapping_id,
        )

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
    contract = _child_evidence_contract(path, tree, source)
    baseline = _Analyzer(source, path).analyze(
        tree,
        reviewed_optional_helpers=reviewed_optional_helpers,
        reviewed_negative_oracles=reviewed_negative_oracles,
        optional_defaults=optional_defaults,
    )
    filtered = [
        violation
        for violation in baseline
        if not (
            violation.code == "unstructured_absence"
            and (violation.line, violation.column) in contract.approved
        )
        and not (
            violation.code == "taint_escape"
            and (violation.line, violation.column, violation.provenance)
            in contract.observer_approved
        )
    ]
    return sorted({*filtered, *contract.violations})


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
