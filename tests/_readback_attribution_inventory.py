"""Fail-closed, fixed-point source inventory for readback attribution.

The inventory lives under ``tests`` deliberately.  It is a source-review aid rather than
runtime framework code: it follows classification emitters through the helpers in the
testcase tree and reports the *relational* state reaching each emitter.  A future release
gate can turn reviewed slices into a zero assertion without teaching the production package
about repository-specific source layout.

The analysis is conservative.  Unknown expressions, unresolved local calls, and unknown
defaults are retained as ``unresolved`` findings.  ``readback_only`` therefore means
"readback candidates plus every uncertainty", never "silently drop things we could not
understand".  Two narrow exemptions exist, each pinned by the gate file: aliases
rooted at out-of-tree module attributes, and classification-module members proven
not to emit (``set_mechanism``/``Classification``).
"""

from __future__ import annotations

import ast
import hashlib
import io
import itertools
import json
import subprocess
import tarfile
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

C_GET_ATTRIBUTE_VALUE: Final = "C_GetAttributeValue"
UNKNOWN_OPERATION: Final = "<unknown>"
UNKNOWN_MECHANISM: Final = "<unknown>"
INHERITED_MECHANISM: Final = "<inherited>"
NONE_VALUE: Final = "<none>"
OMITTED_VALUE: Final = "<omitted>"
TRUE_VALUE: Final = "<true>"
FALSE_VALUE: Final = "<false>"
PARAM_PREFIX: Final = "$"
TUPLE_VALUE: Final = "<tuple>"

STATUS_UNSAFE_INHERITED_READBACK: Final = "unsafe_inherited_readback"
STATUS_EXPLICIT_MECHANISM_READBACK: Final = "explicit_mechanism_readback"
STATUS_SAFE_MECHANISM_FREE_READBACK: Final = "safe_mechanism_free_readback"
STATUS_EXPLICIT_MECHANISM_GROUPING: Final = "explicit_mechanism_grouping"
STATUS_NON_READBACK: Final = "non_readback"
STATUS_UNRESOLVED: Final = "unresolved"
GATE_REJECT: Final = "reject"
GATE_SAFE: Final = "safe"
GATE_GROUPING: Final = "grouping"
GATE_EXCLUDED: Final = "excluded"

_CLASSIFICATION_MODULES: Final = frozenset({"pkcs11_check.classification", "pkcs11_check"})
_CONFTES_MODULE: Final = "pkcs11_check.testcases.conftest"
_CLASSIFICATION_EMITTERS: Final = frozenset({"classify", "record_as", "fail_as", "xfail_as"})
_HELPER_EMITTERS: Final = frozenset({"assert_correct"})
_EMITTERS: Final = _CLASSIFICATION_EMITTERS | _HELPER_EMITTERS
_EMITTER_LIKE_NAMES: Final = _EMITTERS | {"emit"}
# Classification-module members that never emit: the ambient-context setter and
# the record dataclass constructor. Calls bound to these (verified against the
# live module by the gate file) carry operation/mechanism kwargs as data, not
# attribution. Unknown names stay candidates: fail closed on new members.
_CLASSIFICATION_NON_EMITTERS: Final = frozenset({"set_mechanism", "Classification"})
_ATTRIBUTION_KEYWORDS: Final = frozenset({"operation", "mechanism", "inherit_mechanism"})
_EXTERNAL: Final = "external"
RECEIVER_UNBOUND: Final = "unbound"
RECEIVER_INSTANCE_BOUND: Final = "instance-bound"
RECEIVER_CLASS_BOUND: Final = "class-bound"
RECEIVER_STATIC: Final = "static"
RECEIVER_UNKNOWN: Final = "unknown"
type Truth = bool | None


@dataclass(frozen=True, order=True, slots=True)
class CallerCoordinate:
    """Stable source coordinate of the helper call that supplied an emitter state."""

    path: str
    line: int
    column: int
    function: str


@dataclass(frozen=True, order=True, slots=True)
class EffectiveState:
    """One relational operation/mechanism/inheritance state reaching an emitter."""

    operation: str
    mechanism: str
    inherit_mechanism: str
    caller: CallerCoordinate
    status: str


@dataclass(frozen=True, order=True, slots=True)
class FlattenedEffectiveState:
    """One effective state with the finding identity that emitted it."""

    finding: EmitterFinding
    state: EffectiveState

    @property
    def operation(self) -> str:
        return self.state.operation

    @property
    def mechanism(self) -> str:
        return self.state.mechanism

    @property
    def inherit_mechanism(self) -> str:
        return self.state.inherit_mechanism

    @property
    def caller(self) -> CallerCoordinate:
        return self.state.caller

    @property
    def status(self) -> str:
        return self.state.status


@dataclass(frozen=True, order=True, slots=True)
class EmitterFinding:
    """One deterministic emitter finding, retaining all effective states."""

    path: str
    line: int
    column: int
    function: str
    emitter: str
    states: tuple[EffectiveState, ...]
    uncertain: bool = False
    expression: str = ""
    forwarded_parameters: tuple[str, ...] = ()

    @property
    def operations(self) -> tuple[str, ...]:
        """Compatibility view: the sorted operation projection of ``states``."""
        return tuple(sorted({state.operation for state in self.states}))

    @property
    def mechanisms(self) -> tuple[str, ...]:
        """Sorted mechanism projection of the relational states."""
        return tuple(sorted({state.mechanism for state in self.states}))

    @property
    def inherit_mechanisms(self) -> tuple[str, ...]:
        """Sorted inheritance projection of the relational states."""
        return tuple(sorted({state.inherit_mechanism for state in self.states}))

    @property
    def caller_coordinates(self) -> tuple[CallerCoordinate, ...]:
        """Sorted immediate helper-call coordinates for this emitter."""
        return tuple(sorted({state.caller for state in self.states}))

    @property
    def status(self) -> str:
        """Return the status when uniform, otherwise fail closed as unresolved."""
        if self.uncertain:
            return STATUS_UNRESOLVED
        statuses = {state.status for state in self.states}
        return next(iter(statuses)) if len(statuses) == 1 else STATUS_UNRESOLVED

    @property
    def is_readback(self) -> bool:
        """Whether this is a readback candidate or an uncertainty that must be gated."""
        return self.status != STATUS_NON_READBACK

    @property
    def effective_states(self) -> tuple[EffectiveState, ...]:
        """Expose the relational states in their deterministic flattened form."""
        return self.states

    @property
    def gate_action(self) -> str:
        """Return the conservative release-gate action for this finding."""
        statuses = {state.status for state in self.states}
        if (
            self.uncertain
            or not statuses
            or STATUS_UNRESOLVED in statuses
            or STATUS_UNSAFE_INHERITED_READBACK in statuses
        ):
            return GATE_REJECT
        if statuses == {STATUS_SAFE_MECHANISM_FREE_READBACK}:
            return GATE_SAFE
        if statuses == {STATUS_EXPLICIT_MECHANISM_READBACK}:
            return GATE_GROUPING
        if statuses <= {STATUS_EXPLICIT_MECHANISM_GROUPING, STATUS_NON_READBACK}:
            return GATE_EXCLUDED
        return GATE_REJECT


@dataclass(frozen=True, slots=True)
class InventoryCharacterization:
    """Pinned, machine-readable totals for a current-tree characterization."""

    total: int
    candidate_total: int
    file_total: int
    statuses: tuple[tuple[str, int], ...]
    state_statuses: tuple[tuple[str, int], ...]
    mixed_unsafe_states: int
    digest: str
    candidate_digest: str
    corpus_digest: str
    direct_emitter_census: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class CoordinateCensus:
    """Independent AST coordinates used to audit analyzer registration coverage."""

    definition_coordinates: tuple[CallerCoordinate, ...]
    emitter_coordinates: tuple[tuple[CallerCoordinate, str], ...]


@dataclass
class _Domain:
    """Small abstract value domain with scalar truthiness and tuple elements."""

    values: dict[str, set[Truth]] = field(default_factory=dict)
    elements: tuple[_Domain, ...] = ()

    @classmethod
    def scalar(cls, value: str, truth: Truth = None) -> _Domain:
        return cls(values={value: {truth}})

    @classmethod
    def unknown(cls) -> _Domain:
        return cls.scalar(UNKNOWN_OPERATION, None)

    @classmethod
    def tuple_of(cls, elements: tuple[_Domain, ...]) -> _Domain:
        return cls(values={TUPLE_VALUE: {None}}, elements=elements)

    def copy(self) -> _Domain:
        return _Domain(
            values={value: set(truths) for value, truths in self.values.items()},
            elements=tuple(element.copy() for element in self.elements),
        )

    def union(self, other: _Domain) -> bool:
        changed = False
        had_values = bool(self.values)
        had_tuple = TUPLE_VALUE in self.values
        other_has_tuple = TUPLE_VALUE in other.values
        for value, truths in other.values.items():
            target = self.values.setdefault(value, set())
            before = len(target)
            target.update(truths)
            changed |= len(target) != before
        if self.elements and other.values and not other_has_tuple:
            if any(element.values for element in self.elements):
                unknown_elements = tuple(_Domain.unknown() for _ in self.elements)
                if self.elements != unknown_elements:
                    self.elements = unknown_elements
                    changed = True
        if other.elements:
            if had_values and not had_tuple:
                unknown_elements = tuple(_Domain.unknown() for _ in other.elements)
                if self.elements != unknown_elements:
                    self.elements = unknown_elements
                    changed = True
            width = max(len(self.elements), len(other.elements))
            existing = list(self.elements)
            while len(existing) < width:
                existing.append(_Domain.unknown())
            for index in range(width):
                if index >= len(self.elements) and index < len(other.elements):
                    changed = True
                if index < len(other.elements):
                    changed |= existing[index].union(other.elements[index])
            self.elements = tuple(existing)
        return changed

    def tokens(self) -> tuple[str, ...]:
        return tuple(sorted(self.values))


@dataclass(frozen=True, slots=True)
class _Binding:
    kind: str
    value: str
    receiver_mode: str = RECEIVER_UNBOUND


@dataclass(frozen=True, slots=True)
class _AliasAssignment:
    """A callable alias value together with its lexical definition scope."""

    definition_scope_key: str
    expression: ast.expr


@dataclass(frozen=True, slots=True)
class _CallableBinding:
    """Resolved callable target and the descriptor binding at the call site."""

    target: str | None
    receiver_mode: str


@dataclass(frozen=True, slots=True)
class _CallEdge:
    caller: str
    call: ast.Call
    target: str | None
    receiver_mode: str = RECEIVER_UNKNOWN
    unexpanded_arguments: bool = False
    unresolved_import: bool = False
    unresolved_alias: bool = False
    unresolved_descriptor: bool = False


@dataclass(frozen=True, slots=True)
class _Unit:
    path: str
    module: str
    tree: ast.Module
    bindings: Mapping[str, _Binding]
    module_assignments: Mapping[str, tuple[ast.expr, ...]]
    top_level_bindings: frozenset[str]


@dataclass(frozen=True, slots=True)
class _Scope:
    key: str
    unit: _Unit
    node: ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
    display_name: str
    parameters: tuple[str, ...]
    defaults: Mapping[str, ast.expr]
    assignments: Mapping[str, tuple[ast.expr, ...]]
    local_bindings: frozenset[str]
    local_imports: Mapping[str, _Binding]
    class_owner: str | None
    descriptor: str | None
    calls: tuple[ast.Call, ...]
    emitters: tuple[tuple[str, ast.Call], ...]


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _module_name(path: str) -> str:
    name = path.replace("\\", "/").removesuffix(".py").strip("/")
    parts = [part for part in name.split("/") if part]
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or "<source>"


def _source_coordinate_census(sources: Mapping[str, str]) -> CoordinateCensus:
    """Collect definition/emitter coordinates without consulting ``_Analyzer``."""

    definitions: list[CallerCoordinate] = []
    emitters: list[tuple[CallerCoordinate, str]] = []

    def visit(
        path: str,
        node: ast.AST,
        prefix: str,
        function: str,
    ) -> None:
        current_prefix = prefix
        current_function = function
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = f"{prefix}.{node.name}" if prefix else node.name
            coordinate = CallerCoordinate(path, node.lineno, node.col_offset, name)
            definitions.append(coordinate)
            current_prefix = name
            current_function = name
        elif isinstance(node, ast.ClassDef):
            current_prefix = f"{prefix}.{node.name}" if prefix else node.name
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                emitter = node.func.id
            elif isinstance(node.func, ast.Attribute):
                emitter = node.func.attr
            else:
                emitter = None
            if emitter in _EMITTERS:
                emitters.append(
                    (
                        CallerCoordinate(path, node.lineno, node.col_offset, function),
                        emitter,
                    )
                )
        for child in ast.iter_child_nodes(node):
            visit(path, child, current_prefix, current_function)

    for path in sorted(sources):
        visit(path, ast.parse(sources[path], filename=path), "", "<module>")
    return CoordinateCensus(
        definition_coordinates=tuple(sorted(definitions)),
        emitter_coordinates=tuple(sorted(emitters)),
    )


def _tree_sources(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*.py"))
    }


def coordinate_census(root: Path) -> CoordinateCensus:
    """Return independent source/AST coordinates for the live testcase tree."""
    return _source_coordinate_census(_tree_sources(root))


def registered_definition_coordinates(root: Path) -> tuple[CallerCoordinate, ...]:
    """Return function coordinates currently registered by the analyzer."""
    analyzer, _ = _cached_tree_analyzer(root)
    return tuple(
        sorted(
            CallerCoordinate(
                scope.unit.path,
                scope.node.lineno,
                scope.node.col_offset,
                scope.display_name,
            )
            for scope in analyzer.scopes.values()
            if isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
    )


def _relative_import(module: str, current: str, level: int) -> str:
    if level == 0:
        return module
    package = current.split(".")[:-1]
    prefix = package[: max(0, len(package) - level + 1)]
    return ".".join([*prefix, module] if module else prefix)


def _parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[tuple[str, ...], dict[str, ast.expr]]:
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults: dict[str, ast.expr] = {}
    if node.args.defaults:
        for argument, default in zip(positional[-len(node.args.defaults) :], node.args.defaults):
            defaults[argument.arg] = default
    for argument, kw_default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        if kw_default is not None:
            defaults[argument.arg] = kw_default
    return tuple(argument.arg for argument in [*positional, *node.args.kwonlyargs]), defaults


def _decorator_value_kind(node: ast.expr, aliases: Mapping[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        if node.id in {"classmethod", "staticmethod"}:
            return node.id
        return aliases.get(node.id)
    return None


def _update_decorator_aliases(aliases: Mapping[str, str], statement: ast.stmt) -> dict[str, str]:
    updated = dict(aliases)
    targets: Iterable[ast.expr]
    value: ast.expr | None
    if isinstance(statement, ast.Assign):
        targets = statement.targets
        value = statement.value
    elif isinstance(statement, ast.AnnAssign):
        targets = (statement.target,)
        value = statement.value
    else:
        return updated
    kind = _decorator_value_kind(value, updated) if value is not None else None
    for target in targets:
        if isinstance(target, ast.Name):
            if kind is None:
                updated.pop(target.id, None)
            else:
                updated[target.id] = kind
    return updated


def _descriptor(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: Mapping[str, str],
) -> str:
    if not node.decorator_list:
        return "instance"
    kinds = [_decorator_value_kind(decorator, aliases) for decorator in node.decorator_list]
    if any(kind is None for kind in kinds):
        return "unknown"
    if "classmethod" in kinds:
        return "classmethod"
    if "staticmethod" in kinds:
        return "staticmethod"
    return "instance"


class _ScopeVisitor(ast.NodeVisitor):
    """Collect calls and scalar/tuple assignments for one lexical scope."""

    def __init__(self, root: ast.AST) -> None:
        self.root = root
        self.assignments: defaultdict[str, list[ast.expr]] = defaultdict(list)
        self.local_bindings: set[str] = set()
        self.local_imports: dict[str, _Binding] = {}
        self.calls: list[ast.Call] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is not self.root:
            self.local_bindings.add(node.name)
            return
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is not self.root:
            self.local_bindings.add(node.name)
            return
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if node is not self.root:
            self.local_bindings.add(node.name)
            return
        self.generic_visit(node)

    def _bind_target(self, target: ast.expr, value: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self.local_bindings.add(target.id)
            self.assignments[target.id].append(value)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for index, element in enumerate(target.elts):
                if isinstance(element, ast.Starred):
                    if isinstance(element.value, ast.Name):
                        self.local_bindings.add(element.value.id)
                    continue
                subscript = ast.Subscript(
                    value=value,
                    slice=ast.Constant(index),
                    ctx=ast.Load(),
                )
                self._bind_target(element, subscript)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._bind_target(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._bind_target(node.target, node.value)
        elif isinstance(node.target, ast.Name):
            self.local_bindings.add(node.target.id)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._bind_target(node.target, node.value)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._bind_target(node.target, node.iter)
        self.generic_visit(node)

    def _bind_import(self, name: str, binding: _Binding) -> None:
        self.local_bindings.add(name)
        existing = self.local_imports.get(name)
        if existing is not None and existing != binding:
            # Conflicting rebinding (try/except fallback imports): the runtime
            # target is branch-dependent, so fail closed instead of last-wins.
            self.local_imports[name] = _Binding(
                "unresolved-import", f"{existing.value}|{binding.value}"
            )
        else:
            self.local_imports[name] = binding

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self._bind_import(name, _Binding("module", alias.name))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            name = alias.asname or alias.name
            module = node.module or ""
            if module in _CLASSIFICATION_MODULES and alias.name in _CLASSIFICATION_EMITTERS:
                self._bind_import(name, _Binding(_EXTERNAL, alias.name))
            elif module == _CONFTES_MODULE and alias.name in _HELPER_EMITTERS:
                self._bind_import(name, _Binding(_EXTERNAL, alias.name))
            elif module == "pkcs11_check" and alias.name == "classification":
                self._bind_import(name, _Binding("module", "pkcs11_check.classification"))
            else:
                self._bind_import(name, _Binding("import", f"{module}:{alias.name}"))

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)


def _parse_imports(
    tree: ast.Module,
    module_name: str,
) -> tuple[dict[str, _Binding], dict[str, tuple[ast.expr, ...]], frozenset[str]]:
    bindings: dict[str, _Binding] = {}
    assignments: defaultdict[str, list[ast.expr]] = defaultdict(list)
    top_level: set[str] = set()

    def _bind_top_import(name: str, binding: _Binding) -> None:
        existing = bindings.get(name)
        if existing is not None and existing != binding and existing.kind in ("module", "import"):
            # Conflicting rebinding: the runtime target is ambiguous, so fail
            # closed instead of last-wins.
            bindings[name] = _Binding("unresolved-import", f"{existing.value}|{binding.value}")
        else:
            bindings[name] = binding

    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            top_level.add(statement.name)
            bindings[statement.name] = _Binding("local", statement.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                name = alias.asname or alias.name.split(".")[0]
                _bind_top_import(name, _Binding("module", alias.name))
        elif isinstance(statement, ast.ImportFrom):
            module = _relative_import(statement.module or "", module_name, statement.level)
            for alias in statement.names:
                name = alias.asname or alias.name
                if alias.name == "*":
                    bindings[name] = _Binding("unknown", f"{module}.*")
                elif module in _CLASSIFICATION_MODULES and alias.name in _CLASSIFICATION_EMITTERS:
                    _bind_top_import(name, _Binding(_EXTERNAL, alias.name))
                elif module == _CONFTES_MODULE and alias.name in _HELPER_EMITTERS:
                    _bind_top_import(name, _Binding(_EXTERNAL, alias.name))
                elif module == "pkcs11_check" and alias.name == "classification":
                    _bind_top_import(name, _Binding("module", "pkcs11_check.classification"))
                else:
                    _bind_top_import(name, _Binding("import", f"{module}:{alias.name}"))
        elif isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    top_level.add(target.id)
                    bindings[target.id] = _Binding("local", target.id)
                    assignments[target.id].append(statement.value)
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            top_level.add(statement.target.id)
            bindings[statement.target.id] = _Binding("local", statement.target.id)
            if statement.value is not None:
                assignments[statement.target.id].append(statement.value)
    return (
        bindings,
        {key: tuple(values) for key, values in assignments.items()},
        frozenset(top_level),
    )


class _Analyzer:
    def __init__(self, sources: Mapping[str, str]) -> None:
        self.units: dict[str, _Unit] = {}
        for path in sorted(sources):
            tree = ast.parse(sources[path], filename=path)
            module = _module_name(path)
            bindings, assignments, top_level = _parse_imports(tree, module)
            self.units[path] = _Unit(
                path=path,
                module=module,
                tree=tree,
                bindings=bindings,
                module_assignments=assignments,
                top_level_bindings=top_level,
            )
        self.module_units = {unit.module: unit for unit in self.units.values()}
        self.scopes: dict[str, _Scope] = {}
        self.class_keys: set[str] = set()
        self.class_assignments: dict[str, Mapping[str, tuple[ast.expr, ...]]] = {}
        self.alias_assignments: dict[tuple[str, str], tuple[_AliasAssignment, ...]] = {}
        self._collect_scopes()
        self.param_domains: dict[tuple[str, str], _Domain] = defaultdict(_Domain)
        self.edges: tuple[_CallEdge, ...] = self._collect_edges()
        self.incoming: defaultdict[str, set[CallerCoordinate]] = defaultdict(set)
        for edge in self.edges:
            if edge.target is not None:
                self.incoming[edge.target].add(self._coordinate(edge.caller, edge.call))
        self._seed_parameters()
        self.context_domains: dict[tuple[str, CallerCoordinate | None], dict[str, _Domain]] = {}
        self.context_defaults: dict[tuple[str, CallerCoordinate | None], dict[str, _Domain]] = {}
        self.context_inputs: dict[
            tuple[
                tuple[str, CallerCoordinate | None],
                tuple[str, CallerCoordinate | None],
            ],
            dict[str, _Domain],
        ] = {}
        self.context_contributions: defaultdict[
            tuple[str, CallerCoordinate | None],
            dict[tuple[str, CallerCoordinate | None], dict[str, _Domain]],
        ] = defaultdict(dict)
        self.context_input_uncertain: dict[
            tuple[
                tuple[str, CallerCoordinate | None],
                tuple[str, CallerCoordinate | None],
            ],
            bool,
        ] = {}
        self.context_uncertain: defaultdict[tuple[str, CallerCoordinate | None], bool] = (
            defaultdict(bool)
        )
        self.context_uncertainty_contributions: defaultdict[
            tuple[str, CallerCoordinate | None],
            dict[tuple[str, CallerCoordinate | None], bool],
        ] = defaultdict(dict)
        self._findings_cache: dict[bool, tuple[EmitterFinding, ...]] = {}
        self._seed_contexts()

    def _module_candidates(self, imported: str) -> tuple[_Unit, ...]:
        direct = self.module_units.get(imported)
        if direct is not None:
            return (direct,)
        stripped = imported.removeprefix("pkcs11_check.testcases.")
        exact = self.module_units.get(stripped)
        if exact is not None:
            return (exact,)
        suffix_matches = tuple(
            unit for module, unit in self.module_units.items() if module.endswith(f".{stripped}")
        )
        return suffix_matches

    def _resolve_module(self, imported: str, current: _Unit) -> _Unit | None:
        del current
        candidates = self._module_candidates(imported)
        return candidates[0] if len(candidates) == 1 else None

    def _register_alias_assignments(
        self,
        scope_key: str,
        assignments: Mapping[str, tuple[ast.expr, ...]],
    ) -> None:
        for name, expressions in assignments.items():
            self.alias_assignments[(scope_key, name)] = tuple(
                _AliasAssignment(scope_key, expression) for expression in expressions
            )

    def _resolve_import_binding(
        self,
        binding: _Binding,
        unit: _Unit,
        seen: set[tuple[str, str]] | None = None,
    ) -> _Binding:
        if binding.kind != "import":
            return binding
        visited = set() if seen is None else seen
        import_key = (unit.module, binding.value)
        if import_key in visited:
            return _Binding("unresolved-import", binding.value)
        visited.add(import_key)
        module, _, symbol = binding.value.partition(":")
        target_unit = self._resolve_module(module, unit)
        if target_unit is None:
            if self._module_candidates(module) or module.startswith("pkcs11_check.testcases"):
                return _Binding("unresolved-import", binding.value)
            return _Binding("unknown", binding.value)
        target_key = f"{target_unit.module}:{symbol}"
        if target_key in self.class_keys:
            return _Binding("class", target_key)
        if target_key in self.scopes:
            return _Binding("function", target_key)
        # Classes and data definitions in scanned modules are resolved imports too.
        # They are not helper functions we can propagate, but treating every
        # non-function definition as an unresolved import would manufacture an
        # unresolved emitter finding for ordinary constructors (for example
        # CkrExpectation in the CKR specification tables).
        rebound = target_unit.bindings.get(symbol)
        if rebound is not None:
            if rebound.kind == "import":
                return self._resolve_import_binding(rebound, target_unit, visited)
            if rebound.kind == "local" and symbol in target_unit.module_assignments:
                target_scope = self.scopes[f"{target_unit.module}::<module>"]
                target_function = self._resolve_callable_name(target_scope, symbol, set())
                if target_function is not None and target_function.target is not None:
                    return _Binding(
                        "function",
                        target_function.target,
                        target_function.receiver_mode,
                    )
                return _Binding("unresolved-import", binding.value)
            if rebound.kind in {_EXTERNAL, "function"}:
                return rebound
            return _Binding(_EXTERNAL, binding.value)
        if symbol in target_unit.top_level_bindings:
            return _Binding(_EXTERNAL, binding.value)
        return _Binding("unresolved-import", binding.value)

    def _collect_scopes(self) -> None:
        for unit in self.units.values():
            module_key = f"{unit.module}::<module>"
            visitor = _ScopeVisitor(unit.tree)
            visitor.visit(unit.tree)
            self.scopes[module_key] = _Scope(
                key=module_key,
                unit=unit,
                node=unit.tree,
                display_name="<module>",
                parameters=(),
                defaults={},
                assignments=unit.module_assignments,
                local_bindings=unit.top_level_bindings,
                local_imports={},
                class_owner=None,
                descriptor=None,
                calls=tuple(visitor.calls),
                emitters=(),
            )
            self._register_alias_assignments(module_key, unit.module_assignments)

        def visit_body(
            unit: _Unit,
            body: list[ast.stmt],
            prefix: str = "",
            class_owner: str | None = None,
            in_class: bool = False,
            decorator_aliases: Mapping[str, str] | None = None,
        ) -> None:
            def visit_compound(node: ast.AST) -> None:
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        visit_body(
                            unit,
                            [child],
                            prefix,
                            class_owner,
                            in_class,
                            decorator_aliases,
                        )
                    elif isinstance(child, ast.AST):
                        visit_compound(child)

            active_decorator_aliases = dict(decorator_aliases or {})
            for statement in body:
                if isinstance(statement, ast.ClassDef):
                    name = f"{prefix}.{statement.name}" if prefix else statement.name
                    class_key = f"{unit.module}:{name}"
                    self.class_keys.add(class_key)
                    class_assignments: defaultdict[str, list[ast.expr]] = defaultdict(list)
                    class_bindings: set[str] = set()
                    for class_statement in statement.body:
                        if isinstance(
                            class_statement,
                            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                        ):
                            class_bindings.add(class_statement.name)
                        if isinstance(class_statement, ast.Assign):
                            for target in class_statement.targets:
                                if isinstance(target, ast.Name):
                                    class_assignments[target.id].append(class_statement.value)
                                    class_bindings.add(target.id)
                        elif isinstance(class_statement, ast.AnnAssign):
                            if (
                                isinstance(class_statement.target, ast.Name)
                                and class_statement.value
                            ):
                                class_assignments[class_statement.target.id].append(
                                    class_statement.value
                                )
                                class_bindings.add(class_statement.target.id)
                    self.class_assignments[class_key] = {
                        key: tuple(values) for key, values in class_assignments.items()
                    }
                    self.scopes[class_key] = _Scope(
                        key=class_key,
                        unit=unit,
                        node=statement,
                        display_name=name,
                        parameters=(),
                        defaults={},
                        assignments=self.class_assignments[class_key],
                        local_bindings=frozenset(class_bindings),
                        local_imports={},
                        class_owner=None,
                        descriptor=None,
                        calls=(),
                        emitters=(),
                    )
                    self._register_alias_assignments(class_key, self.class_assignments[class_key])
                    visit_body(unit, statement.body, name, name, True, active_decorator_aliases)
                    continue
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    active_decorator_aliases = _update_decorator_aliases(
                        active_decorator_aliases, statement
                    )
                    continue
                name = f"{prefix}.{statement.name}" if prefix else statement.name
                key = f"{unit.module}:{name}"
                parameters, defaults = _parameters(statement)
                visitor = _ScopeVisitor(statement)
                visitor.visit(statement)
                local_bindings = set(visitor.local_bindings)
                local_bindings.update(parameters)
                self.scopes[key] = _Scope(
                    key=key,
                    unit=unit,
                    node=statement,
                    display_name=name,
                    parameters=parameters,
                    defaults=defaults,
                    assignments={key: tuple(values) for key, values in visitor.assignments.items()},
                    local_bindings=frozenset(local_bindings),
                    local_imports=visitor.local_imports,
                    class_owner=f"{unit.module}:{class_owner}" if class_owner else None,
                    descriptor=(
                        _descriptor(statement, active_decorator_aliases) if in_class else None
                    ),
                    calls=tuple(visitor.calls),
                    emitters=(),
                )
                self._register_alias_assignments(key, self.scopes[key].assignments)
                visit_body(unit, statement.body, name, class_owner, False, active_decorator_aliases)
                continue

            # Definitions nested in if/try/with/loop/match bodies are lexical
            # declarations too.  Walk compound statements without descending
            # into a function/class twice (the branches above own those bodies).
            for statement in body:
                if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    visit_compound(statement)

        for unit in self.units.values():
            visit_body(unit, unit.tree.body)
        for key, scope in list(self.scopes.items()):
            emitters = tuple(
                (emitter, call)
                for call in scope.calls
                if (emitter := self._emitter_name(scope, call)) is not None
            )
            self.scopes[key] = _Scope(
                key=scope.key,
                unit=scope.unit,
                node=scope.node,
                display_name=scope.display_name,
                parameters=scope.parameters,
                defaults=scope.defaults,
                assignments=scope.assignments,
                local_bindings=scope.local_bindings,
                local_imports=scope.local_imports,
                class_owner=scope.class_owner,
                descriptor=scope.descriptor,
                calls=scope.calls,
                emitters=emitters,
            )

    def _binding(self, scope: _Scope, name: str) -> _Binding | None:
        if scope.display_name != "<module>" and name in scope.assignments:
            return None
        if name in scope.local_imports:
            return self._resolve_import_binding(scope.local_imports[name], scope.unit)
        if scope.display_name != "<module>" and name in scope.local_bindings:
            return None
        binding = scope.unit.bindings.get(name)
        if binding is None:
            return None
        return self._resolve_import_binding(binding, scope.unit)

    def _module_alias(self, scope: _Scope, root: str) -> str | None:
        binding = self._binding(scope, root)
        if binding is not None and binding.kind == "module":
            return binding.value
        return None

    def _function_key(self, module: str, name: str) -> str | None:
        candidate = f"{module}:{name}"
        return candidate if candidate in self.scopes and name != "<module>" else None

    def _emitter_name(self, scope: _Scope, call: ast.Call) -> str | None:
        if isinstance(call.func, ast.Name):
            binding = self._binding(scope, call.func.id)
            if binding is not None and binding.kind == _EXTERNAL and binding.value in _EMITTERS:
                return binding.value
            return None
        name = _dotted_name(call.func)
        if name is None:
            return None
        base, _, attribute = name.rpartition(".")
        module = self._module_alias(scope, base.split(".", 1)[0])
        if module in _CLASSIFICATION_MODULES and attribute in _CLASSIFICATION_EMITTERS:
            return attribute
        if module == _CONFTES_MODULE and attribute in _HELPER_EMITTERS:
            return attribute
        if attribute in _HELPER_EMITTERS and module and module.endswith(".conftest"):
            return attribute
        return None

    def _enclosing_scopes(self, scope: _Scope) -> tuple[_Scope, ...]:
        if scope.display_name == "<module>":
            return ()
        parts = scope.display_name.split(".")
        scopes: list[_Scope] = []
        for index in range(len(parts) - 1, 0, -1):
            key = f"{scope.unit.module}:{'.'.join(parts[:index])}"
            parent = self.scopes.get(key)
            if parent is not None:
                scopes.append(parent)
        return tuple(scopes)

    def _alias_expressions(self, scope: _Scope, name: str) -> tuple[_AliasAssignment, ...]:
        """Return lexical alias assignments, retaining each definition scope."""
        scope_keys = [scope.key]
        scope_keys.extend(parent.key for parent in self._enclosing_scopes(scope))
        if scope.class_owner is not None:
            scope_keys.append(scope.class_owner)
        scope_keys.append(f"{scope.unit.module}::<module>")
        for scope_key in scope_keys:
            assignments = self.alias_assignments.get((scope_key, name), ())
            if assignments:
                return assignments
        return ()

    def _alias_expressions_for_scope_key(
        self,
        scope_key: str,
        name: str,
    ) -> tuple[_AliasAssignment, ...]:
        return self.alias_assignments.get((scope_key, name), ())

    def _alias_definition_scope(self, current: _Scope, assignment: _AliasAssignment) -> _Scope:
        """Return an alias's lexical scope; class bodies have no call scope node."""
        return self.scopes.get(assignment.definition_scope_key, current)

    def _resolve_callable_name(
        self,
        scope: _Scope,
        name: str,
        seen: set[tuple[str, str]],
    ) -> _CallableBinding | None:
        token = (scope.key, name)
        if token in seen:
            return None
        next_seen = {*seen, token}
        expressions = self._alias_expressions(scope, name)
        if expressions:
            targets = [
                self._resolve_callable_expression(
                    self._alias_definition_scope(scope, assignment),
                    assignment.expression,
                    next_seen,
                )
                for assignment in expressions
            ]
            if (
                len(targets) == len(expressions)
                and targets
                and all(target is not None for target in targets)
                and len({(target.target, target.receiver_mode) for target in targets if target})
                == 1
            ):
                return targets[0]
            return None
        binding = self._binding(scope, name)
        if binding is not None:
            if binding.kind == "function":
                return _CallableBinding(binding.value, binding.receiver_mode)
            if binding.kind in {"class", _EXTERNAL, "unknown", "unresolved-import"}:
                return None
        prefixes: list[str] = []
        if scope.display_name != "<module>":
            parts = scope.display_name.split(".")
            prefixes.extend(".".join(parts[:index]) for index in range(len(parts), 0, -1))
        if scope.class_owner is not None:
            owner = scope.class_owner.split(":", 1)[1]
            prefixes.insert(0, owner)
        prefixes.append("")
        for prefix in prefixes:
            key = self._function_key(scope.unit.module, f"{prefix}.{name}".strip("."))
            if key is not None:
                return _CallableBinding(key, RECEIVER_UNBOUND)
        return None

    def _static_container_elements(
        self,
        scope: _Scope,
        expression: ast.expr,
        key: ast.expr,
    ) -> tuple[tuple[_Scope, ast.expr], ...] | None:
        """Select from a deliberately small, literal callable container domain."""
        if isinstance(expression, ast.Name):
            assignments = self._alias_expressions(scope, expression.id)
        else:
            assignments = (_AliasAssignment(scope.key, expression),)
        if not assignments:
            return None
        selected: list[tuple[_Scope, ast.expr]] = []
        index: int | None = None
        string_key: str | None = None
        if isinstance(key, ast.Constant) and type(key.value) is int:
            index = key.value
        elif (
            isinstance(key, ast.UnaryOp)
            and isinstance(key.op, (ast.USub, ast.UAdd))
            and isinstance(key.operand, ast.Constant)
            and type(key.operand.value) is int
        ):
            index = -key.operand.value if isinstance(key.op, ast.USub) else key.operand.value
        elif isinstance(key, ast.Constant) and type(key.value) is str:
            string_key = key.value
        else:
            return None
        for assignment in assignments:
            container = assignment.expression
            if isinstance(container, (ast.List, ast.Tuple)) and index is not None:
                if index < 0 or index >= len(container.elts):
                    return None
                selected.append(
                    (
                        self._alias_definition_scope(scope, assignment),
                        container.elts[index],
                    )
                )
            elif isinstance(container, ast.Dict) and string_key is not None:
                if any(item_key is None for item_key in container.keys):
                    return None
                matches = [
                    value
                    for item_key, value in zip(container.keys, container.values)
                    if (
                        isinstance(item_key, ast.Constant)
                        and type(item_key.value) is str
                        and item_key.value == string_key
                    )
                ]
                if len(matches) != 1:
                    return None
                selected.append(
                    (
                        self._alias_definition_scope(scope, assignment),
                        matches[0],
                    )
                )
            else:
                return None
        return tuple(selected)

    def _resolve_container_callable(
        self,
        scope: _Scope,
        expression: ast.Subscript,
        seen: set[tuple[str, str]],
    ) -> _CallableBinding | None:
        selected = self._static_container_elements(scope, expression.value, expression.slice)
        if not selected:
            return None
        targets = [
            self._resolve_callable_expression(definition_scope, item, seen)
            for definition_scope, item in selected
        ]
        if (
            len(targets) == len(selected)
            and all(target is not None for target in targets)
            and len({(target.target, target.receiver_mode) for target in targets if target}) == 1
        ):
            return targets[0]
        return None

    def _classification_connected_expression(
        self,
        scope: _Scope,
        expression: ast.expr,
        seen: set[tuple[str, str]],
    ) -> bool:
        """Conservatively identify containers whose callable values reach emitters."""
        if self._is_classification_object(scope, expression):
            return True
        name = _dotted_name(expression)
        if name is not None and name.rsplit(".", 1)[-1] in _EMITTERS:
            return True
        if isinstance(expression, ast.Subscript):
            return self._classification_connected_expression(scope, expression.value, seen)
        if isinstance(expression, (ast.List, ast.Tuple)):
            return any(
                self._classification_connected_expression(scope, item, seen)
                for item in expression.elts
            )
        if isinstance(expression, ast.Dict):
            return any(
                self._classification_connected_expression(scope, item, seen)
                for item in expression.values
            )
        if isinstance(expression, ast.Name):
            assignments = self._alias_expressions(scope, expression.id)
            if assignments:
                token = (scope.key, expression.id)
                if token in seen:
                    return False
                next_seen = {*seen, token}
                return any(
                    self._classification_connected_expression(
                        self._alias_definition_scope(scope, assignment),
                        assignment.expression,
                        next_seen,
                    )
                    for assignment in assignments
                )
        binding = self._resolve_callable_expression(scope, expression, set())
        if binding is None or binding.target is None:
            return False
        target_scope = self.scopes.get(binding.target)
        if target_scope is None:
            return False
        return self._scope_reaches_emitter(target_scope, seen)

    def _scope_reaches_emitter(self, scope: _Scope, seen: set[tuple[str, str]]) -> bool:
        if scope.key in {key for key, _ in seen}:
            return False
        next_seen = {*seen, (scope.key, "<callable>")}
        if scope.emitters:
            return True
        return any(
            self._classification_connected_expression(scope, call.func, next_seen)
            for call in scope.calls
            if not self._emitter_name(scope, call)
        )

    def _resolve_callable_expression(
        self,
        scope: _Scope,
        expression: ast.expr,
        seen: set[tuple[str, str]],
    ) -> _CallableBinding | None:
        if isinstance(expression, ast.Name):
            return self._resolve_callable_name(scope, expression.id, seen)
        if isinstance(expression, ast.Subscript):
            return self._resolve_container_callable(scope, expression, seen)
        name = _dotted_name(expression)
        if name is None:
            return None
        base, _, attribute = name.rpartition(".")
        root = base.split(".", 1)[0]
        imported_module = self._module_alias(scope, root)
        if imported_module is not None:
            unit = self._resolve_module(imported_module, scope.unit)
            if unit is not None:
                relative = name.removeprefix(f"{root}.")
                target = self._function_key(unit.module, relative)
                if target is not None:
                    return self._callable_binding_for_expression(scope, expression, target)
                return None
            return None
        binding = self._binding(scope, root)
        if binding is not None and binding.kind == "class":
            class_key, _, class_name = binding.value.partition(":")
            target = self._function_key(class_key, f"{class_name}.{attribute}")
            if target is not None:
                return self._callable_binding_for_expression(scope, expression, target)
            return None
        if root in scope.unit.top_level_bindings:
            target = self._function_key(scope.unit.module, f"{root}.{attribute}")
            if target is not None:
                return self._callable_binding_for_expression(scope, expression, target)
            class_alias_key = f"{scope.unit.module}:{root}"
            expressions = self._alias_expressions_for_scope_key(class_alias_key, attribute)
            targets = [
                self._resolve_callable_expression(
                    self._alias_definition_scope(scope, assignment),
                    assignment.expression,
                    seen,
                )
                for assignment in expressions
            ]
            if (
                len(targets) == len(expressions)
                and targets
                and all(target is not None for target in targets)
                and len({(target.target, target.receiver_mode) for target in targets if target})
                == 1
            ):
                resolved = targets[0]
                assert resolved is not None
                if resolved.target is not None:
                    return self._callable_binding_for_expression(scope, expression, resolved.target)
                return resolved
            return None
        if root in {"self", "cls"} and scope.class_owner is not None:
            owner = scope.class_owner.split(":", 1)[1]
            target = self._function_key(scope.unit.module, f"{owner}.{attribute}")
            if target is not None:
                return self._callable_binding_for_expression(scope, expression, target)
            expressions = self._alias_expressions_for_scope_key(scope.class_owner, attribute)
            targets = [
                self._resolve_callable_expression(
                    self._alias_definition_scope(scope, assignment),
                    assignment.expression,
                    seen,
                )
                for assignment in expressions
            ]
            if (
                len(targets) == len(expressions)
                and targets
                and all(target is not None for target in targets)
                and len({(target.target, target.receiver_mode) for target in targets if target})
                == 1
            ):
                resolved = targets[0]
                assert resolved is not None
                if resolved.target is not None:
                    return self._callable_binding_for_expression(scope, expression, resolved.target)
                return resolved
            return None
        if root and scope.class_owner is not None:
            target = self._function_key(scope.unit.module, f"{root}.{attribute}")
            if target is not None:
                return self._callable_binding_for_expression(scope, expression, target)
        return None

    def _callable_binding_for_expression(
        self,
        scope: _Scope,
        expression: ast.expr,
        target_key: str,
    ) -> _CallableBinding:
        target = self.scopes[target_key]
        descriptor = target.descriptor
        if descriptor is None:
            return _CallableBinding(target_key, RECEIVER_UNBOUND)
        if descriptor == "unknown":
            return _CallableBinding(target_key, RECEIVER_UNKNOWN)
        if descriptor == "staticmethod":
            return _CallableBinding(target_key, RECEIVER_STATIC)
        name = _dotted_name(expression)
        if name is None:
            return _CallableBinding(target_key, RECEIVER_UNKNOWN)
        base, _, _ = name.rpartition(".")
        root = base.split(".", 1)[0]
        if root == "self":
            mode = RECEIVER_INSTANCE_BOUND if descriptor == "instance" else RECEIVER_CLASS_BOUND
            return _CallableBinding(target_key, mode)
        if root == "cls":
            mode = RECEIVER_CLASS_BOUND if descriptor == "classmethod" else RECEIVER_UNKNOWN
            return _CallableBinding(target_key, mode)
        binding = self._binding(scope, root)
        class_qualified = root in scope.unit.top_level_bindings or (
            binding is not None and binding.kind == "class"
        )
        if target.class_owner is not None:
            owner = target.class_owner.split(":", 1)[1]
            if binding is not None and binding.kind == "module":
                relative_class = name.removeprefix(f"{root}.").rsplit(".", 1)[0]
                module_unit = self._resolve_module(binding.value, scope.unit)
                class_qualified |= module_unit is target.unit and relative_class == owner
        if class_qualified:
            mode = RECEIVER_CLASS_BOUND if descriptor == "classmethod" else RECEIVER_UNBOUND
            return _CallableBinding(target_key, mode)
        return _CallableBinding(target_key, RECEIVER_UNBOUND)

    def _resolve_function_call(self, scope: _Scope, call: ast.Call) -> _CallableBinding | None:
        return self._resolve_callable_expression(scope, call.func, set())

    def _is_external_module_attribute(self, scope: _Scope, expression: ast.expr) -> bool:
        """Whether an alias value is an attribute of an out-of-tree module.

        Only chains bottoming out at a plain name bound to an imported module
        that resolves outside the scanned tree (and outside the
        classification/conftest modules) count: such a value can be neither an
        in-tree helper nor a recognized emitter. Call/subscript-rooted chains
        (``factory().helper``), unresolvable ``pkcs11_check.testcases.*`` roots
        (typos, mirroring :meth:`_resolve_import_binding`), and emitter-like
        tails stay unresolved so ``emit = foreign.record_as`` keeps its
        fail-closed finding.
        """
        if not isinstance(expression, ast.Attribute):
            return False
        base: ast.expr = expression
        while isinstance(base, ast.Attribute):
            base = base.value
        if not isinstance(base, ast.Name):
            return False
        dotted = _dotted_name(expression)
        if dotted is None:
            return False
        module = self._module_alias(scope, dotted.split(".", 1)[0])
        if module is None or self._is_classification_object(scope, expression):
            return False
        if module.startswith("pkcs11_check.testcases"):
            return False
        if self._module_candidates(module):
            # Resolvable or ambiguous: the target may be an in-tree helper.
            return False
        return dotted.rsplit(".", 1)[-1] not in _EMITTER_LIKE_NAMES

    def _unresolved_callable_alias(self, scope: _Scope, call: ast.Call) -> bool:
        if isinstance(call.func, ast.Name):
            expressions = self._alias_expressions(scope, call.func.id)
            if expressions:
                if all(
                    self._is_external_module_attribute(
                        self._alias_definition_scope(scope, assignment),
                        assignment.expression,
                    )
                    for assignment in expressions
                ):
                    return False
                return self._resolve_function_call(scope, call) is None
            binding = self._binding(scope, call.func.id)
            return binding is not None and binding.kind == "unresolved-import"
        name = _dotted_name(call.func)
        if name is None:
            return False
        root = name.split(".", 1)[0]
        binding = self._binding(scope, root)
        if binding is not None and binding.kind == "unresolved-import":
            return True
        module_name = self._module_alias(scope, root)
        if module_name is None:
            return False
        unit = self._resolve_module(module_name, scope.unit)
        return unit is not None and self._function_key(unit.module, name.rsplit(".", 1)[-1]) is None

    def _call_has_unexpanded_arguments(self, call: ast.Call) -> bool:
        return any(isinstance(argument, ast.Starred) for argument in call.args) or any(
            keyword.arg is None for keyword in call.keywords
        )

    def _unresolved_import_call(self, scope: _Scope, call: ast.Call) -> bool:
        if isinstance(call.func, ast.Name):
            binding = self._binding(scope, call.func.id)
            return binding is not None and binding.kind == "unresolved-import"
        name = _dotted_name(call.func)
        if name is None:
            return False
        root = name.split(".", 1)[0]
        binding = self._binding(scope, root)
        return binding is not None and binding.kind == "unresolved-import"

    def _collect_edges(self) -> tuple[_CallEdge, ...]:
        edges: list[_CallEdge] = []
        for scope in self.scopes.values():
            for call in scope.calls:
                if self._emitter_name(scope, call) is not None:
                    continue
                binding = self._resolve_function_call(scope, call)
                edges.append(
                    _CallEdge(
                        caller=scope.key,
                        call=call,
                        target=binding.target if binding is not None else None,
                        receiver_mode=(
                            binding.receiver_mode if binding is not None else RECEIVER_UNKNOWN
                        ),
                        unexpanded_arguments=self._call_has_unexpanded_arguments(call),
                        unresolved_import=self._unresolved_import_call(scope, call),
                        unresolved_alias=binding is None
                        and self._unresolved_callable_alias(scope, call),
                        unresolved_descriptor=(
                            binding is not None and binding.receiver_mode == RECEIVER_UNKNOWN
                        ),
                    )
                )
        return tuple(edges)

    def _classification_non_emitter_call(self, scope: _Scope, call: ast.Call) -> bool:
        """Whether the call targets a classification-module member that never emits.

        Known gap (accepted): a conditional definition shadowing the import
        (``if ...: def set_mechanism``) is invisible to the top-level import
        tables, so the call exempts though the runtime may bind the local
        def. Only the call-site marker is affected — emitters inside the
        shadowing def still report as their own findings.
        """
        if isinstance(call.func, ast.Name):
            binding = self._binding(scope, call.func.id)
            if binding is None or binding.kind != "unknown":
                return False
            module, _, member = binding.value.partition(":")
            return module in _CLASSIFICATION_MODULES and member in _CLASSIFICATION_NON_EMITTERS
        name = _dotted_name(call.func)
        if name is None:
            return False
        base, _, member = name.rpartition(".")
        module = self._module_alias(scope, base.split(".", 1)[0])
        return module in _CLASSIFICATION_MODULES and member in _CLASSIFICATION_NON_EMITTERS

    def _unknown_call_candidate(self, scope: _Scope, call: ast.Call) -> bool:
        if self._classification_non_emitter_call(scope, call):
            return False
        return (
            self._unsupported_callee_candidate(scope, call)
            or any(keyword.arg in _ATTRIBUTION_KEYWORDS for keyword in call.keywords)
            or self._known_emitter_name(call)
        )

    def _known_emitter_name(self, call: ast.Call) -> bool:
        name = _dotted_name(call.func)
        if name is None:
            return False
        return name.rsplit(".", 1)[-1] in _EMITTER_LIKE_NAMES

    def _is_classification_object(self, scope: _Scope, expression: ast.expr) -> bool:
        name = _dotted_name(expression)
        if name in _CLASSIFICATION_MODULES or name == _CONFTES_MODULE:
            return True
        if name is None:
            return False
        module = self._module_alias(scope, name.split(".", 1)[0])
        return module in _CLASSIFICATION_MODULES or (
            module == _CONFTES_MODULE or (module is not None and module.endswith(".conftest"))
        )

    def _unsupported_callee_candidate(self, scope: _Scope, call: ast.Call) -> bool:
        func = call.func
        if isinstance(func, ast.Call):
            if (
                isinstance(func.func, ast.Name)
                and func.func.id == "getattr"
                and func.args
                and self._is_classification_object(scope, func.args[0])
            ):
                return True
            return False
        if not isinstance(func, ast.Subscript):
            return False
        key = func.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            if key.value in _EMITTERS:
                return True
        return self._is_classification_object(
            scope, func.value
        ) or self._classification_connected_expression(scope, func.value, set())

    def _seed_parameters(self) -> None:
        for scope in self.scopes.values():
            for parameter in scope.parameters:
                default = scope.defaults.get(parameter)
                if default is None:
                    self.param_domains[(scope.key, parameter)].union(
                        _Domain.scalar(f"{PARAM_PREFIX}{parameter}", None)
                    )
                else:
                    self.param_domains[(scope.key, parameter)].union(
                        self._eval(default, scope, set())
                    )

    def _seed_contexts(self) -> None:
        """Create one default context per uncalled scope and one per incoming edge."""
        for key, scope in self.scopes.items():
            coordinates: Iterable[CallerCoordinate | None]
            if self.incoming.get(key):
                coordinates = self.incoming[key]
            else:
                coordinates = (None,)
            for coordinate in coordinates:
                context_key = (key, coordinate)
                defaults = {
                    parameter: self.param_domains[(key, parameter)].copy()
                    for parameter in scope.parameters
                }
                self.context_defaults[context_key] = defaults
                self.context_domains[context_key] = {
                    parameter: domain.copy() for parameter, domain in defaults.items()
                }

    def _domain_for_name(
        self,
        scope: _Scope,
        name: str,
        seen: set[tuple[str, str]],
        domains: Mapping[tuple[str, str], _Domain] | None = None,
    ) -> _Domain:
        """Resolve a name to its value domain (see :meth:`_emitter_depends_on_parameters`)."""
        key = (scope.key, name)
        if key in seen:
            return _Domain.scalar(f"{PARAM_PREFIX}{name}", None)
        next_seen = {*seen, key}
        if name in scope.assignments:
            result = _Domain()
            for expression in scope.assignments[name]:
                result.union(self._eval(expression, scope, next_seen, domains))
            return result if result.values else _Domain.unknown()
        if name in scope.parameters:
            source = self.param_domains if domains is None else domains
            result = source[(scope.key, name)].copy()
            return result if result.values else _Domain.scalar(f"{PARAM_PREFIX}{name}", None)
        if name in scope.unit.module_assignments:
            result = _Domain()
            for expression in scope.unit.module_assignments[name]:
                result.union(self._eval(expression, scope, seen, domains))
            return result if result.values else _Domain.unknown()
        return _Domain.unknown()

    def _eval(
        self,
        node: ast.expr,
        scope: _Scope,
        seen: set[tuple[str, str]],
        domains: Mapping[tuple[str, str], _Domain] | None = None,
    ) -> _Domain:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return _Domain.scalar(node.value, bool(node.value))
            if node.value is None:
                return _Domain.scalar(NONE_VALUE, False)
            if node.value is True:
                return _Domain.scalar(TRUE_VALUE, True)
            if node.value is False:
                return _Domain.scalar(FALSE_VALUE, False)
            return _Domain.unknown()
        if isinstance(node, ast.Name):
            return self._domain_for_name(scope, node.id, seen, domains)
        if isinstance(node, (ast.Tuple, ast.List)):
            return _Domain.tuple_of(
                tuple(self._eval(element, scope, seen, domains) for element in node.elts)
            )
        if isinstance(node, ast.Subscript):
            base = self._eval(node.value, scope, seen, domains)
            index: int | None = None
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int):
                index = node.slice.value
            if index is not None and base.elements:
                try:
                    return base.elements[index]
                except IndexError:
                    return _Domain.unknown()
            return _Domain.unknown()
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            result = _Domain()
            pending = self._eval(node.values[0], scope, seen, domains)
            for operand in node.values[1:]:
                next_pending = _Domain()
                for value, truths in pending.values.items():
                    for truth in truths:
                        if truth is True:
                            result.union(_Domain.scalar(value, truth))
                        else:
                            if truth is None:
                                result.union(_Domain.scalar(value, truth))
                            next_pending.union(self._eval(operand, scope, seen, domains))
                pending = next_pending
            result.union(pending)
            return result if result.values else _Domain.unknown()
        if isinstance(node, ast.IfExp):
            result = self._eval(node.body, scope, seen, domains)
            result.union(self._eval(node.orelse, scope, seen, domains))
            return result
        if isinstance(node, ast.NamedExpr):
            return self._eval(node.value, scope, seen, domains)
        return _Domain.unknown()

    def _propagate(self) -> None:
        """Run a finite-domain worklist to convergence; no silent iteration cap."""
        outgoing: defaultdict[str, list[_CallEdge]] = defaultdict(list)
        for edge in self.edges:
            if edge.target is not None:
                outgoing[edge.caller].append(edge)
        queue = deque(self.context_domains)
        queued = set(self.context_domains)
        while queue:
            context_key = queue.popleft()
            queued.discard(context_key)
            caller_key, _ = context_key
            caller = self.scopes[caller_key]
            caller_context = self.context_domains[context_key]
            caller_domains = {
                (caller.key, parameter): domain for parameter, domain in caller_context.items()
            }
            for edge in outgoing[caller_key]:
                target_key = edge.target
                if target_key is None:
                    continue
                target = self.scopes[target_key]
                target_context_key = (target_key, self._coordinate(edge.caller, edge.call))
                target_context = self.context_domains[target_context_key]
                target_defaults = self.context_defaults[target_context_key]
                input_key = (target_context_key, context_key)
                previous_input = self.context_inputs.get(input_key)
                input_values = {
                    parameter: target_defaults[parameter].copy() for parameter in target.parameters
                }
                parameters = target.parameters
                if edge.receiver_mode in {RECEIVER_INSTANCE_BOUND, RECEIVER_CLASS_BOUND}:
                    parameters = parameters[1:]
                positional = list(edge.call.args)
                for index, parameter in enumerate(parameters):
                    expression: ast.expr | None = None
                    if index < len(positional):
                        expression = positional[index]
                    else:
                        expression = next(
                            (
                                keyword.value
                                for keyword in edge.call.keywords
                                if keyword.arg == parameter
                            ),
                            None,
                        )
                    if expression is not None:
                        values = self._eval(expression, caller, set(), caller_domains)
                        input_values[parameter] = values
                input_changed = previous_input != input_values
                if input_changed:
                    self.context_inputs[input_key] = input_values
                    self.context_contributions[target_context_key][context_key] = input_values
                input_uncertain = (
                    self.context_uncertain[context_key]
                    or edge.unexpanded_arguments
                    or edge.unresolved_descriptor
                )
                previous_uncertain = self.context_input_uncertain.get(input_key)
                uncertainty_changed = previous_uncertain != input_uncertain
                if uncertainty_changed:
                    self.context_input_uncertain[input_key] = input_uncertain
                    self.context_uncertainty_contributions[target_context_key][context_key] = (
                        input_uncertain
                    )
                if input_changed or uncertainty_changed:
                    recomputed = {parameter: _Domain() for parameter in target.parameters}
                    for source_values in self.context_contributions[target_context_key].values():
                        for parameter, values in source_values.items():
                            recomputed[parameter].union(values)
                    recomputed_uncertain = any(
                        self.context_uncertainty_contributions[target_context_key].values()
                    )
                    target_changed = any(
                        target_context[parameter] != recomputed[parameter]
                        for parameter in target.parameters
                    )
                    target_changed |= (
                        self.context_uncertain[target_context_key] != recomputed_uncertain
                    )
                    target_context.update(recomputed)
                    self.context_uncertain[target_context_key] = recomputed_uncertain
                    for parameter, values in recomputed.items():
                        self.param_domains[(target.key, parameter)].union(values)
                else:
                    target_changed = False
                if target_changed and target_context_key not in queued:
                    queue.append(target_context_key)
                    queued.add(target_context_key)

    def _coordinate(self, scope_key: str, call: ast.Call) -> CallerCoordinate:
        scope = self.scopes[scope_key]
        return CallerCoordinate(
            path=scope.unit.path,
            line=call.lineno,
            column=call.col_offset,
            function=scope.display_name,
        )

    def _forwarded_parameters(self, scope: _Scope, call: ast.Call) -> tuple[str, ...]:
        names: set[str] = set()
        for keyword in call.keywords:
            if keyword.arg in _ATTRIBUTION_KEYWORDS:
                names.update(
                    node.id for node in ast.walk(keyword.value) if isinstance(node, ast.Name)
                )
        return tuple(sorted(name for name in names if name in scope.parameters))

    def _emitter_depends_on_parameters(self, scope: _Scope, call: ast.Call) -> bool:
        """Whether attribution kwargs transitively read scope parameters.

        Caller-context uncertainty (star-arg callers, unknown descriptors) can only
        affect attribution through parameters. Direct-literal emitters (even under
        pytest-style decorators or star-arg callers) are certain; anything reaching
        a parameter stays fail-closed. Over-approximates: every ``Name`` under the
        kwargs is followed through local and module assignments. Must cover every
        parameter-reaching channel in :meth:`_domain_for_name`; extend in lockstep.
        """
        pending = [
            node.id
            for keyword in call.keywords
            if keyword.arg in _ATTRIBUTION_KEYWORDS
            for node in ast.walk(keyword.value)
            if isinstance(node, ast.Name)
        ]
        seen: set[str] = set()
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            if name in scope.parameters:
                return True
            for source in (
                scope.assignments.get(name, ()),
                scope.unit.module_assignments.get(name, ()),
            ):
                for expression in source:
                    pending.extend(
                        node.id for node in ast.walk(expression) if isinstance(node, ast.Name)
                    )
        return False

    def _raw_domain(
        self,
        scope: _Scope,
        call: ast.Call,
        keyword_name: str,
        default: _Domain,
        domains: Mapping[tuple[str, str], _Domain] | None = None,
    ) -> _Domain:
        expression = next(
            (keyword.value for keyword in call.keywords if keyword.arg == keyword_name),
            None,
        )
        return (
            default.copy() if expression is None else self._eval(expression, scope, set(), domains)
        )

    def _effective_mechanism(self, raw: str, inherit: str) -> str:
        if inherit == TRUE_VALUE and raw in {NONE_VALUE, OMITTED_VALUE}:
            return INHERITED_MECHANISM
        if inherit == FALSE_VALUE and raw == OMITTED_VALUE:
            return NONE_VALUE
        if raw == OMITTED_VALUE:
            return UNKNOWN_MECHANISM
        return raw

    def _status(self, operation: str, mechanism: str, inherit: str) -> str:
        uncertain = (
            operation == UNKNOWN_OPERATION
            or operation == TUPLE_VALUE
            or operation.startswith(PARAM_PREFIX)
            or mechanism == UNKNOWN_MECHANISM
            or mechanism == TUPLE_VALUE
            or mechanism.startswith(PARAM_PREFIX)
            or inherit not in {TRUE_VALUE, FALSE_VALUE}
        )
        if uncertain:
            return STATUS_UNRESOLVED
        if operation == C_GET_ATTRIBUTE_VALUE:
            if inherit == TRUE_VALUE and mechanism == INHERITED_MECHANISM:
                return STATUS_UNSAFE_INHERITED_READBACK
            if inherit == FALSE_VALUE and mechanism == NONE_VALUE:
                return STATUS_SAFE_MECHANISM_FREE_READBACK
            return STATUS_EXPLICIT_MECHANISM_READBACK
        if mechanism not in {NONE_VALUE, INHERITED_MECHANISM}:
            return STATUS_EXPLICIT_MECHANISM_GROUPING
        return STATUS_NON_READBACK

    def _finding(
        self,
        scope: _Scope,
        emitter: str,
        call: ast.Call,
        *,
        unknown_edge: bool = False,
        caller_override: CallerCoordinate | None = None,
    ) -> EmitterFinding:
        states: set[EffectiveState] = set()
        context_items: list[
            tuple[CallerCoordinate, tuple[str, CallerCoordinate | None], dict[str, _Domain]]
        ] = [
            (coordinate, (scope.key, coordinate), self.context_domains[(scope.key, coordinate)])
            for coordinate in sorted(self.incoming.get(scope.key, ()))
        ]
        if not context_items:
            context_items = [
                (
                    self._coordinate(scope.key, call),
                    (scope.key, None),
                    self.context_domains[(scope.key, None)],
                )
            ]
        for caller, context_key, context in context_items:
            domains = {(scope.key, parameter): domain for parameter, domain in context.items()}
            op_domain = self._raw_domain(
                scope,
                call,
                "operation",
                _Domain.unknown(),
                domains,
            )
            if unknown_edge:
                mech_domain = self._raw_domain(scope, call, "mechanism", _Domain.unknown(), domains)
                inherit_domain = self._raw_domain(
                    scope, call, "inherit_mechanism", _Domain.unknown(), domains
                )
            else:
                mech_domain = self._raw_domain(
                    scope,
                    call,
                    "mechanism",
                    _Domain.scalar(OMITTED_VALUE, None),
                    domains,
                )
                inherit_domain = self._raw_domain(
                    scope,
                    call,
                    "inherit_mechanism",
                    _Domain.scalar(TRUE_VALUE, True),
                    domains,
                )
            effective_caller = caller_override or caller
            for operation, mechanism_raw, inherit_raw in itertools.product(
                op_domain.tokens(), mech_domain.tokens(), inherit_domain.tokens()
            ):
                if operation == NONE_VALUE:
                    operation = UNKNOWN_OPERATION
                mechanism = self._effective_mechanism(mechanism_raw, inherit_raw)
                states.add(
                    EffectiveState(
                        operation=operation,
                        mechanism=mechanism,
                        inherit_mechanism=inherit_raw,
                        caller=effective_caller,
                        status=self._status(operation, mechanism, inherit_raw),
                    )
                )
        expression_node = next(
            (keyword.value for keyword in call.keywords if keyword.arg == "operation"),
            None,
        )
        return EmitterFinding(
            path=scope.unit.path,
            line=call.lineno,
            column=call.col_offset,
            function=scope.display_name,
            emitter=emitter,
            states=tuple(sorted(states)),
            uncertain=(
                self._call_has_unexpanded_arguments(call)
                or (
                    self._emitter_depends_on_parameters(scope, call)
                    and (
                        any(
                            self.context_uncertain[context_key]
                            for _, context_key, _ in context_items
                        )
                        or scope.descriptor == "unknown"
                    )
                )
            ),
            expression=ast.unparse(expression_node) if expression_node is not None else "<omitted>",
            forwarded_parameters=self._forwarded_parameters(scope, call),
        )

    def findings(self, *, readback_only: bool) -> tuple[EmitterFinding, ...]:
        cached = self._findings_cache.get(readback_only)
        if cached is not None:
            return cached
        self._propagate()
        findings: list[EmitterFinding] = []
        for scope in self.scopes.values():
            for emitter, call in scope.emitters:
                finding = self._finding(scope, emitter, call)
                if not readback_only or finding.is_readback:
                    findings.append(finding)
            for edge in self.edges:
                if edge.caller != scope.key or edge.target is not None:
                    continue
                if not isinstance(
                    edge.call.func, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)
                ):
                    continue
                if (
                    not self._unknown_call_candidate(scope, edge.call)
                    and not edge.unresolved_import
                    and not edge.unresolved_alias
                ):
                    continue
                finding = self._finding(
                    scope,
                    "<unknown-call>",
                    edge.call,
                    unknown_edge=True,
                    caller_override=self._coordinate(scope.key, edge.call),
                )
                if not readback_only or finding.is_readback:
                    findings.append(finding)
        result = tuple(sorted(findings))
        self._findings_cache[readback_only] = result
        return result


def _canonical_finding(finding: EmitterFinding) -> dict[str, object]:
    return {
        "path": finding.path,
        "line": finding.line,
        "column": finding.column,
        "function": finding.function,
        "emitter": finding.emitter,
        "uncertain": finding.uncertain,
        "expression": finding.expression,
        "forwarded_parameters": list(finding.forwarded_parameters),
        "states": [
            {
                "operation": state.operation,
                "mechanism": state.mechanism,
                "inherit_mechanism": state.inherit_mechanism,
                "status": state.status,
                "caller": {
                    "path": state.caller.path,
                    "line": state.caller.line,
                    "column": state.caller.column,
                    "function": state.caller.function,
                },
            }
            for state in finding.states
        ],
    }


def _coordinate_free_finding_payload(finding: EmitterFinding) -> str:
    """Serialize one finding with every line/column zeroed for move-proof hashing."""
    return json.dumps(
        _coordinate_free_finding(finding),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def inventory_digest(findings: Iterable[EmitterFinding]) -> str:
    """Return a stable SHA-256 over the complete canonical finding inventory.

    Identity is coordinate-free: findings hash by (path, function, emitter,
    expression, states) with lines/columns zeroed, and entries sort by
    serialized payload rather than source order. Inserting, deleting, or
    reordering unrelated code therefore leaves the digest untouched; only
    added/removed findings and status/content changes drift it. Coordinate
    moves remain visible in :func:`format_inventory_diff` for review.
    """
    payload = sorted(_coordinate_free_finding_payload(finding) for finding in findings)
    return hashlib.sha256("\n".join(payload).encode()).hexdigest()


def flatten_effective_states(
    findings: Iterable[EmitterFinding],
) -> tuple[FlattenedEffectiveState, ...]:
    """Flatten findings while retaining the emitter identity for every state."""
    return tuple(
        FlattenedEffectiveState(finding, state)
        for finding in sorted(findings)
        for state in finding.effective_states
    )


def direct_emitter_census(
    findings: Iterable[EmitterFinding],
) -> tuple[tuple[str, int], ...]:
    """Count source-level recognized emitters independently of state classification."""
    counts = Counter(finding.emitter for finding in findings if finding.emitter in _EMITTERS)
    return tuple(sorted(counts.items()))


def corpus_digest(sources: Mapping[str, str]) -> str:
    """Hash canonical source text and syntax trees, independently of findings."""
    payload = [
        {
            "path": path,
            "source": sources[path],
            "ast": ast.dump(
                ast.parse(sources[path], filename=path),
                annotate_fields=True,
                include_attributes=False,
            ),
        }
        for path in sorted(sources)
    ]
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def should_gate_readback(finding: EmitterFinding) -> bool:
    """Return whether a finding must block a reviewed readback gate."""
    return finding.gate_action == GATE_REJECT


def scan_sources(
    sources: Mapping[str, str],
    *,
    readback_only: bool = False,
) -> tuple[EmitterFinding, ...]:
    """Analyze several source files as one repository, including cross-file helper edges."""
    return _Analyzer(sources).findings(readback_only=readback_only)


def scan_source(
    source: str,
    *,
    path: str = "<source>.py",
    readback_only: bool = False,
) -> tuple[EmitterFinding, ...]:
    """Analyze one Python source string."""
    return scan_sources({path: source}, readback_only=readback_only)


_TREE_ANALYZER_CACHE: dict[str, _Analyzer] = {}


def _cached_tree_analyzer(root: Path) -> tuple[_Analyzer, str]:
    """Return the cached analyzer for the tree under *root* plus its corpus digest.

    Full-tree scans dominate the gate-file runtime while every tree-level entry
    point re-analyzes identical sources. Sources are still re-read and re-hashed
    on each call to key the cache; only the analysis is memoized. The analyzer
    is a pure function of the source mapping, so one entry per corpus digest is
    exact, never stale.
    """
    sources = _tree_sources(root)
    digest = corpus_digest(sources)
    analyzer = _TREE_ANALYZER_CACHE.get(digest)
    if analyzer is None:
        analyzer = _Analyzer(sources)
        _TREE_ANALYZER_CACHE[digest] = analyzer
    return analyzer, digest


def scan_tree(
    root: Path,
    *,
    readback_only: bool = False,
) -> tuple[EmitterFinding, ...]:
    """Analyze all Python files beneath *root* with root-relative POSIX identities."""
    analyzer, _ = _cached_tree_analyzer(root)
    return analyzer.findings(readback_only=readback_only)


@dataclass(frozen=True, slots=True)
class LabeledCallShape:
    """One static view of a ``func(...)`` call site, for replay coupling."""

    line: int
    args: tuple[object, ...]
    kwargs: dict[str, object]
    label_source: str


DYNAMIC_ARG: Final = "<dynamic>"


def labeled_call_shapes(source_path: Path, func_name: str) -> tuple[LabeledCallShape, ...]:
    """Every ``func_name(...)`` call in a file, with static arguments resolved.

    Constant positional/keyword values are returned as-is; anything dynamic
    (names, f-strings, calls, ``*``/``**`` unpacking) becomes ``<dynamic>``.
    A call with ``**`` unpacking additionally reports ``mechanism`` as
    ``<dynamic>`` unless statically present: an explicit mechanism could hide
    in the mapping. ``label_source`` is the source segment of the ``label=``
    keyword ("" when absent) so dynamically-built labels can still be matched
    by substring.

    This couples replay-style regression tests to the source call they
    characterize: the replay pins the call semantics, this pins the call's
    continued existence and shape at its source site.
    """
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    shapes: list[LabeledCallShape] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != func_name:
            continue
        args = tuple(
            arg.value if isinstance(arg, ast.Constant) else DYNAMIC_ARG for arg in node.args
        )
        kwargs: dict[str, object] = {}
        label_source = ""
        star_kwargs = False
        for keyword in node.keywords:
            if keyword.arg is None:
                star_kwargs = True
                continue
            kwargs[keyword.arg] = (
                keyword.value.value if isinstance(keyword.value, ast.Constant) else DYNAMIC_ARG
            )
            if keyword.arg == "label":
                label_source = ast.get_source_segment(source, keyword.value) or ""
        if star_kwargs and "mechanism" not in kwargs:
            kwargs["mechanism"] = DYNAMIC_ARG
        shapes.append(LabeledCallShape(node.lineno, args, kwargs, label_source))
    return tuple(shapes)


def characterize_tree(root: Path) -> InventoryCharacterization:
    """Return pinned totals/digests without asserting that the tree is clean."""
    analyzer, corpus = _cached_tree_analyzer(root)
    all_findings = analyzer.findings(readback_only=False)
    candidates = tuple(finding for finding in all_findings if finding.is_readback)
    statuses = tuple(sorted(Counter(finding.status for finding in all_findings).items()))
    state_statuses = tuple(
        sorted(Counter(state.status for state in flatten_effective_states(all_findings)).items())
    )
    mixed_unsafe_states = sum(
        1
        for finding in all_findings
        if finding.status == STATUS_UNRESOLVED
        for state in finding.states
        if state.status == STATUS_UNSAFE_INHERITED_READBACK
    )
    return InventoryCharacterization(
        total=len(all_findings),
        candidate_total=len(candidates),
        file_total=len({finding.path for finding in candidates}),
        statuses=statuses,
        state_statuses=state_statuses,
        mixed_unsafe_states=mixed_unsafe_states,
        digest=inventory_digest(all_findings),
        candidate_digest=inventory_digest(candidates),
        corpus_digest=corpus,
        direct_emitter_census=direct_emitter_census(all_findings),
    )


def git_head_tree_sources(tree_root: Path) -> dict[str, str]:
    """Read the HEAD-tree ``*.py`` sources for *tree_root* without touching the worktree.

    The mapping uses the same root-relative POSIX keys as :func:`scan_tree`, so
    HEAD findings diff cleanly against worktree findings. Raises
    :class:`subprocess.CalledProcessError` when git fails (not a checkout, no
    HEAD), :class:`RuntimeError` when the archive holds no Python sources,
    :class:`ValueError` when *tree_root* escapes the work tree, and
    :class:`UnicodeDecodeError`/:class:`tarfile.ReadError` on undecodable or
    corrupt archives.
    """
    toplevel = subprocess.run(
        ["git", "-C", str(tree_root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout.strip()
    prefix = tree_root.resolve().relative_to(Path(toplevel).resolve()).as_posix()
    archive = subprocess.run(
        ["git", "-C", toplevel, "archive", "HEAD", "--", prefix],
        capture_output=True,
        check=True,
    ).stdout
    sources: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith(".py"):
                continue
            name = member.name
            if prefix != ".":
                name = name.removeprefix(prefix + "/")
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            sources[name] = extracted.read().decode("utf-8")
    if not sources:
        raise RuntimeError(f"no HEAD sources found for {tree_root}")
    return sources


def _coordinate_free_finding(finding: EmitterFinding) -> dict[str, object]:
    """Return the canonical finding with every line/column zeroed for move diffing."""
    canonical = _canonical_finding(finding)
    canonical["line"] = 0
    canonical["column"] = 0
    states = canonical["states"]
    if isinstance(states, list):
        for state in states:
            if not isinstance(state, dict):
                continue
            caller = state.get("caller")
            if isinstance(caller, dict):
                caller["line"] = 0
                caller["column"] = 0
    return canonical


_DIFF_LIST_CAP = 50


def _capped(lines: list[str]) -> list[str]:
    if len(lines) <= _DIFF_LIST_CAP:
        return lines
    return [*lines[:_DIFF_LIST_CAP], f"  ... +{len(lines) - _DIFF_LIST_CAP} more"]


def _counter_delta_lines(header: str, old: Counter[str], new: Counter[str]) -> list[str]:
    """Render per-value ``old -> new`` lines for values whose count moved."""
    changed = sorted(value for value in set(old) | set(new) if old[value] != new[value])
    if not changed:
        return [f"{header}: unchanged"]
    lines = [f"{header}:"]
    for value in changed:
        delta = new[value] - old[value]
        lines.append(f"  {value}: {old[value]} -> {new[value]} ({delta:+d})")
    return lines


def _change_detail(former: EmitterFinding, latter: EmitterFinding) -> str:
    """Describe what differs between two paired findings, omitting equal fields."""
    parts: list[str] = []
    if former.status != latter.status:
        parts.append(f"status {former.status} -> {latter.status}")
    if former.operations != latter.operations:
        parts.append(f"ops {former.operations} -> {latter.operations}")
    if former.mechanisms != latter.mechanisms:
        parts.append(f"mechs {former.mechanisms} -> {latter.mechanisms}")
    return "; ".join(parts) if parts else "content changed"


def format_inventory_diff(
    old: Iterable[EmitterFinding],
    new: Iterable[EmitterFinding],
) -> str:
    """Render what moved between two finding inventories.

    Sections cover paths, emitter and status censuses, coordinate-only
    moves, status/content changes, and added/removed findings. Within each
    (path, function, emitter) group, findings pair content-first: identical
    findings cancel, then coordinate-free matches pair as moves (a match at
    the same coordinates means only its callers moved). A lone leftover on
    each side is one edit; any other leftovers are added/removed — so a
    mid-group insert/delete never fabricates a change or misattributes the
    removal to a surviving finding.
    """
    before = tuple(sorted(old))
    after = tuple(sorted(new))
    lines = [f"inventory drift: HEAD {len(before)} findings -> worktree {len(after)} findings"]
    old_paths = {finding.path for finding in before}
    new_paths = {finding.path for finding in after}
    added_paths = sorted(new_paths - old_paths)
    removed_paths = sorted(old_paths - new_paths)
    if added_paths or removed_paths:
        lines.append(f"paths: +{len(added_paths)} -{len(removed_paths)}")
        path_lines = [f"  + {path}" for path in added_paths]
        path_lines.extend(f"  - {path}" for path in removed_paths)
        lines.extend(_capped(path_lines))
    else:
        lines.append("paths: unchanged")
    lines.extend(
        _counter_delta_lines(
            "emitters",
            Counter(finding.emitter for finding in before),
            Counter(finding.emitter for finding in after),
        )
    )
    lines.extend(
        _counter_delta_lines(
            "statuses",
            Counter(finding.status for finding in before),
            Counter(finding.status for finding in after),
        )
    )

    def _group(
        findings: tuple[EmitterFinding, ...],
    ) -> dict[tuple[str, str, str], list[EmitterFinding]]:
        grouped: dict[tuple[str, str, str], list[EmitterFinding]] = defaultdict(list)
        for finding in findings:
            grouped[(finding.path, finding.function, finding.emitter)].append(finding)
        for group in grouped.values():
            group.sort(key=lambda finding: (finding.line, finding.column))
        return grouped

    old_groups = _group(before)
    new_groups = _group(after)
    moves: list[str] = []
    changes: list[str] = []
    added: list[str] = []
    removed: list[str] = []
    for key in sorted(set(old_groups) | set(new_groups)):
        unmatched_new = list(new_groups.get(key, []))
        still_old: list[EmitterFinding] = []
        for former in old_groups.get(key, []):
            try:
                unmatched_new.remove(former)
            except ValueError:
                still_old.append(former)
        candidates = [(_coordinate_free_finding(latter), latter) for latter in unmatched_new]
        leftovers_old: list[EmitterFinding] = []
        for former in still_old:
            shape = _coordinate_free_finding(former)
            hit = next(
                (entry for entry in candidates if entry[0] == shape),
                None,
            )
            if hit is None:
                leftovers_old.append(former)
                continue
            candidates.remove(hit)
            latter = hit[1]
            if (former.line, former.column) != (latter.line, latter.column):
                moves.append(
                    f"  {former.path} {former.function} {former.emitter}: "
                    f"({former.line},{former.column}) -> ({latter.line},{latter.column})"
                )
            else:
                moves.append(
                    f"  {former.path}:{former.line} {former.function} {former.emitter}: "
                    "callers moved"
                )
        leftovers_new = [latter for _, latter in candidates]
        if len(leftovers_old) == 1 and len(leftovers_new) == 1:
            former, latter = leftovers_old[0], leftovers_new[0]
            changes.append(
                f"  {former.path}:{former.line} {former.function} {former.emitter}: "
                f"{_change_detail(former, latter)}"
            )
        else:
            for entries, bucket in ((leftovers_old, removed), (leftovers_new, added)):
                for entry in entries:
                    bucket.append(
                        f"  {entry.path}:{entry.line} {entry.function} "
                        f"{entry.emitter} [{entry.status}]"
                    )
    lines.append(f"coordinate-only moves ({len(moves)}):")
    lines.extend(_capped(moves))
    lines.append(f"status/content changes ({len(changes)}):")
    lines.extend(_capped(changes))
    lines.append(f"added ({len(added)}):")
    lines.extend(_capped(added))
    lines.append(f"removed ({len(removed)}):")
    lines.extend(_capped(removed))
    return "\n".join(lines)


def head_inventory_diff(tree_root: Path, current: Iterable[EmitterFinding]) -> str:
    """Diff *current* findings against the git HEAD tree; never raises Exception.

    Diagnostics must not mask the gate failure they explain, so every failure
    (not a checkout, no HEAD, unreadable archive, unformattable input)
    degrades to a placeholder.
    """
    try:
        head_findings = scan_sources(git_head_tree_sources(tree_root))
        after = tuple(sorted(current))
        if head_findings == after:
            return (
                f"inventory drift: HEAD {len(head_findings)} findings "
                f"-> worktree {len(after)} findings "
                "(identical findings; drift is in corpus text or the pinned constants)"
            )
        return format_inventory_diff(head_findings, after)
    except Exception as exc:
        return f"<inventory diff unavailable: {exc}>"
