"""Static guard that isolated product probes preserve the selected interface."""

from __future__ import annotations

import ast
from pathlib import Path

_TESTCASE_ROOT = Path(__file__).parents[1] / "src/pkcs11_check/testcases"
_RUNNER_MODULE = "pkcs11_check.testcases._probes.runner"
_RUNNER_PACKAGE = "pkcs11_check.testcases._probes"
# These children intentionally bypass the selected RawPKCS11 function table and call
# exported symbols/function-list pointers directly.  Their callers remain visible here so a
# newly added generic target cannot accidentally lose exact-interface transport.
_RAW_EXCEPTIONS = frozenset(
    {"ckr_general", "ckr_null_params", "initialize_args", "mutex_callback_safety"}
)
_REVIEWED_WRAPPER_PARAMETERS = {
    Path("ckr/test_ckr_destructive.py"): {("_run_destructive", "interface")},
}


def _child_entrypoints(target: str) -> tuple[bool, bool]:
    """Return whether a literal target has generic and raw child entrypoints."""
    child = _TESTCASE_ROOT / "_probes" / f"{target}.py"
    assert child.is_file(), f"run_probe target {target!r} has no child module {child}"
    tree = ast.parse(child.read_text(encoding="utf-8"))
    generic = False
    raw = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        generic |= node.func.id == "probe_main"
        raw |= node.func.id == "probe_main_raw"
    return generic, raw


def _relative_import_module(path: Path, node: ast.ImportFrom) -> str:
    """Resolve a relative import from a testcase path for import-aware scanning."""
    if node.level == 0:
        return node.module or ""
    package = ("pkcs11_check", "testcases", *path.relative_to(_TESTCASE_ROOT).parent.parts)
    if node.level > len(package) + 1:
        return ""
    base = package[: len(package) - node.level + 1]
    suffix = () if node.module is None else tuple(node.module.split("."))
    return ".".join((*base, *suffix))


def _attribute_chain(node: ast.AST) -> tuple[str, ...] | None:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        parent = _attribute_chain(node.value)
        return None if parent is None else (*parent, node.attr)
    return None


def _runner_imports(tree: ast.AST, path: Path) -> tuple[set[str], set[tuple[str, ...]]]:
    direct_names: set[str] = set()
    module_names: set[tuple[str, ...]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name != _RUNNER_MODULE:
                    continue
                bound = alias.asname
                module_names.add(tuple(bound.split(".")) if bound else tuple(alias.name.split(".")))
        elif isinstance(node, ast.ImportFrom):
            module = _relative_import_module(path, node)
            if module == _RUNNER_MODULE:
                for alias in node.names:
                    if alias.name == "run_probe":
                        direct_names.add(alias.asname or alias.name)
            elif module == _RUNNER_PACKAGE:
                for alias in node.names:
                    if alias.name == "runner":
                        module_names.add((alias.asname or alias.name,))
    return direct_names, module_names


def _runner_calls_from_source(path: Path, source: str) -> tuple[list[ast.Call], list[str]]:
    tree = ast.parse(source, filename=str(path))
    direct_names, module_names = _runner_imports(tree, path)
    calls: list[ast.Call] = []
    unresolved: list[str] = []
    allowed_binding_nodes: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            if node.func.id in direct_names:
                calls.append(node)
                allowed_binding_nodes.update(id(child) for child in ast.walk(node.func))
            elif node.func.id == "run_probe":
                unresolved.append(f"{path}:{node.lineno}: unresolvable run_probe binding")
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "run_probe":
            continue
        chain = _attribute_chain(node.func.value)
        if chain in module_names:
            calls.append(node)
            allowed_binding_nodes.update(id(child) for child in ast.walk(node.func))
        else:
            unresolved.append(f"{path}:{node.lineno}: unresolvable module-qualified run_probe")

    module_roots = {name[0] for name in module_names if name}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Name):
            continue
        if node.id not in direct_names | module_roots:
            continue
        if isinstance(node.ctx, ast.Load) and id(node) in allowed_binding_nodes:
            continue
        reason = "escaped" if isinstance(node.ctx, ast.Load) else "reassigned"
        unresolved.append(f"{path}:{node.lineno}: canonical runner binding {reason}")
    return calls, unresolved


def _run_probe_calls(path: Path) -> tuple[list[ast.Call], list[str]]:
    return _runner_calls_from_source(path, path.read_text(encoding="utf-8"))


def _is_config_interface_expression(node: ast.AST) -> bool:
    """Accept only direct, statically visible p11_config interface transport."""
    if isinstance(node, ast.Attribute):
        return (
            isinstance(node.value, ast.Name)
            and node.value.id == "p11_config"
            and node.attr == "interface"
        )
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    if node.func.id != "getattr" or node.keywords or len(node.args) != 3:
        return False
    receiver, field, default = node.args
    return (
        isinstance(receiver, ast.Name)
        and receiver.id == "p11_config"
        and isinstance(field, ast.Constant)
        and field.value == "interface"
        and isinstance(default, ast.Constant)
        and default.value == "auto"
    )


def _enclosing_function(tree: ast.AST, call: ast.Call) -> ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and any(
            isinstance(child, ast.Call)
            and child.lineno == call.lineno
            and child.col_offset == call.col_offset
            for child in ast.walk(node)
        ):
            return node
    return None


def _is_reviewed_wrapper_transport(path: Path, tree: ast.AST, call: ast.Call) -> bool:
    relative = path.relative_to(_TESTCASE_ROOT)
    function = _enclosing_function(tree, call)
    if function is None:
        return False
    parameter_names = {
        argument.arg
        for argument in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    }
    for function_name, parameter_name in _REVIEWED_WRAPPER_PARAMETERS.get(relative, set()):
        if function.name != function_name or parameter_name not in parameter_names:
            continue
        interface_parameter = next(
            (keyword.value for keyword in call.keywords if keyword.arg == "interface"), None
        )
        if (
            not isinstance(interface_parameter, ast.Name)
            or interface_parameter.id != parameter_name
        ):
            return False
        callers = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == function_name
        ]
        return bool(callers) and all(
            any(
                keyword.arg == parameter_name and _is_config_interface_expression(keyword.value)
                for keyword in caller.keywords
            )
            for caller in callers
        )
    return False


def _all_run_probe_calls() -> tuple[list[tuple[Path, ast.Call]], list[str]]:
    """Discover every launcher call in the complete testcase source tree."""
    launches: list[tuple[Path, ast.Call]] = []
    unresolved: list[str] = []
    for path in sorted(_TESTCASE_ROOT.rglob("*.py")):
        calls, errors = _run_probe_calls(path)
        launches.extend((path, call) for call in calls)
        unresolved.extend(errors)
    return launches, unresolved


def test_every_probe_launcher_transports_explicit_interface() -> None:
    launches, unresolved = _all_run_probe_calls()
    missing: list[str] = []
    invalid_transport: list[str] = []
    discovered_targets: set[str] = set()
    discovered_files: set[Path] = set()
    for path, call in launches:
        relative = path.relative_to(_TESTCASE_ROOT)
        discovered_files.add(relative)
        if not call.args or not isinstance(call.args[0], ast.Constant):
            unresolved.append(f"{relative}:{call.lineno}: non-literal run_probe target")
            continue
        target = call.args[0].value
        if not isinstance(target, str):
            unresolved.append(f"{relative}:{call.lineno}: non-string run_probe target")
            continue
        discovered_targets.add(target)
        child = _TESTCASE_ROOT / "_probes" / f"{target}.py"
        if not child.is_file():
            unresolved.append(f"{relative}:{call.lineno}: missing child {child}")
            continue
        generic, raw = _child_entrypoints(target)
        if target in _RAW_EXCEPTIONS:
            if not raw or generic:
                unresolved.append(
                    f"{relative}:{call.lineno}: raw exception {target!r} is not raw-only"
                )
            continue
        if not generic and not raw:
            unresolved.append(
                f"{relative}:{call.lineno}: {target!r} has no probe_main/probe_main_raw"
            )
            continue
        interface_keywords = [keyword for keyword in call.keywords if keyword.arg == "interface"]
        if not interface_keywords:
            missing.append(f"{relative}:{call.lineno}: {target}")
        elif not _is_config_interface_expression(interface_keywords[0].value) and not (
            _is_reviewed_wrapper_transport(path, ast.parse(path.read_text(encoding="utf-8")), call)
        ):
            invalid_transport.append(f"{relative}:{call.lineno}: {target}")

    assert launches, "dynamic testcase discovery found no run_probe launchers"
    assert _RAW_EXCEPTIONS <= discovered_targets, (
        "intentional raw launcher exception is not covered: "
        + ", ".join(sorted(_RAW_EXCEPTIONS - discovered_targets))
    )
    assert {
        Path("ckr/test_ckr_general.py"),
        Path("ckr/test_ckr_null_params.py"),
        Path("test_initialize_args.py"),
        Path("test_mutex_callback_safety.py"),
    } <= discovered_files
    assert not unresolved, "unresolved probe targets require an explicit review: " + "; ".join(
        unresolved
    )
    assert not missing, (
        "generic probe launchers must pass interface=p11_config.interface: " + "; ".join(missing)
    )
    assert not invalid_transport, (
        "generic probe launchers must transport the configured interface expression: "
        + "; ".join(invalid_transport)
    )


def test_import_aware_discovery_supports_alias_and_module_qualified_calls() -> None:
    path = _TESTCASE_ROOT / "synthetic_imports.py"
    source = """
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._probes.runner import run_probe as launch
import pkcs11_check.testcases._probes.runner as runner

run_probe("direct", {"module_path": "x"}, interface=p11_config.interface)
launch("aliased", {"module_path": "x"}, interface=p11_config.interface)
runner.run_probe("qualified", {"module_path": "x"}, interface=p11_config.interface)
"""

    calls, unresolved = _runner_calls_from_source(path, source)

    assert len(calls) == 3
    assert not unresolved


def test_import_aware_discovery_rejects_unresolvable_indirection() -> None:
    path = _TESTCASE_ROOT / "synthetic_unresolved.py"
    source = """
from somewhere_else import run_probe

run_probe("unknown", {"module_path": "x"}, interface=None)
"""

    calls, unresolved = _runner_calls_from_source(path, source)

    assert not calls
    assert unresolved


def test_import_aware_discovery_rejects_direct_binding_assignment() -> None:
    path = _TESTCASE_ROOT / "synthetic_assignment.py"
    source = """
from pkcs11_check.testcases._probes.runner import run_probe

launch = run_probe
launch("hidden", {"module_path": "x"}, interface=p11_config.interface)
"""

    calls, unresolved = _runner_calls_from_source(path, source)

    assert not calls
    assert any("escaped" in error for error in unresolved)


def test_import_aware_discovery_rejects_module_binding_assignment_and_escape() -> None:
    path = _TESTCASE_ROOT / "synthetic_module_assignment.py"
    source = """
import pkcs11_check.testcases._probes.runner as runner

launch = runner.run_probe
launch("hidden", {"module_path": "x"}, interface=p11_config.interface)

def expose():
    return runner.run_probe

def pass_to(callback):
    return callback

pass_to(runner.run_probe)
"""

    calls, unresolved = _runner_calls_from_source(path, source)

    assert not calls
    assert len([error for error in unresolved if "escaped" in error]) >= 3
