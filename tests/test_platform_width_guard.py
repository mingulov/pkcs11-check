"""Guard: sentinel-distinctness test premises must be width-gated (S1 + S2).

Two spellings of ``CK_UNAVAILABLE_INFORMATION`` circulate deliberately: the
platform sentinel ``(CK_ULONG)-1`` and the 32-bit spelling ``0xFFFFFFFF``
some modules return even on 64-bit hosts. On LP64 they are distinct integers;
on Win64 LLP64 (4-byte ``CK_ULONG``) they are the same value. A test whose
verdict depends on telling them apart -- "the 32-bit spelling must still
fail" -- silently inverts on LLP64 (CI run 40196463065, fixed by gating in
``4f6238ed``), while every Linux run stays green.

S1 flags a test function with such a distinctness premise unless it is
width-gated, accept-both, or ``# audit-ok:``-annotated. Two premise shapes
are recognised: (a) the function compares against BOTH spellings directly,
and (b) the function drives a 32-bit-spelled sentinel stimulus (a name bound
to the 32-bit spelling, or a fake behaviour tag whose dispatch branch in
this file returns that spelling) and expects a terminal failure -- i.e. it
pins that the 32-bit spelling is NOT accepted as the sentinel.

S2 flags local sentinel recomputes (``c_ulong(-1)`` / ``CK_ULONG(-1)`` /
``(1 << (sizeof(c_ulong) * 8)) - 1``) outside the generated seam, so the
sentinel has exactly one patchable source (see ``tests/_llp64_sim_plugin.py``).
Pinned stimulus-max sites (oversize lengths, not sentinels) are allowlisted
by (file, bound name) and stale-checked.

S4 pins the exact census of module-level bindings whose value folds to one
of the two width literals (``0xFFFFFFFF`` / ``0xFFFFFFFFFFFFFFFF``) in
``src/`` + ``tests/`` -- literals, ``(1 << 32) - 1``-style constant
expressions, ``int()``/``CK_CONSTANT()`` wraps and same-file aliases alike.
Bindings routed through the seam (``int(CK_UNAVAILABLE_INFORMATION)``) do
not fold to a literal and need no entry. The census makes S1's input
population exhaustive: a new width-literal binding fails here until it is
routed through the seam or added as a deliberate census entry.

Known bounded miss (E11, Slice-2 review): a bare
``assert predicate(computed_spelling)`` has no comparison against a
spelling for S1 to key on, and a helper-computed spelling does not fold
in ``_spell_names``. The only ``_is_unavailable_length`` consumer in
``tests/`` today is ``tests/test_sentinel_width_invariant.py`` -- the
runtime oracle for that predicate, host-width-relative since the I1
fix and run on real LLP64 by the windows-contracts job. Covering this
shape needs computed-spelling folding plus a rule for which calls are
acceptance predicates; that is declared here and pinned as a miss
below, not silently treated as a spare.

These are value-level static checks only; neither proves anything about the
real LLP64 ABI (struct layouts, field truncation, DLL calls stay CI-only).
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_S32 = 0xFFFFFFFF
_SPLAT = 0xFFFFFFFFFFFFFFFF
_PLAT_NAME = "CK_UNAVAILABLE_INFORMATION"
_S32_NAME = "CK_UNAVAILABLE_INFORMATION_32"
_WIDTH_TOKENS = frozenset({_PLAT_NAME, "CK_ULONG", "c_ulong", "sizeof", "requires_64bit_ck_ulong"})
_S1_TREES = (_ROOT / "tests", _ROOT / "src" / "pkcs11_check" / "testcases")
_S2_TREES = (_ROOT / "src", _ROOT / "tests", _ROOT / "scripts")

# Files that ARE the seam or the independent oracle re-deriving it.
_S2_EXEMPT_FILES = frozenset(
    {
        "src/pkcs11_check/raw/types_std.py",  # generated sentinel definition
        "scripts/generate_raw_standard.py",  # the generator emitting it
        "tests/test_raw_constants.py",  # independent oracle: must recompute
    }
)

# (file, bound name) stimulus-max sites: a width-relative *max* used as an
# oversize argument, not the unavailable sentinel. Stale-checked below.
_MAX = "stimulus max, not sentinel"
_RV_MAX = "CK_RV range max, not sentinel"
_FAKE_LEN = "fake writes the host sentinel into ulValueLen"
_S2_ALLOWLIST: dict[tuple[str, str], str] = {
    ("src/pkcs11_check/testcases/_probes/aes_keywrap_pad.py", "_OVERSIZED_DATALEN"): _MAX,
    ("src/pkcs11_check/testcases/_probes/api_boundary.py", "_CK_ULONG_MAX"): _MAX,
    ("src/pkcs11_check/testcases/_probes/arithmetic_overflow.py", "_CK_ULONG_MAX"): _MAX,
    (
        "src/pkcs11_check/testcases/security/test_aes_keywrap_pad_overflow.py",
        "_OVERSIZED_DATALEN",
    ): _MAX,
    ("src/pkcs11_check/testcases/security/test_api_boundary.py", "_CK_ULONG_MAX"): _MAX,
    ("src/pkcs11_check/testcases/security/test_operation_state_uaf.py", "_UAF_RV_MAX"): _RV_MAX,
    ("tests/test_windows_abi_bigvalues.py", "expected"): "oracle for the stimulus-max sites",
    ("tests/test_signature_width_contract.py", "ulValueLen"): _FAKE_LEN,
    ("tests/test_x942_dh_runtime_classification.py", "ulValueLen"): _FAKE_LEN,
    ("src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py", "_CKR_MAX"): _RV_MAX,
    ("src/pkcs11_check/testcases/security/test_error_path_rsa.py", "_NATIVE_CKR_MAX"): _RV_MAX,
    ("tests/test_ckr_raw_attrs_permission_classification.py", "native_max"): _RV_MAX,
    ("tests/test_field_size_child_runtime.py", "_CK_ULONG_MASK"): "field-width mask, not sentinel",
}


def _value_names(node: ast.AST) -> set[str]:
    names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
    return names


def _value_ints(node: ast.AST) -> set[int]:
    return {
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, int)
    }


def _simple_value(node: ast.expr) -> bool:
    """A plain constant/name/int() binding value (not a mark/skipif call)."""
    if isinstance(node, (ast.Constant, ast.Name, ast.Attribute, ast.BinOp)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"int", "CK_CONSTANT"}
    )


def _bound_names(node: ast.stmt) -> tuple[set[str], ast.expr | None]:
    if isinstance(node, ast.Assign):
        return {t.id for t in node.targets if isinstance(t, ast.Name)}, node.value
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return {node.target.id}, node.value
    return set(), None


def _spell_names(stmts: list[ast.stmt]) -> tuple[set[str], set[str]]:
    """Fixpoint: names bound to the 32-bit / platform sentinel spellings."""
    s32: set[str] = {_S32_NAME}
    splat: set[str] = {_PLAT_NAME}
    for _ in range(4):
        for node in stmts:
            names, value = _bound_names(node)
            if not names or value is None or not _simple_value(value):
                continue
            ints, refs = _value_ints(value), _value_names(value)
            if _S32 in ints or refs & s32:
                s32 |= names
            if _SPLAT in ints or refs & splat:
                splat |= names
    return s32, splat


def _spell_refs(node: ast.AST, s32: set[str], splat: set[str]) -> tuple[bool, bool]:
    """Whether ``node`` references the 32-bit / platform spellings."""
    ints, refs = _value_ints(node), _value_names(node)
    return (_S32 in ints or bool(refs & s32)), (_SPLAT in ints or bool(refs & splat))


def _tag_spells(tree: ast.Module, s32: set[str], splat: set[str]) -> dict[str, str]:
    """Fake behaviour tags whose ``tag == "..."`` branch returns one spelling."""
    tags: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        strings = [
            n.value
            for n in ast.walk(node.test)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        ]
        if len(strings) != 1:
            continue
        body = ast.Module(body=node.body, type_ignores=[])
        has32, hasplat = _spell_refs(body, s32, splat)
        if has32 and not hasplat:
            tags[strings[0]] = "32"
        elif hasplat and not has32:
            tags[strings[0]] = "plat"
    return tags


def _is_skip_shaped(node: ast.expr) -> bool:
    """A ``skipif``/``xfail`` mark (called or bare), not just any decorator."""
    func = node.func if isinstance(node, ast.Call) else node
    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
    return name in {"skipif", "xfail"}


def _gate_names(tree: ast.Module) -> set[str]:
    """Module names bound to a width gate.

    The binding value must be a skip-shaped mark mentioning a width token
    (or the gate itself). A name bound to e.g. ``parametrize`` over sentinel
    values is a stimulus table, not a gate, and must not exempt anything.
    """
    gates = {"requires_64bit_ck_ulong"}
    for node in tree.body:
        names, value = _bound_names(node)
        if not names or value is None or not (_value_names(value) & _WIDTH_TOKENS):
            continue
        if _is_skip_shaped(value) or "requires_64bit_ck_ulong" in _value_names(value):
            gates |= names
    return gates


def _decorated_gated(decorators: list[ast.expr], gates: set[str]) -> bool:
    for dec in decorators:
        names = _value_names(dec)
        if names & gates:
            return True
        if _is_skip_shaped(dec) and names & _WIDTH_TOKENS:
            return True
    return False


def _module_gated(tree: ast.Module, gates: set[str]) -> bool:
    for node in tree.body:
        names, value = _bound_names(node)
        if "pytestmark" in names and value is not None and _value_names(value) & gates:
            return True
    return False


def _body_refs(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Module:
    """Function body without decorators (the gate itself references both)."""
    return ast.Module(body=list(fn.body), type_ignores=[])


def _or_covers_both(node: ast.BoolOp, s32: set[str], splat: set[str]) -> bool:
    has32 = hasplat = False
    for value in node.values:
        v32, vplat = _spell_refs(value, s32, splat)
        has32, hasplat = has32 or v32, hasplat or vplat
    return has32 and hasplat


def _distinguishing_comparisons(body: ast.AST, s32: set[str], splat: set[str]) -> tuple[bool, bool]:
    """Spellings compared *outside* an accept-both context, per comparison.

    A comparison is accept-both when both spellings appear in it (the
    ``x in (S32, SPLAT)`` membership) or when it sits inside an ``or`` whose
    operands together cover both spellings (``x == S32 or x == SPLAT``).
    An accept-both assertion elsewhere in the body does not exempt a
    distinguishing comparison elsewhere: the exemption is scoped to the
    comparison it contains.
    """
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(body):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    def accept_both(node: ast.Compare, has32: bool, hasplat: bool) -> bool:
        if has32 and hasplat:
            return True
        cur: ast.AST | None = node
        while cur is not None:
            cur = parents.get(id(cur))
            if isinstance(cur, ast.BoolOp) and isinstance(cur.op, ast.Or):
                return _or_covers_both(cur, s32, splat)
            if isinstance(cur, ast.stmt):
                return False
        return False

    out32 = outplat = False
    for node in ast.walk(body):
        if not isinstance(node, ast.Compare):
            continue
        has32, hasplat = _spell_refs(node, s32, splat)
        if accept_both(node, has32, hasplat):
            continue
        out32, outplat = out32 or has32, outplat or hasplat
    return out32, outplat


def _expects_failure(body: ast.AST) -> bool:
    """A terminal-failure expectation: pytest.raises or a *fails* helper."""
    for node in ast.walk(body):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if (
            name == "raises"
            or "assert_fails" in name
            or name in {"assert_xfails", "_assert_fails_non_xfail"}
        ):
            return True
    return False


def _width_branched(body: ast.AST) -> bool:
    """The body branches on sizeof(c_ulong) (the width split is explicit).

    A bare mention (``w = sizeof(c_ulong)``) is not a branch and exempts
    nothing; the sizeof call must appear in an ``if``/conditional test.
    """
    for node in ast.walk(body):
        test = node.test if isinstance(node, (ast.If, ast.IfExp)) else None
        if test is not None and any(_is_sizeof_ulong(n) for n in ast.walk(test)):
            return True
    return False


def s1_offenders_in_source(source: str, label: str) -> list[str]:
    """Ungated sentinel-distinctness premises in one source text."""
    lines = source.splitlines()
    tree = ast.parse(source, filename=label)
    mod32, modplat = _spell_names(tree.body)
    tags = _tag_spells(tree, mod32, modplat)
    gates = _gate_names(tree)
    if _module_gated(tree, gates):
        return []
    assigned_plat = modplat - {_PLAT_NAME}
    offenders: list[str] = []

    def check(fn: ast.FunctionDef | ast.AsyncFunctionDef, cls_gated: bool, cls: str) -> None:
        if not fn.name.startswith("test_"):
            return
        span = lines[fn.lineno - 1 : fn.end_lineno or fn.lineno]
        if any("# audit-ok:" in line for line in span):
            return
        if cls_gated or _decorated_gated(fn.decorator_list, gates):
            return
        body = _body_refs(fn)
        if _width_branched(body):
            return
        local32, localplat = _spell_names(list(fn.body))
        s32, splat = mod32 | local32, modplat | localplat
        cmp32, cmpplat = _distinguishing_comparisons(body, s32, splat)
        direct = cmp32 and cmpplat
        # Stimulus shape: a 32-bit sentinel name/tag driven at a probe that
        # must still fail. Bare 0xFFFFFFFF literals alone do not count --
        # they are also ordinary CK_ULONG-max stimuli.
        body_names = _value_names(body)
        strings = {
            n.value
            for n in ast.walk(body)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        }
        drives32 = bool(body_names & s32) or any(tags.get(s) == "32" for s in strings)
        _, bodyplat = _spell_refs(body, s32, splat)
        stimulus = drives32 and _expects_failure(body) and (bodyplat or bool(assigned_plat))
        if direct or stimulus:
            where = f"{cls}::{fn.name}" if cls else fn.name
            offenders.append(f"{label}::{where}")

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            cg = _decorated_gated(node.decorator_list, gates)
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    check(item, cg, node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            check(node, False, "")
    return offenders


def _is_minus_one(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and node.operand.value == 1
    ) or (isinstance(node, ast.Constant) and node.value == -1)


def _is_sizeof_ulong(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and _value_names(node) >= {"sizeof"}
        and bool(_value_names(node) & {"c_ulong", "CK_ULONG"})
    )


def _is_recompute(node: ast.AST) -> bool:
    """A local ``c_ulong(-1)`` / ``(1 << (sizeof(c_ulong)*8)) - 1`` shape."""
    if isinstance(node, ast.Call) and node.args and _is_minus_one(node.args[0]):
        names = _value_names(node.func)
        if names & {"c_ulong", "CK_ULONG"}:
            return True
    if (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Sub)
        and isinstance(node.right, ast.Constant)
        and node.right.value == 1
        and any(_is_sizeof_ulong(n) for n in ast.walk(node.left))
    ):
        return True
    return False


def s2_sites_in_source(source: str, label: str) -> list[tuple[str, str, int]]:
    """``(label, bound name, lineno)`` for every local sentinel recompute."""
    tree = ast.parse(source, filename=label)
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    def bound_name(node: ast.AST) -> str:
        cur: ast.AST | None = node
        while cur is not None:
            if isinstance(cur, ast.Assign):
                for target in cur.targets:
                    if isinstance(target, ast.Name):
                        return target.id
                    if isinstance(target, ast.Attribute):
                        return target.attr
                    if isinstance(target, ast.Subscript) and isinstance(
                        target.value, ast.Attribute
                    ):
                        return target.value.attr
                return "<expr>"
            if isinstance(cur, ast.AnnAssign):
                if isinstance(cur.target, ast.Name):
                    return cur.target.id
                if isinstance(cur.target, ast.Attribute):
                    return cur.target.attr
                return "<expr>"
            cur = parents.get(id(cur))
        return "<expr>"

    sites: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if _is_recompute(node):
            sites.append((label, bound_name(node), getattr(node, "lineno", 0)))
    return sorted(set(sites))


def _fold_int(node: ast.AST, known: dict[str, int]) -> int | None:
    """Constant-fold a small int expression; ``None`` when not provable.

    Handles the width-literal spellings in the tree: plain literals,
    ``(1 << 32) - 1`` / ``2**64 - 1`` arithmetic, ``int()`` /
    ``CK_CONSTANT()`` wraps, and names already folded in this module.
    Anything derived from ``sizeof`` or a seam import (the width-relative
    recomputes S2 owns, and ``int(CK_UNAVAILABLE_INFORMATION)``) does not
    fold, by design.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.Name):
        return known.get(node.id)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _fold_int(node.operand, known)
        return None if value is None else -value
    if (
        isinstance(node, ast.Call)
        and node.args
        and _value_names(node.func) & {"int", "CK_CONSTANT"}
    ):
        return _fold_int(node.args[0], known)
    if isinstance(node, ast.BinOp):
        left, right = _fold_int(node.left, known), _fold_int(node.right, known)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.LShift) and 0 <= right <= 128:
            return left << right
        if isinstance(node.op, ast.RShift) and 0 <= right <= 128:
            return left >> right
        if isinstance(node.op, ast.Pow) and 0 <= right <= 128:
            return int(left**right)
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitAnd):
            return left & right
    return None


def s4_bindings_in_source(source: str) -> dict[str, int]:
    """Module-level bindings folding to a width literal: name -> value.

    The folding environment keeps every safely foldable integer
    intermediate (P7) -- a computed sentinel such as
    ``_SENT = (1 << _BITS) - 1`` only folds when ``_BITS`` itself folds,
    even though 64 is no sentinel. Only the reported bindings are
    filtered to the two sentinel values.
    """
    tree = ast.parse(source)
    bindings: list[tuple[str, ast.expr]] = []
    for node in tree.body:
        names, value = _bound_names(node)
        if value is not None:
            bindings.extend((name, value) for name in sorted(names))
    env: dict[str, int] = {}
    changed = True
    while changed:  # fixpoint so alias chains of any length resolve
        changed = False
        for name, value in bindings:
            folded = _fold_int(value, env)
            if name not in env and folded is not None:
                env[name] = folded
                changed = True
    return {name: value for name, value in env.items() if value in (_S32, _SPLAT)}


def s4_census() -> list[tuple[str, str]]:
    """Sorted (file, name) width-literal bindings across ``src/`` + ``tests/``."""
    out: list[tuple[str, str]] = []
    for tree in (_ROOT / "src", _ROOT / "tests"):
        for path in sorted(tree.rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            bindings = s4_bindings_in_source(path.read_text(encoding="utf-8"))
            out.extend((rel, name) for name in bindings)
    return sorted(out)


# S4 ratchet pin: every module-level width-literal binding in src/ + tests/.
# Adding an entry is a deliberate, reviewable act -- prefer routing through
# CK_UNAVAILABLE_INFORMATION / CK_UNAVAILABLE_INFORMATION_32 instead.
_S4_CENSUS: tuple[tuple[str, str], ...] = (
    # the generated 32-bit seam definition itself
    ("src/pkcs11_check/raw/types_std.py", "CK_UNAVAILABLE_INFORMATION_32"),
    # 32-bit-max / oversized-length stimuli (fixed 32-bit values by design)
    ("src/pkcs11_check/testcases/_probes/arithmetic_overflow.py", "_ULONG_32BIT_MAX"),
    ("src/pkcs11_check/testcases/security/test_arithmetic_overflow.py", "_ULONG_32BIT_MAX"),
    (
        "src/pkcs11_check/testcases/security/test_scalar_attr_length_extended.py",
        "_WILD_OVERSIZED_LENGTH",
    ),
    # the sim's collapsed value, contract-fake unavailable spellings, and
    # the detectors' own spelling constants
    ("tests/_llp64_sim_plugin.py", "COLLAPSED_SENTINEL"),
    ("tests/test_byte_kdf_protection_contract.py", "_U64"),
    ("tests/test_copy_attribute_contract.py", "_U64"),
    ("tests/test_llp64_sim_census.py", "_S32"),
    ("tests/test_llp64_sim_census.py", "_SPLAT"),
    ("tests/test_logout_object_lifetime_contract.py", "_UNAVAILABLE"),
    ("tests/test_object_policy_effect_contract.py", "_U64"),
    ("tests/test_platform_width_guard.py", "_S32"),
    ("tests/test_platform_width_guard.py", "_SPLAT"),
    ("tests/test_protected_component_contract.py", "_U32"),
    ("tests/test_protected_component_contract.py", "_U64"),
    # the 64-bit-value gating guard's own window bounds
    ("tests/test_security_64bit_value_gating.py", "_HIGH"),
    ("tests/test_security_64bit_value_gating.py", "_LOW"),
)


def test_s1_detector_fires_and_spares() -> None:
    """Synthetic RED/GREEN: a guard that cannot fail is not a guard."""
    ungated_direct = (
        "CK_UNAVAILABLE_INFORMATION = 0xFFFFFFFFFFFFFFFF\n"
        "def test_pin(x):\n"
        "    assert x == CK_UNAVAILABLE_INFORMATION\n"
        "    assert x != 0xFFFFFFFF\n"
    )
    assert s1_offenders_in_source(ungated_direct, "x.py") == ["x.py::test_pin"]

    gated = (
        "import pytest\n"
        "CK_UNAVAILABLE_INFORMATION = 0xFFFFFFFFFFFFFFFF\n"
        "_skip32 = pytest.mark.skipif(int(CK_UNAVAILABLE_INFORMATION) == 0xFFFFFFFF, reason='r')\n"
        "@_skip32\n"
        "def test_pin(x):\n"
        "    assert x == CK_UNAVAILABLE_INFORMATION\n"
        "    assert x != 0xFFFFFFFF\n"
    )
    assert s1_offenders_in_source(gated, "x.py") == []

    accept_both = "def test_pin(x):\n    assert x in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)\n"
    assert s1_offenders_in_source(accept_both, "x.py") == []

    fake = (
        "_U64 = 0xFFFFFFFFFFFFFFFF\n"
        "_U32 = 0xFFFFFFFF\n"
        "def plan(tag):\n"
        "    if tag == 'refuse32':\n"
        "        return _U32\n"
        "    return _U64\n"
    )
    stimulus_fail = fake + (
        "import pytest\n"
        "def test_legacy():\n"
        "    with pytest.raises(Failed):\n"
        "        run(plan('refuse32'))\n"
    )
    assert s1_offenders_in_source(stimulus_fail, "x.py") == ["x.py::test_legacy"]

    stimulus_accept = fake + ("def test_matrix():\n    run(plan('refuse32'))\n")
    assert s1_offenders_in_source(stimulus_accept, "x.py") == []

    width_branch = (
        "import ctypes\n"
        "def test_oracle():\n"
        "    if ctypes.sizeof(ctypes.c_ulong) == 4:\n"
        "        assert V == 0xFFFFFFFF\n"
        "    else:\n"
        "        assert V == 0xFFFFFFFFFFFFFFFF\n"
    )
    assert s1_offenders_in_source(width_branch, "x.py") == []

    audited = ungated_direct.replace(
        "    assert x != 0xFFFFFFFF\n",
        "    assert x != 0xFFFFFFFF  # audit-ok: width-independent oracle\n",
    )
    assert s1_offenders_in_source(audited, "x.py") == []

    # Slice-1 review M2: exemptions are scoped, not body-wide. An accept-both
    # assert elsewhere does not spare distinguishing comparisons...
    accept_elsewhere = (
        "def test_pin(x):\n"
        "    assert x in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)\n"
        "    assert x == 0xFFFFFFFFFFFFFFFF\n"
        "    assert x != 0xFFFFFFFF\n"
    )
    assert s1_offenders_in_source(accept_elsewhere, "x.py") == ["x.py::test_pin"]

    # ...but an ``or`` over both spellings stays accept-both.
    or_both = "def test_pin(x):\n    assert x == 0xFFFFFFFF or x == 0xFFFFFFFFFFFFFFFF\n"
    assert s1_offenders_in_source(or_both, "x.py") == []

    # A non-skip decorator mentioning a width name is not a gate.
    parametrize_not_gate = (
        "import pytest\n"
        "CK_UNAVAILABLE_INFORMATION = 0xFFFFFFFFFFFFFFFF\n"
        "@pytest.mark.parametrize('v', [CK_UNAVAILABLE_INFORMATION])\n"
        "def test_pin(x, v):\n"
        "    assert x == CK_UNAVAILABLE_INFORMATION\n"
        "    assert x != 0xFFFFFFFF\n"
    )
    assert s1_offenders_in_source(parametrize_not_gate, "x.py") == ["x.py::test_pin"]

    # A bare sizeof mention without a branch is not a width split.
    sizeof_mention = (
        "import ctypes\n"
        "def test_pin(x):\n"
        "    w = ctypes.sizeof(ctypes.c_ulong)\n"
        "    assert x == 0xFFFFFFFFFFFFFFFF\n"
        "    assert x != 0xFFFFFFFF\n"
    )
    assert s1_offenders_in_source(sizeof_mention, "x.py") == ["x.py::test_pin"]

    # E11 declared miss (see module docstring): a bare assert-predicate
    # over a helper-computed spelling is not an S1 premise shape. This
    # pins the miss -- if S1 ever flags it, re-adjudicate E11 here.
    bare_predicate = (
        "def _sentinel(w):\n"
        "    return (1 << w) - 1\n"
        "def test_pin():\n"
        "    assert _is_unavailable_length(_sentinel(64))\n"
    )
    assert s1_offenders_in_source(bare_predicate, "x.py") == []


def test_s2_detector_fires_and_spares() -> None:
    bad = "import ctypes\n_X = ctypes.c_ulong(-1).value\n"
    assert s2_sites_in_source(bad, "x.py") == [("x.py", "_X", 2)]
    bad2 = "_Y = (1 << (ctypes.sizeof(ctypes.c_ulong) * 8)) - 1\n"
    assert s2_sites_in_source(bad2, "x.py") == [("x.py", "_Y", 1)]
    clean = "from pkcs11_check.raw.types_std import CK_UNAVAILABLE_INFORMATION\n"
    assert s2_sites_in_source(clean, "x.py") == []


def test_s1_sentinel_distinctness_premises_are_gated() -> None:
    offenders: list[str] = []
    for tree in _S1_TREES:
        pattern = "test_*.py" if tree.name == "tests" else "*.py"
        for path in sorted(tree.rglob(pattern)):
            rel = path.relative_to(_ROOT).as_posix()
            offenders.extend(s1_offenders_in_source(path.read_text(encoding="utf-8"), rel))
    assert offenders == [], (
        "test(s) pin a 32-bit-vs-platform sentinel distinction without a width gate -- "
        "they invert on 4-byte CK_ULONG. Gate with requires_64bit_ck_ulong or a skipif "
        "mentioning CK_UNAVAILABLE_INFORMATION/CK_ULONG, accept both spellings, or "
        "annotate # audit-ok: <reason>:\n  " + "\n  ".join(offenders)
    )


def test_s2_no_local_sentinel_recompute() -> None:
    offenders: list[str] = []
    found: set[tuple[str, str]] = set()
    for tree in _S2_TREES:
        for path in sorted(tree.rglob("*.py")):
            rel = path.relative_to(_ROOT).as_posix()
            if rel in _S2_EXEMPT_FILES:
                continue
            for label, name, lineno in s2_sites_in_source(path.read_text(encoding="utf-8"), rel):
                if (label, name) in _S2_ALLOWLIST:
                    found.add((label, name))
                else:
                    offenders.append(f"{label}:{lineno} ({name})")
    assert offenders == [], (
        "local CK_UNAVAILABLE_INFORMATION recompute outside the generated seam; "
        "import CK_UNAVAILABLE_INFORMATION instead:\n  " + "\n  ".join(offenders)
    )
    stale = set(_S2_ALLOWLIST) - found
    assert not stale, (
        "stale S2 allowlist entries (site disappeared -- remove them):\n  "
        + "\n  ".join(f"{f} ({n})" for f, n in sorted(stale))
    )


def test_s4_detector_fires_and_spares() -> None:
    """Synthetic: literal, computed and aliased bindings fold; seam spares."""
    src = (
        "_LIT = 0xFFFFFFFF\n"
        "_COMPUTED = (1 << 32) - 1\n"
        "_POW = 2**64 - 1\n"
        "_WRAPPED = int(0xFFFFFFFFFFFFFFFF)\n"
        "_GEN = CK_CONSTANT(0xFFFFFFFF)\n"
        "_ALIAS = _LIT\n"
        "_CHAIN = _ALIAS\n"
        "_SEAM = int(CK_UNAVAILABLE_INFORMATION)\n"
        "_OTHER = 0xFFFFFFFE\n"
        "def f() -> None:\n"
        "    _LOCAL = 0xFFFFFFFF\n"
    )
    assert s4_bindings_in_source(src) == {
        "_LIT": _S32,
        "_COMPUTED": _S32,
        "_POW": _SPLAT,
        "_WRAPPED": _SPLAT,
        "_GEN": _S32,
        "_ALIAS": _S32,
        "_CHAIN": _S32,
    }


def test_s4_computed_sentinel_via_intermediate_constant() -> None:
    """P7: foldable intermediates feed computed sentinels; only sentinels report."""
    src = (
        "_BITS = 64\n"
        "_SENT = (1 << _BITS) - 1\n"
        "_ALIAS = _SENT\n"
        "_HALF = 32\n"
        "_W32 = (1 << _HALF) - 1\n"
        "_OTHER = _BITS + 1\n"
    )
    assert s4_bindings_in_source(src) == {
        "_SENT": _SPLAT,
        "_ALIAS": _SPLAT,
        "_W32": _S32,
    }


def test_s4_width_literal_census_is_pinned() -> None:
    found = s4_census()
    assert found == list(_S4_CENSUS), (
        "module-level width-literal bindings drifted from the S4 census.\n"
        "  new (route through CK_UNAVAILABLE_INFORMATION / "
        "_32, or add a deliberate census entry): "
        f"{sorted(set(found) - set(_S4_CENSUS))}\n"
        f"  stale (remove the pin): {sorted(set(_S4_CENSUS) - set(found))}"
    )
