from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HEADER = REPO_ROOT / "third_party/pkcs11-headers/3.2/pkcs11.h"
OUT_TYPES = REPO_ROOT / "src/pkcs11_check/raw/types_std.py"
OUT_METADATA = REPO_ROOT / "src/pkcs11_check/raw/metadata_std.py"

SYMBOL_PREFIXES = (
    "CKA_", "CKC_", "CKD_", "CKF_", "CKG_", "CKH_", "CKK_", "CKM_",
    "CKN_", "CKO_", "CKP_", "CKR_", "CKS_", "CKT_", "CKU_", "CKV_", "CKZ_",
    "CK_",  # CK_CERTIFICATE_CATEGORY_*, CK_SECURITY_DOMAIN_*, etc.
    "CRYPTOKI_VERSION_",
)

# Last-match-wins prefix ordering for typed constant families.
CONSTANT_TYPE_MAP = [
    ("CK_", "CK_CONSTANT"),
    ("CKA_", "CKA"), ("CKC_", "CKC"), ("CKD_", "CKD"),
    ("CKF_", "CKF"), ("CKG_", "CKG"), ("CKH_", "CKH"),
    ("CKK_", "CKK"), ("CKM_", "CKM"), ("CKN_", "CKN"),
    ("CKO_", "CKO"), ("CKP_", "CKP"), ("CKR_", "CKR"),
    ("CKS_", "CKS"), ("CKT_", "CKT"), ("CKU_", "CKU"),
    ("CKV_", "CKV"), ("CKZ_", "CKZ"),
    ("CRYPTOKI_VERSION_", "CK_CONSTANT"),
    # 3.x overrides (more specific prefixes win over shorter ones)
    ("CKG_MGF1_", "CKG"), ("CKH_HEDGE_", "CKH"), ("CKH_DETERMINISTIC_", "CKH"),
    ("CKP_ML_DSA_", "CKP"), ("CKP_ML_KEM_", "CKP"), ("CKP_SLH_DSA_", "CKP"),
    ("CKP_PKCS5_PBKD2_", "CKP"), ("CKS_LAST_VALIDATION_", "CKS"),
    ("CK_CERTIFICATE_CATEGORY_", "CK_CONSTANT"), ("CK_SECURITY_DOMAIN_", "CK_CONSTANT"),
]
NAME_TABLES = {
    "ATTR_NAMES": "CKA_",
    "MECHANISM_NAMES": "CKM_",
    "KEY_TYPE_NAMES": "CKK_",
    "OBJECT_CLASS_NAMES": "CKO_",
    "RV_NAMES": "CKR_",
    "FLAG_NAMES": "CKF_",
}


def _resolve_constant_type(name: str) -> str:
    """Return the typed constant class name for a symbol, using last-match-wins."""
    result = "CK_CONSTANT"  # fallback
    for prefix, cls_name in CONSTANT_TYPE_MAP:
        if name.startswith(prefix):
            result = cls_name
    return result


# OASIS-style: typedef struct CK_X { ... } CK_X;
STRUCT_PATTERN = re.compile(
    r"typedef struct\s+(CK_\w+)\s*\{(?P<body>.*?)\}\s*(CK_\w+)\s*;",
    re.DOTALL,
)
# Public-domain / plain-style: struct CK_X { ... };
PLAIN_STRUCT_PATTERN = re.compile(
    r"^struct\s+(CK_\w+)\s*\{(?P<body>.*?)\};",
    re.DOTALL | re.MULTILINE,
)
# OASIS-style function prototypes (pkcs11f.h)
FUNCTION_PATTERN = re.compile(
    r"CK_PKCS11_FUNCTION_INFO\((C_\w+)\)\s*"
    r"#ifdef CK_NEED_ARG_LIST\s*\((?P<args>.*?)\);\s*#endif",
    re.DOTALL,
)
# Public-domain function pointer typedefs: typedef CK_RV (* CK_C_Foo)(args);
PD_FUNCPTR_PATTERN = re.compile(
    r"typedef\s+CK_RV\s*\(\*\s*(?P<name>CK_C_\w+)\)\((?P<args>[^)]*)\)\s*;",
)
# Public-domain extern prototypes: extern CK_RV C_Foo(args);
PD_EXTERN_PATTERN = re.compile(
    r"extern\s+CK_RV\s+(C_\w+)\((?P<args>[^)]*)\)\s*;",
)
# OASIS-style: typedef struct CK_X CK_X;
OPAQUE_STRUCT_PATTERN = re.compile(r"^typedef struct (CK_\w+)\s+(CK_\w+)\s*;$", re.MULTILINE)
# Public-domain: STRUCTDEF(CK_X);
PD_STRUCTDEF_PATTERN = re.compile(r"^STRUCTDEF\((CK_\w+)\)\s*;", re.MULTILINE)
# OASIS-style callbacks
CALLBACK_PATTERN = re.compile(
    r"typedef CK_CALLBACK_FUNCTION\((?P<return_type>[^,]+),\s*(?P<name>CK_\w+)\)\((?P<args>.*?)\);",
    re.DOTALL,
)
# Public-domain callbacks: typedef CK_RV (* CK_NOTIFY)(...);
PD_CALLBACK_PATTERN = re.compile(
    r"typedef\s+CK_RV\s*\(\*\s*(?P<name>CK_(?!C_)\w+)\)\((?P<args>[^)]*)\)\s*;",
)

C_PRIMITIVES = {
    "unsigned char": "ctypes.c_ubyte",
    "char": "ctypes.c_char",
    "unsigned long int": "ctypes.c_ulong",
    "long int": "ctypes.c_long",
    "void": "None",
}


def _strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def _normalize_spaces(text: str) -> str:
    return " ".join(text.split())


def _clean_expr(expr: str) -> str:
    expr = expr.split("/*", 1)[0].strip()
    return re.sub(r"(?<=[0-9A-Fa-f])[uUlL]+\b", "", expr)


def _try_eval_expr(expr: str, resolved: dict[str, int]) -> int | str:
    cleaned = _clean_expr(expr)
    names = set(re.findall(r"\b[A-Z][A-Z0-9_]+\b", cleaned))
    for name in sorted(names, key=len, reverse=True):
        value = resolved.get(name)
        if value is None:
            continue
        cleaned = re.sub(rf"\b{name}\b", str(value), cleaned)
    if re.fullmatch(r"[0-9xXa-fA-F()~+<>&| \-]+", cleaned) is None:
        return _clean_expr(expr)
    return int(eval(cleaned, {"__builtins__": {}}, {}))


def _parse_symbols(text: str) -> dict[str, int | str]:
    symbols: dict[str, int | str] = {}
    resolved: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"#define\s+((?:CK|CRYPTOKI_)[A-Z0-9_]+)\s+(.+)$", line)
        if match is None:
            continue
        name, expr = match.groups()
        if not name.startswith(SYMBOL_PREFIXES):
            continue
        value = _try_eval_expr(expr, resolved)
        symbols[name] = value
        if isinstance(value, int):
            resolved[name] = value
    return symbols


def _parse_aliases(text: str) -> dict[str, tuple[str, int]]:
    aliases: dict[str, tuple[str, int]] = {}

    # Public-domain: ULONGDEF(CK_X) -> typedef CK_ULONG CK_X; typedef CK_X * CK_X_PTR;
    for match in re.finditer(r"^ULONGDEF\((CK_\w+)\)\s*;", text, re.MULTILINE):
        name = match.group(1)
        aliases[name] = ("CK_ULONG", 0)
        aliases[f"{name}_PTR"] = (name, 1)

    for match in re.finditer(r"typedef\s+(?P<body>[^;{}]+);", text, re.DOTALL):
        body = _normalize_spaces(match.group("body").replace("\\\n", " "))
        if "(" in body or ")" in body:
            continue
        # Skip macro template lines
        if "__name__" in body:
            continue
        target_match = re.match(r"(?P<source>.+?)\s+(?P<target>CK_\w+)$", body)
        if target_match is None:
            continue
        source, target = target_match.groups()
        if source.startswith("struct "):
            continue
        if target in aliases:
            continue  # Don't overwrite ULONGDEF-generated aliases
        # Count pointer depth from CK_PTR (OASIS) and * (public-domain)
        pointer_depth = source.count("CK_PTR") + source.count("*")
        base = _normalize_spaces(source.replace("CK_PTR", " ").replace("*", " ").strip())
        if not base:
            continue
        aliases[target] = (base, pointer_depth)
    return aliases


def _parse_opaque_structs(text: str) -> set[str]:
    structs: set[str] = set()
    # OASIS: typedef struct CK_X CK_X;
    for match in OPAQUE_STRUCT_PATTERN.finditer(text):
        struct_name, target_name = match.groups()
        if struct_name == target_name:
            structs.add(target_name)
    # Public-domain: STRUCTDEF(CK_X);
    for match in PD_STRUCTDEF_PATTERN.finditer(text):
        structs.add(match.group(1))
    return structs


def _generate_struct_ptr_aliases(
    opaque_structs: set[str],
    parsed_structs: dict[str, list[tuple[str, str]]],
    aliases: dict[str, tuple[str, int]],
) -> None:
    """Generate *_PTR and *_PTR_PTR aliases for struct types (STRUCTDEF expansion)."""
    all_struct_names = opaque_structs | set(parsed_structs)
    for name in all_struct_names:
        ptr_name = f"{name}_PTR"
        ptr_ptr_name = f"{name}_PTR_PTR"
        if ptr_name not in aliases:
            aliases[ptr_name] = (name, 1)
        if ptr_ptr_name not in aliases:
            aliases[ptr_ptr_name] = (name, 2)


def _parse_arg_types(args_block: str) -> list[str]:
    args_block = _strip_comments(args_block)
    arg_types: list[str] = []
    for line in args_block.splitlines():
        line = _normalize_spaces(line.strip())
        if line.endswith(","):
            line = line[:-1].strip()
        if not line or line == "void":
            continue
        arg_match = re.match(r"(.+?)\s+(\w+)$", line)
        if arg_match is None:
            continue
        arg_type, _ = arg_match.groups()
        arg_types.append(arg_type)
    return arg_types


def _parse_callbacks(text: str) -> dict[str, tuple[str, list[str]]]:
    callbacks: dict[str, tuple[str, list[str]]] = {}
    # OASIS: CK_CALLBACK_FUNCTION(CK_RV, CK_NOTIFY)(...)
    for match in CALLBACK_PATTERN.finditer(text):
        callbacks[match.group("name")] = (
            _normalize_spaces(match.group("return_type")),
            _parse_arg_types(match.group("args")),
        )
    # Public-domain: typedef CK_RV (* CK_NOTIFY)(...);
    for match in PD_CALLBACK_PATTERN.finditer(text):
        name = match.group("name")
        if name not in callbacks:
            callbacks[name] = ("CK_RV", _parse_pd_arg_types(match.group("args")))
    return callbacks


def _parse_structs(text: str) -> dict[str, list[tuple[str, str]]]:
    structs: dict[str, list[tuple[str, str]]] = {}
    for match in STRUCT_PATTERN.finditer(text):
        name = match.group(3)
        fields: list[tuple[str, str]] = []
        body = _strip_comments(match.group("body"))
        for raw_field in body.split(";"):
            field = _normalize_spaces(raw_field)
            if not field:
                continue
            field_match = re.match(r"(.+?)\s+(\w+)(\[\d+\])?$", field)
            if field_match is None:
                continue
            field_type, field_name, array_suffix = field_match.groups()
            if array_suffix is not None:
                field_type = f"{field_type}{array_suffix}"
            fields.append((field_name, field_type))
        structs[name] = fields
    for match in PLAIN_STRUCT_PATTERN.finditer(text):
        name = match.group(1)
        fields: list[tuple[str, str]] = []
        body = _strip_comments(match.group("body"))
        for raw_field in body.split(";"):
            field = _normalize_spaces(raw_field)
            if not field:
                continue
            field_match = re.match(r"(.+?)\s+(\w+)(\[\d+\])?$", field)
            if field_match is None:
                continue
            field_type, field_name, array_suffix = field_match.groups()
            if array_suffix is not None:
                field_type = f"{field_type}{array_suffix}"
            fields.append((field_name, field_type))
        structs[name] = fields
    return structs


def _normalize_arg_type(type_str: str) -> str:
    """Normalize C arg types to PKCS#11 typedef names for metadata."""
    t = _normalize_spaces(type_str)
    # void * -> CK_VOID_PTR
    if t == "void *":
        return "CK_VOID_PTR"
    # CK_X * * -> CK_X_PTR_PTR
    m = re.match(r"(CK_\w+)\s*\*\s*\*$", t)
    if m:
        return f"{m.group(1)}_PTR_PTR"
    # CK_X * -> CK_X_PTR
    m = re.match(r"(CK_\w+)\s*\*$", t)
    if m:
        return f"{m.group(1)}_PTR"
    return t


def _parse_pd_arg_types(args: str) -> list[str]:
    """Parse argument types from a public-domain function pointer typedef."""
    args = _strip_comments(args).strip()
    if not args or args == "void":
        return []
    types = []
    for arg in args.split(","):
        arg = _normalize_spaces(arg.strip())
        if not arg or arg == "void":
            continue
        # "CK_SESSION_HANDLE hSession" -> "CK_SESSION_HANDLE"
        # "void *pReserved" -> "void *"
        # "CK_FUNCTION_LIST **ppFunctionList" -> "CK_FUNCTION_LIST **"
        parts = arg.rsplit(" ", 1)
        if len(parts) == 2:
            type_part = parts[0].strip()
            name_part = parts[1].strip()
            # Move pointer stars from name to type
            while name_part.startswith("*"):
                type_part += " *"
                name_part = name_part[1:]
            types.append(_normalize_arg_type(_normalize_spaces(type_part)))
        else:
            types.append(_normalize_arg_type(arg))
    return types


def _parse_functions(text: str) -> list[tuple[str, list[str]]]:
    functions: list[tuple[str, list[str]]] = []
    seen = set()

    # OASIS: CK_PKCS11_FUNCTION_INFO(C_*)
    for match in FUNCTION_PATTERN.finditer(text):
        name = match.group(1)
        if name not in seen:
            functions.append((name, _parse_arg_types(match.group("args"))))
            seen.add(name)

    # Public-domain: extract order from CK_FUNCTION_LIST_3_2 struct,
    # and signatures from typedef CK_RV (* CK_C_*)(...)
    if not functions:
        # Parse function pointer typedefs for signatures
        funcptr_sigs: dict[str, list[str]] = {}
        for match in PD_FUNCPTR_PATTERN.finditer(text):
            ck_name = match.group("name")  # CK_C_Initialize
            func_name = ck_name[3:]  # C_Initialize
            funcptr_sigs[func_name] = _parse_pd_arg_types(match.group("args"))

        # Also try extern prototypes
        for match in PD_EXTERN_PATTERN.finditer(text):
            func_name = match.group(1)
            if func_name not in funcptr_sigs:
                funcptr_sigs[func_name] = _parse_pd_arg_types(match.group("args"))

        # Extract function order from CK_FUNCTION_LIST_3_2 (the most complete one)
        fl32_match = re.search(
            r"struct\s+CK_FUNCTION_LIST_3_2\s*\{(?P<body>.*?)\};",
            text, re.DOTALL,
        )
        if fl32_match:
            body = _strip_comments(fl32_match.group("body"))
            for line in body.splitlines():
                line = _normalize_spaces(line.strip()).rstrip(";").strip()
                if not line:
                    continue
                # "CK_C_Initialize C_Initialize" or "CK_VERSION version"
                parts = line.split()
                if len(parts) == 2 and parts[1].startswith("C_"):
                    func_name = parts[1]
                    if func_name not in seen:
                        sig = funcptr_sigs.get(func_name, [])
                        functions.append((func_name, sig))
                        seen.add(func_name)

    return functions


def _render_alias(
    name: str,
    aliases: dict[str, tuple[str, int]],
    struct_names: set[str],
    callable_names: set[str],
) -> str:
    base, pointer_depth = aliases[name]
    if pointer_depth == 0:
        return _render_ctype(base, aliases, struct_names, callable_names)

    target = _render_ctype(base, aliases, struct_names, callable_names)
    for _ in range(pointer_depth):
        if target == "None":
            target = "ctypes.c_void_p"
        else:
            target = f"ctypes.POINTER({target})"
    return target


def _render_ctype(
    type_name: str,
    aliases: dict[str, tuple[str, int]],
    struct_names: set[str],
    callable_names: set[str],
) -> str:
    normalized = _normalize_spaces(type_name)
    primitive = C_PRIMITIVES.get(normalized)
    if primitive is not None:
        return primitive
    if normalized.startswith("struct "):
        normalized = normalized.removeprefix("struct ")
    if normalized in struct_names:
        return normalized
    if normalized in callable_names:
        return normalized
    if normalized in aliases:
        return normalized
    if normalized.endswith("_PTR") or normalized == "CK_VOID_PTR":
        return "ctypes.c_void_p"
    if normalized.startswith("CK_"):
        return "ctypes.c_ulong"
    return "ctypes.c_void_p"


def _field_ctype(
    field_type: str,
    aliases: dict[str, tuple[str, int]],
    struct_names: set[str],
    callable_names: set[str],
) -> str:
    array_match = re.match(r"(.+?)\[(\d+)\]$", field_type)
    if array_match is not None:
        base_type, size = array_match.groups()
        return f"{_render_ctype(base_type, aliases, struct_names, callable_names)} * {size}"
    # Handle pointer fields: "CK_UTF8CHAR *" -> ctypes.c_void_p
    ptr_match = re.match(r"(.+?)\s*(\*+)$", field_type)
    if ptr_match is not None:
        return "ctypes.c_void_p"
    return _render_ctype(field_type, aliases, struct_names, callable_names)


def _function_pointer_name(name: str) -> str:
    return f"CK_{name}"


def _render_callable_type(
    return_type: str,
    arg_types: list[str],
    aliases: dict[str, tuple[str, int]],
    struct_names: set[str],
    callable_names: set[str],
) -> str:
    rendered_return = _render_ctype(return_type, aliases, struct_names, callable_names)
    rendered_args = [
        _render_ctype(arg_type, aliases, struct_names, callable_names)
        for arg_type in arg_types
    ]
    if rendered_args:
        return f"ctypes.CFUNCTYPE({rendered_return}, {', '.join(rendered_args)})"
    return f"ctypes.CFUNCTYPE({rendered_return})"


def _function_list_fields(
    struct_name: str,
    functions: list[tuple[str, list[str]]],
) -> list[tuple[str, str]]:
    version_fields = [("version", "CK_VERSION")]
    names = [name for name, _ in functions]
    v30_start = names.index("C_GetInterfaceList") if "C_GetInterfaceList" in names else len(names)
    v32_start = names.index("C_EncapsulateKey") if "C_EncapsulateKey" in names else len(names)

    if struct_name == "CK_FUNCTION_LIST":
        selected = functions[:v30_start]
    elif struct_name == "CK_FUNCTION_LIST_3_0":
        selected = functions[:v32_start]
    elif struct_name == "CK_FUNCTION_LIST_3_2":
        selected = functions
    else:
        return version_fields

    return version_fields + [(name, _function_pointer_name(name)) for name, _ in selected]


def _constant_class_lines() -> list[str]:
    """Return Python source lines defining the typed constant class hierarchy."""
    return [
        "class CK_CONSTANT(int):",
        "    _name: str | None",
        "    def __new__(cls, value: int, name: str | None = None) -> Self:",
        "        obj = super().__new__(cls, value)",
        "        obj._name = name",
        "        return obj",
        "    def _hex(self) -> str:",
        "        import ctypes as _ct",
        "        mask = (1 << (_ct.sizeof(_ct.c_ulong) * 8)) - 1",
        "        return f'0x{self & mask:08x}'",
        "    def __repr__(self) -> str:",
        "        if self._name:",
        "            return f'<{self._name}: {self._hex()}>'",
        "        return f'<{self.__class__.__name__}({self._hex()})>'",
        "    def __str__(self) -> str:",
        "        if self._name:",
        "            return self._name",
        "        return self._hex()",
        "    def __getnewargs__(self) -> tuple[int, str | None]:  # type: ignore[override]",
        "        return (int(self), self._name)",
        "",
        "class CKA(CK_CONSTANT): pass",
        "class CKC(CK_CONSTANT): pass",
        "class CKD(CK_CONSTANT): pass",
        "class CKF(CK_CONSTANT):",
        '    def __or__(self, other: int) -> "CKF": return CKF(int.__or__(self, other))',
        '    def __ror__(self, other: int) -> "CKF": return CKF(int.__or__(self, other))',
        '    def __and__(self, other: int) -> "CKF": return CKF(int.__and__(self, other))',
        '    def __rand__(self, other: int) -> "CKF": return CKF(int.__and__(self, other))',
        '    def __invert__(self) -> "CKF": return CKF(int.__invert__(self))',
        "class CKG(CK_CONSTANT): pass",
        "class CKH(CK_CONSTANT): pass",
        "class CKK(CK_CONSTANT): pass",
        "class CKM(CK_CONSTANT): pass",
        "class CKN(CK_CONSTANT): pass",
        "class CKO(CK_CONSTANT): pass",
        "class CKP(CK_CONSTANT): pass",
        "class CKR(CK_CONSTANT): pass",
        "class CKS(CK_CONSTANT): pass",
        "class CKT(CK_CONSTANT): pass",
        "class CKU(CK_CONSTANT): pass",
        "class CKV(CK_CONSTANT): pass",
        "class CKZ(CK_CONSTANT): pass",
    ]


def _render_types_module(
    *,
    symbols: dict[str, int | str],
    structs: dict[str, list[tuple[str, str]]],
    aliases: dict[str, tuple[str, int]],
    opaque_structs: set[str],
    callbacks: dict[str, tuple[str, list[str]]],
    functions: list[tuple[str, list[str]]],
) -> str:
    if not symbols and not structs and not callbacks:
        return (
            '"""Generated PKCS#11 standard types/constants."""\n'
            "from __future__ import annotations\n\n"
            "STANDARD_GENERATED = True\n"
        )

    lines = [
        '"""Generated PKCS#11 standard types/constants."""',
        "from __future__ import annotations",
        "",
        "import ctypes",
        "from typing import Self",
        "",
        "STANDARD_GENERATED = True",
        "",
    ]

    # Emit typed constant class hierarchy
    lines.extend(_constant_class_lines())
    lines.append("")

    struct_names = opaque_structs | set(structs)
    function_pointer_names = {_function_pointer_name(name) for name, _ in functions}
    callable_names = set(callbacks) | function_pointer_names
    for name in sorted(struct_names):
        lines.append(f"class {name}(ctypes.Structure):")
        lines.append("    pass")
        lines.append("")

    # Render aliases with dependency ordering: base types before types that reference them
    rendered_aliases: set[str] = set()

    def _render_alias_with_deps(name: str) -> None:
        if name in rendered_aliases or not name.startswith("CK_"):
            return
        base, _ = aliases[name]
        # Ensure the base type is rendered first if it's also an alias
        clean_base = _normalize_spaces(base.replace("*", " ").replace("CK_PTR", " ").strip())
        if clean_base in aliases and clean_base not in rendered_aliases:
            _render_alias_with_deps(clean_base)
        rendered_aliases.add(name)
        lines.append(f"{name} = {_render_alias(name, aliases, struct_names, callable_names)}")

    for name in sorted(aliases):
        _render_alias_with_deps(name)
    lines.append("")

    for name in sorted(callbacks):
        return_type, arg_types = callbacks[name]
        rendered = _render_callable_type(
            return_type, arg_types, aliases, struct_names, callable_names
        )
        lines.append(f"{name} = {rendered}")
    if callbacks:
        lines.append("")

    for name, arg_types in functions:
        lines.append(
            f"{_function_pointer_name(name)} = "
            f"{_render_callable_type('CK_RV', arg_types, aliases, struct_names, callable_names)}"
        )
    if functions:
        lines.append("")

    for name, fields in structs.items():
        if name.startswith("CK_FUNCTION_LIST"):
            fields = _function_list_fields(name, functions)
        if not fields:
            lines.append(f"{name}._fields_: list[tuple[str, object]] = []")
        else:
            lines.append(f"{name}._fields_ = [")
            for field_name, field_type in fields:
                rendered_field = _field_ctype(
                    field_type, aliases, struct_names, callable_names
                )
                lines.append(f'    ("{field_name}", {rendered_field}),')
            lines.append("    ]")
        lines.append("")

    # Platform-dependent CK_ULONG mask (computed at runtime in types_std.py)
    lines.append("_CK_ULONG_MAX = (1 << (ctypes.sizeof(ctypes.c_ulong) * 8)) - 1")
    lines.append("")

    for name, value in symbols.items():
        if isinstance(value, str):
            # Unresolved expression — emit as plain constant
            lines.append(f"{name} = {value}")
        elif value == -1 or (value < 0):
            # Platform-dependent value like ~0UL: emit runtime expression
            cls = _resolve_constant_type(name)
            lines.append(f"{name} = {cls}(_CK_ULONG_MAX, {name!r})")
        else:
            cls = _resolve_constant_type(name)
            lines.append(f"{name} = {cls}(0x{value:08x}, {name!r})")
    return "\n".join(lines) + "\n"


def _render_metadata_module(
    *,
    symbols: dict[str, int | str],
    functions: list[tuple[str, list[str]]],
) -> str:
    if not symbols and not functions:
        return (
            '"""Generated PKCS#11 standard metadata."""\n'
            "from __future__ import annotations\n\n"
            'STANDARD_COUNTS = {"functions": 0, "attrs": 0, "mechanisms": 0}\n'
        )

    lines = [
        '"""Generated PKCS#11 standard metadata."""',
        "from __future__ import annotations",
        "",
        "FUNCTION_SIGNATURES = {",
    ]
    for name, args in functions:
        lines.append(f"    {name!r}: {args!r},")
    lines.extend(
        [
            "}",
            "",
            "FUNCTION_INDICES = {",
        ]
    )
    for index, (name, _) in enumerate(functions):
        lines.append(f"    {name!r}: {index},")
    lines.extend(
        [
            "}",
            "",
            "STANDARD_COUNTS = {",
            f'    "functions": {len(functions)},',
            f'    "attrs": {sum(1 for name in symbols if name.startswith("CKA_"))},',
            f'    "mechanisms": {sum(1 for name in symbols if name.startswith("CKM_"))},',
            "}",
            "",
        ]
    )

    for table_name, prefix in NAME_TABLES.items():
        lines.append(f"{table_name} = {{")
        for name, value in symbols.items():
            if not name.startswith(prefix) or not isinstance(value, int):
                continue
            lines.append(f"    {hex(value)}: {name!r},")
        lines.append("}")
        lines.append("")

    lines.append("SYMBOL_NAME_TABLES = {")
    for table_name in NAME_TABLES:
        lines.append(f'    "{table_name}": {table_name},')
    lines.append("}")

    return "\n".join(lines)


def _load_inputs(header: Path) -> tuple[str, str]:
    root_text = header.read_text()
    header_dir = header.parent
    type_header = header_dir / "pkcs11t.h"
    function_header = header_dir / "pkcs11f.h"
    # Multi-file OASIS headers: pkcs11.h + pkcs11t.h + pkcs11f.h
    if type_header.is_file():
        types_text = f"{type_header.read_text()}\n{root_text}"
        functions_text = function_header.read_text() if function_header.is_file() else root_text
        return types_text, functions_text
    # Single-file public-domain header: everything in pkcs11.h
    return root_text, root_text


def generate_raw_standard(*, header: Path, out_types: Path, out_metadata: Path) -> None:
    if not header.is_file():
        raise SystemExit(f"missing header: {header}")

    types_text, functions_text = _load_inputs(header)
    symbols = _parse_symbols(types_text)
    aliases = _parse_aliases(types_text)
    opaque_structs = _parse_opaque_structs(types_text)
    callbacks = _parse_callbacks(types_text)
    structs = _parse_structs(types_text)
    _generate_struct_ptr_aliases(opaque_structs, structs, aliases)
    functions = _parse_functions(functions_text)

    out_types.write_text(
        _render_types_module(
            symbols=symbols,
            structs=structs,
            aliases=aliases,
            opaque_structs=opaque_structs,
            callbacks=callbacks,
            functions=functions,
        )
    )
    out_metadata.write_text(_render_metadata_module(symbols=symbols, functions=functions))

    # Format generated files with ruff if available
    import shutil
    import subprocess as _sp

    ruff_bin = shutil.which("ruff")
    if ruff_bin:
        for path in (out_types, out_metadata):
            _sp.run(  # noqa: S603
                [ruff_bin, "format", str(path)],
                capture_output=True,
            )


def main() -> None:
    generate_raw_standard(header=HEADER, out_types=OUT_TYPES, out_metadata=OUT_METADATA)


if __name__ == "__main__":
    main()
