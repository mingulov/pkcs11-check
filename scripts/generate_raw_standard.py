from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HEADER = REPO_ROOT / "third_party/pkcs11-headers/3.2/pkcs11.h"
OUT_TYPES = REPO_ROOT / "src/pkcs11_check/raw/types_std.py"
OUT_METADATA = REPO_ROOT / "src/pkcs11_check/raw/metadata_std.py"

SYMBOL_PREFIXES = ("CKA_", "CKM_", "CKK_", "CKO_", "CKR_", "CKF_")
NAME_TABLES = {
    "ATTR_NAMES": "CKA_",
    "MECHANISM_NAMES": "CKM_",
    "KEY_TYPE_NAMES": "CKK_",
    "OBJECT_CLASS_NAMES": "CKO_",
    "RV_NAMES": "CKR_",
    "FLAG_NAMES": "CKF_",
}

STRUCT_PATTERN = re.compile(
    r"typedef struct\s+(CK_\w+)\s*\{(?P<body>.*?)\}\s*(CK_\w+)\s*;",
    re.DOTALL,
)
PLAIN_STRUCT_PATTERN = re.compile(
    r"^struct\s+(CK_\w+)\s*\{(?P<body>.*?)\};",
    re.DOTALL | re.MULTILINE,
)
FUNCTION_PATTERN = re.compile(
    r"CK_PKCS11_FUNCTION_INFO\((C_\w+)\)\s*"
    r"#ifdef CK_NEED_ARG_LIST\s*\((?P<args>.*?)\);\s*#endif",
    re.DOTALL,
)
OPAQUE_STRUCT_PATTERN = re.compile(r"^typedef struct (CK_\w+)\s+(CK_\w+)\s*;$", re.MULTILINE)
CALLBACK_PATTERN = re.compile(
    r"typedef CK_CALLBACK_FUNCTION\([^,]+,\s*(CK_\w+)\)\((?P<args>.*?)\);",
    re.DOTALL,
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
        match = re.match(r"#define\s+(CK[A-Z0-9_]+)\s+(.+)$", line)
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
    for match in re.finditer(r"^typedef\s+(.+?)\s+(CK_\w+)\s*;$", text, re.MULTILINE):
        source, target = match.groups()
        if "{" in source or "}" in source:
            continue
        if source.startswith("struct "):
            continue
        pointer_depth = source.count("CK_PTR")
        base = _normalize_spaces(source.replace("CK_PTR", " ").strip())
        if not base:
            continue
        aliases[target] = (base, pointer_depth)
    return aliases


def _parse_opaque_structs(text: str) -> set[str]:
    structs: set[str] = set()
    for match in OPAQUE_STRUCT_PATTERN.finditer(text):
        struct_name, target_name = match.groups()
        if struct_name == target_name:
            structs.add(target_name)
    return structs


def _parse_callbacks(text: str) -> set[str]:
    return {match.group(1) for match in CALLBACK_PATTERN.finditer(text)}


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


def _parse_functions(text: str) -> list[tuple[str, list[str]]]:
    functions: list[tuple[str, list[str]]] = []
    for match in FUNCTION_PATTERN.finditer(text):
        name = match.group(1)
        args_block = _strip_comments(match.group("args"))
        arg_types: list[str] = []
        for line in args_block.splitlines():
            line = _normalize_spaces(line.strip())
            if line.endswith(","):
                line = line[:-1].strip()
            if not line:
                continue
            arg_match = re.match(r"(.+?)\s+(\w+)$", line)
            if arg_match is None:
                continue
            arg_type, _ = arg_match.groups()
            arg_types.append(arg_type)
        functions.append((name, arg_types))
    return functions


def _render_alias(
    name: str,
    aliases: dict[str, tuple[str, int]],
    struct_names: set[str],
) -> str:
    base, pointer_depth = aliases[name]
    if pointer_depth == 0:
        return _render_ctype(base, aliases, struct_names)

    target = _render_ctype(base, aliases, struct_names)
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
) -> str:
    normalized = _normalize_spaces(type_name)
    primitive = C_PRIMITIVES.get(normalized)
    if primitive is not None:
        return primitive
    if normalized.startswith("struct "):
        normalized = normalized.removeprefix("struct ")
    if normalized in struct_names:
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
) -> str:
    array_match = re.match(r"(.+?)\[(\d+)\]$", field_type)
    if array_match is None:
        return _render_ctype(field_type, aliases, struct_names)
    base_type, size = array_match.groups()
    return f"{_render_ctype(base_type, aliases, struct_names)} * {size}"


def _render_types_module(
    *,
    symbols: dict[str, int | str],
    structs: dict[str, list[tuple[str, str]]],
    aliases: dict[str, tuple[str, int]],
    opaque_structs: set[str],
    callbacks: set[str],
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
        "",
        "STANDARD_GENERATED = True",
        "",
    ]

    struct_names = opaque_structs | set(structs)
    for name in sorted(struct_names):
        lines.append(f"class {name}(ctypes.Structure):")
        lines.append("    pass")
        lines.append("")

    for name in sorted(callbacks):
        lines.append(f"{name} = ctypes.c_void_p")
    if callbacks:
        lines.append("")

    for name in aliases:
        if not name.startswith("CK_"):
            continue
        lines.append(f"{name} = {_render_alias(name, aliases, struct_names)}")
    lines.append("")

    for name, fields in structs.items():
        if not fields:
            lines.append(f"{name}._fields_: list[tuple[str, object]] = []")
        else:
            lines.append(f"{name}._fields_ = [")
            for field_name, field_type in fields:
                lines.append(
                    f'    ("{field_name}", {_field_ctype(field_type, aliases, struct_names)}),'
                )
            lines.append("    ]")
        lines.append("")

    for name, value in symbols.items():
        rendered = value if isinstance(value, str) else hex(value)
        lines.append(f"{name} = {rendered}")
    lines.append("")
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
    lines.append("")
    return "\n".join(lines)


def _load_inputs(header: Path) -> tuple[str, str]:
    root_text = header.read_text()
    header_dir = header.parent
    type_header = header_dir / "pkcs11t.h"
    function_header = header_dir / "pkcs11f.h"
    types_text = type_header.read_text() if type_header.is_file() else root_text
    if type_header.is_file():
        types_text = f"{types_text}\n{root_text}"
    return types_text, (
        function_header.read_text() if function_header.is_file() else root_text
    )


def generate_raw_standard(*, header: Path, out_types: Path, out_metadata: Path) -> None:
    if not header.is_file():
        raise SystemExit(f"missing header: {header}")

    types_text, functions_text = _load_inputs(header)
    symbols = _parse_symbols(types_text)
    aliases = _parse_aliases(types_text)
    opaque_structs = _parse_opaque_structs(types_text)
    callbacks = _parse_callbacks(types_text)
    structs = _parse_structs(types_text)
    functions = _parse_functions(functions_text)

    out_types.write_text(
        _render_types_module(
            symbols=symbols,
            structs=structs,
            aliases=aliases,
            opaque_structs=opaque_structs,
            callbacks=callbacks,
        )
    )
    out_metadata.write_text(_render_metadata_module(symbols=symbols, functions=functions))


def main() -> None:
    generate_raw_standard(header=HEADER, out_types=OUT_TYPES, out_metadata=OUT_METADATA)


if __name__ == "__main__":
    main()
