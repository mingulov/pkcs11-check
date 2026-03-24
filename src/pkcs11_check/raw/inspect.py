"""Human-readable rendering helpers for raw PKCS#11 values."""

from __future__ import annotations

import ctypes
from typing import Any

from .extensions import lookup_inspector, lookup_symbol_name
from .faults import CountFaultArg, SizedFaultArg
from .pack import LengthArg, PackedAttribute, PackedMechanism, PointerArg, TemplateArg


def _render_symbol(namespace: str, value: int) -> str:
    return lookup_symbol_name(namespace, value) or f"0x{value:08x}"


def render_length(length: LengthArg) -> str:
    """Render explicit/native length provenance."""
    mode = "explicit" if length.explicit else "native"
    return f"len={length.value} {mode}"


def _byte_preview(storage: Any) -> str | None:
    raw = getattr(storage, "raw", None)
    if raw is None and isinstance(storage, bytes):
        raw = storage
    if raw is None and hasattr(storage, "_type_") and isinstance(storage, object):
        item_type = getattr(type(storage), "_type_", None)
        if item_type in (bytes,):
            raw = bytes(storage)
        elif item_type in (ctypes.c_char, ctypes.c_byte, ctypes.c_ubyte):
            raw = bytes(storage)
    if raw is None:
        return None
    data = raw[:-1] if raw.endswith(b"\x00") else raw
    return data[:16].hex()


def render_pointer(pointer: PointerArg) -> str:
    """Render pointer provenance and backing-storage details."""
    if pointer.pointer is None:
        return f"ptr=NULL origin={pointer.origin}"

    parts = [f"kind={pointer.kind}", f"origin={pointer.origin}"]
    if pointer.native_length is not None:
        parts.append(f"native_len={pointer.native_length}")
    if pointer.kind == "bytes":
        preview = _byte_preview(pointer.storage)
        if preview is not None:
            parts.append(f"preview={preview}")
    elif pointer.kind == "struct":
        parts.append(f"struct={type(pointer.storage).__name__}")
    elif pointer.kind == "scalar":
        value = getattr(pointer.storage, "value", None)
        parts.append(f"value={value}")
    elif pointer.kind == "array":
        if pointer.element_type is not None:
            parts.append(f"element_type={pointer.element_type}")
        if pointer.element_count is not None:
            parts.append(f"count={pointer.element_count}")
    return " ".join(parts)


def render_attribute(attribute: PackedAttribute) -> str:
    """Render a packed attribute with its pointer and length provenance."""
    name = _render_symbol("attrs", int(attribute.attribute.type))
    return f"{name} ({render_pointer(attribute.pointer_arg)} {render_length(attribute.length_arg)})"


def render_template(template: TemplateArg) -> str:
    """Render a CK_ATTRIBUTE template and its packed attributes."""
    rendered = ", ".join(render_attribute(attribute) for attribute in template.attributes)
    return f"template[count={template.count}] [{rendered}]"


def render_count_fault(fault: CountFaultArg) -> str:
    """Render a malformed pointer/count state such as a mismatched template count."""
    return (
        f"count_fault[{fault.note}] (claimed={fault.claimed_count}, actual={fault.actual_count}, "
        f"{render_pointer(fault.pointer_arg)})"
    )


def render_sized_fault(fault: SizedFaultArg) -> str:
    """Render a malformed pointer/length state such as truncated or wrong-shape input."""
    return f"sized_fault[{fault.note}] ({render_pointer(fault.pointer_arg)}, {render_length(fault.length_arg)})"


def render_mechanism(mechanism: PackedMechanism) -> str:
    """Render a packed mechanism using symbolic naming when available."""
    mechanism_id = int(mechanism.ck.mechanism)
    name = _render_symbol("mechanisms", mechanism_id)
    inspector = lookup_inspector(mechanism_id)
    if inspector is not None:
        detail = inspector(mechanism)
    else:
        detail = render_pointer(mechanism.pointer_arg)
    return (
        f"{name} (0x{mechanism_id:08x}, "
        f"{render_length(mechanism.length_arg)}, {detail})"
    )
