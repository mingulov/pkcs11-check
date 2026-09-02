"""Collection-safe PKCS#11 capability probing via a helper subprocess."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from pkcs11_check.core.crash_codes import (
    crash_detail_name,
    ctypes_access_violation_code,
    is_crash_returncode,
)
from pkcs11_check.core.loader import load_module
from pkcs11_check.core.process_observation import build_process_observation


@dataclass(frozen=True)
class CapabilityManifest:
    """Minimal capability snapshot used for safe skip decisions."""

    status: str
    module_path: str
    requested_interface: str
    interface_version: str | None
    slot_index: int
    slot_count: int | None
    mechanisms: list[str]
    functions: list[str] = field(default_factory=list)
    error: str | None = None
    mechanism_info: dict[str, dict[str, Any]] = field(default_factory=dict)
    process_observation: dict[str, Any] | None = None


def _mechanism_name(value: object) -> str:
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    if name is not None:
        return str(name)
    if isinstance(value, int):
        return f"0x{value:08x}"
    return str(value)


def probe_capabilities(module: Path, interface: str, slot: int) -> CapabilityManifest:
    """Probe module capabilities inside a short-lived helper process."""
    try:
        p11 = load_module(module, interface=interface)
        slots = p11.get_slots(token_present=True)
        if slot >= len(slots):
            msg = f"slot {slot} not found (token-present slots: {len(slots)})"
            raise IndexError(msg)
        raw_mechs = slots[slot].get_mechanisms()
        mechanisms = sorted(_mechanism_name(mech) for mech in raw_mechs)
        mech_info: dict[str, dict[str, Any]] = {}
        for mech in raw_mechs:
            info = slots[slot].get_mechanism_info(mech)
            mech_info[_mechanism_name(mech)] = {
                "flags": int(info.flags),
                "min_key_size": int(info.min_key_length),
                "max_key_size": int(info.max_key_length),
            }
        return CapabilityManifest(
            status="ok",
            module_path=str(module),
            requested_interface=interface,
            interface_version=p11.interface_version,
            slot_index=slot,
            slot_count=len(slots),
            mechanisms=mechanisms,
            functions=sorted(p11.raw.available_function_names()),
            mechanism_info=mech_info,
        )
    except Exception as exc:
        windows_status = ctypes_access_violation_code(exc)
        return CapabilityManifest(
            status="crashed" if windows_status is not None else "error",
            module_path=str(module),
            requested_interface=interface,
            interface_version=None,
            slot_index=slot,
            slot_count=None,
            mechanisms=[],
            error=(
                f"provider call crashed ({crash_detail_name(windows_status)}): {exc}"
                if windows_status is not None
                else f"{type(exc).__name__}: {exc}"
            ),
        )


def load_manifest(path: Path) -> CapabilityManifest:
    """Load a capability manifest from disk."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return CapabilityManifest(**raw)


def save_manifest(path: Path, manifest: CapabilityManifest) -> None:
    """Persist a capability manifest as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(manifest), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_preflight_subprocess(
    module: Path,
    *,
    interface: str,
    slot: int,
    timeout: int,
    output_path: Path,
) -> CapabilityManifest:
    """Probe capabilities in a fresh Python subprocess and load the manifest."""
    cmd = [
        sys.executable,
        "-m",
        "pkcs11_check.core.preflight",
        "--module",
        str(module),
        "--interface",
        interface,
        "--slot",
        str(slot),
        "--output",
        str(output_path),
    ]
    process = subprocess.Popen(cmd)
    try:
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait()
            return CapabilityManifest(
                status="timeout",
                module_path=str(module),
                requested_interface=interface,
                interface_version=None,
                slot_index=slot,
                slot_count=None,
                mechanisms=[],
                error=f"preflight timed out after {timeout}s",
                process_observation=build_process_observation(
                    str(module), "preflight", 0, returncode, timed_out=True
                ),
            )
    except BaseException:
        try:
            process.kill()
        except BaseException:
            pass
        else:
            try:
                process.wait()
            except BaseException:
                pass
        raise

    if returncode == 0 and output_path.exists():
        return load_manifest(output_path)

    if is_crash_returncode(returncode):
        return CapabilityManifest(
            status="crashed",
            module_path=str(module),
            requested_interface=interface,
            interface_version=None,
            slot_index=slot,
            slot_count=None,
            mechanisms=[],
            error=f"preflight crashed ({crash_detail_name(returncode)})",
            process_observation=build_process_observation(str(module), "preflight", 0, returncode),
        )

    return CapabilityManifest(
        status="error",
        module_path=str(module),
        requested_interface=interface,
        interface_version=None,
        slot_index=slot,
        slot_count=None,
        mechanisms=[],
        error=f"preflight exited with code {returncode}",
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write a PKCS#11 capability manifest")
    parser.add_argument("--module", required=True)
    parser.add_argument("--interface", default="auto")
    parser.add_argument("--slot", type=int, default=0)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    """CLI entry point for the helper subprocess."""
    args = _parse_args()
    manifest = probe_capabilities(
        Path(args.module),
        interface=args.interface,
        slot=args.slot,
    )
    save_manifest(Path(args.output), manifest)


if __name__ == "__main__":
    main()
