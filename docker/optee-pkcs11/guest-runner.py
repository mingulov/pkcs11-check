#!/usr/bin/env python3
"""Guest-side OP-TEE PKCS#11 runner for Docker validation."""

from __future__ import annotations

import os
import shlex
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from pkcs11_check.cli.app import main as pkcs11_cli_main
from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    get_slot_ids,
    login_user,
    logout_quietly,
    open_session,
)
from pkcs11_check.raw.recipes import init_pin, init_token
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKR_OK,
    CKU_SO,
)

DEFAULT_MODULE = "/usr/lib/libckteec.so"
DEFAULT_SLOT = "0"
DEFAULT_INTERFACE = "2.40"
DEFAULT_ARTIFACT_DIR = "/mnt/artifacts"
DEFAULT_SITE = "/mnt/pkcs11-check/site"
DEFAULT_TARGET = "pkcs11_check/testcases"
SOURCE_TESTCASE_PREFIX = "src/pkcs11_check/testcases"
DEFAULT_TOKEN_LABEL = "pkcs11-check"
DEFAULT_SO_PIN = "87654321"
DEFAULT_USER_PIN = "1234"


def _shlex_split(value: str | None) -> list[str]:
    if not value:
        return []
    return shlex.split(value)


def _artifact_path(env: Mapping[str, str], name: str) -> str:
    artifact_dir = Path(env.get("PKCS11_CHECK_ARTIFACT_DIR", DEFAULT_ARTIFACT_DIR))
    return str(artifact_dir / name)


def normalize_target(env: Mapping[str, str], target: str) -> str:
    source_prefix = SOURCE_TESTCASE_PREFIX.rstrip("/")
    normalized = target.rstrip("/")
    site = Path(env.get("PKCS11_CHECK_SITE", DEFAULT_SITE))
    if normalized == source_prefix:
        return str(site / DEFAULT_TARGET)
    testcase_prefix = f"{source_prefix}/"
    if target.startswith(testcase_prefix):
        return str(site / target.removeprefix("src/"))
    return target


def build_cli_args(env: Mapping[str, str]) -> list[str]:
    module = env.get("PKCS11_CHECK_MODULE", DEFAULT_MODULE)
    slot = env.get("PKCS11_CHECK_SLOT", DEFAULT_SLOT)
    interface = env.get("PKCS11_CHECK_INTERFACE", DEFAULT_INTERFACE)

    args = [
        "test",
        "--module",
        module,
        "--interface",
        interface,
        "--slot",
        slot,
        "--isolation",
        env.get("PKCS11_CHECK_ISOLATION", "auto"),
        "--output",
        "json",
        "--output-file",
        _artifact_path(env, "results.json"),
        "--state-file",
        _artifact_path(env, "state.json"),
        "--policy-file",
        _artifact_path(env, "policy.json"),
    ]

    timeout = env.get("PKCS11_CHECK_TIMEOUT")
    if timeout:
        args.extend(["--timeout", timeout])

    max_crashes = env.get("PKCS11_CHECK_MAX_CRASHES_PER_FILE")
    if max_crashes:
        args.extend(["--max-crashes-per-file", max_crashes])

    category = env.get("PKCS11_CHECK_CATEGORY")
    if category:
        args.extend(["--category", category])

    match = env.get("PKCS11_CHECK_MATCH")
    if match:
        args.extend(["--match", match])

    marker = env.get("PKCS11_CHECK_MARKER")
    if marker:
        args.extend(["--marker", marker])

    if env.get("PKCS11_CHECK_DESTRUCTIVE", "0") != "0":
        args.append("--destructive")

    args.extend(_shlex_split(env.get("PKCS11_CHECK_EXTRA_ARGS")))
    targets = _shlex_split(env.get("PKCS11_CHECK_TARGETS"))
    args.extend(normalize_target(env, target) for target in targets)
    if not targets:
        args.append(str(Path(env.get("PKCS11_CHECK_SITE", DEFAULT_SITE)) / DEFAULT_TARGET))
    return args


def render_serial_command(env: Mapping[str, str]) -> str:
    python_path = env.get("PKCS11_CHECK_SITE", DEFAULT_SITE)
    runner = env.get("PKCS11_CHECK_GUEST_RUNNER", "/mnt/pkcs11-check/guest-runner.py")
    return f"PYTHONPATH={shlex.quote(python_path)} python3 {shlex.quote(runner)}"


def initialize_token(env: Mapping[str, str]) -> None:
    module = env.get("PKCS11_CHECK_MODULE", DEFAULT_MODULE)
    slot_index = int(env.get("PKCS11_CHECK_SLOT", DEFAULT_SLOT))
    so_pin = env.get("PKCS11_CHECK_SO_PIN", DEFAULT_SO_PIN).encode()
    user_pin = env.get("PKCS11_CHECK_PIN", DEFAULT_USER_PIN).encode()
    token_label = env.get("PKCS11_CHECK_TOKEN_LABEL", DEFAULT_TOKEN_LABEL)

    raw = RawPKCS11.from_lib(module)
    session = 0
    try:
        expect_rv(raw.C_Initialize(None), CKR_OK)
        slots = get_slot_ids(raw, token_present=True)
        if slot_index >= len(slots):
            raise RuntimeError(f"slot index {slot_index} not present")
        slot_id = slots[slot_index]
        init_token(raw, slot_id, so_pin, token_label)
        session = open_session(raw, slot_id, int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
        login_user(raw, session, int(CKU_SO), so_pin)
        init_pin(raw, session, user_pin)
    finally:
        if session:
            logout_quietly(raw, session)
            close_session_quietly(raw, session)
        raw.C_Finalize(None)


def run_pkcs11_check_cli(env: Mapping[str, str], args: Sequence[str]) -> int:
    original_argv = sys.argv[:]
    original_pin = os.environ.get("P11TEST_PIN")
    had_pin = "P11TEST_PIN" in os.environ
    try:
        os.environ["P11TEST_PIN"] = env.get("PKCS11_CHECK_PIN", DEFAULT_USER_PIN)
        sys.argv = ["pkcs11-check", *args]
        try:
            pkcs11_cli_main()
        except SystemExit as exc:
            code = exc.code
            if code is None:
                return 0
            if isinstance(code, int):
                return code
            return 1
        return 0
    finally:
        sys.argv = original_argv
        if had_pin:
            os.environ["P11TEST_PIN"] = original_pin or ""
        else:
            os.environ.pop("P11TEST_PIN", None)


def main() -> int:
    env = os.environ
    artifact_dir = Path(env.get("PKCS11_CHECK_ARTIFACT_DIR", DEFAULT_ARTIFACT_DIR))
    artifact_dir.mkdir(parents=True, exist_ok=True)
    initialize_token(env)
    return run_pkcs11_check_cli(env, build_cli_args(env))


if __name__ == "__main__":
    raise SystemExit(main())
