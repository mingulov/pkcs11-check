"""Tests for pkcs11-check state command."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from pkcs11_check.cli.app import app

runner = CliRunner()


def test_state_command_renders_state_file(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text(
        """{
  "fingerprint": "abc123",
  "units": ["a.py", "b.py"],
  "results": [
    {"target": "a.py", "status": "passed", "returncode": 0, "duration_s": 0.1},
    {"target": "b.py", "status": "crashed", "returncode": -11, "duration_s": 1.4}
  ]
}
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["state", str(state_file)])

    assert result.exit_code == 0
    assert "State File" in result.output
    assert "Status Summary" in result.output
    assert "crashed" in result.output


def test_state_command_renders_policy_file(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        """{
  "backends": {
    "deadbeef": {
      "promoted_files": ["/tmp/test_demo.py"],
      "crashed_tests": ["/tmp/test_demo.py::test_case"]
    }
  }
}
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["state", str(policy_file)])

    assert result.exit_code == 0
    assert "Policy File" in result.output
    assert "Backend Policies" in result.output


def test_state_command_json_output_echoes_file(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text('{"fingerprint":"abc123","units":[],"results":[]}\n', encoding="utf-8")

    result = runner.invoke(app, ["state", "--output", "json", str(state_file)])

    assert result.exit_code == 0
    assert '"fingerprint": "abc123"' in result.output
