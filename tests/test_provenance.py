from __future__ import annotations

from pathlib import Path

from pkcs11_check import provenance as P


def test_framework_version_prefers_env() -> None:
    got = P.framework_version(
        env={"PKCS11_CHECK_FRAMEWORK_VERSION": "v0.1.6-42-gabc123-dirty"},
        repo_root=None,
    )
    assert got == {"version": "v0.1.6-42-gabc123-dirty", "dirty": True, "source": "env"}


def test_framework_version_uses_git_describe_when_repo(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    calls: list[list[str]] = []

    def fake_git(args: list[str], cwd: Path) -> str | None:
        calls.append(args)
        return "v0.1.6-5-gdeadbee"

    got = P.framework_version(env={}, repo_root=tmp_path, run_git=fake_git)
    assert got == {"version": "v0.1.6-5-gdeadbee", "dirty": False, "source": "git-describe"}
    assert calls == [["describe", "--tags", "--always", "--dirty"]]


def test_framework_version_falls_back_to_package_version() -> None:
    from pkcs11_check import __version__

    got = P.framework_version(env={}, repo_root=None)
    assert got == {"version": __version__, "dirty": False, "source": "package"}


def test_read_build_provenance_absent_or_malformed(tmp_path: Path) -> None:
    assert P.read_build_provenance(tmp_path / "nope.json") == {}
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert P.read_build_provenance(bad) == {}


def test_read_build_provenance_loads_dict(tmp_path: Path) -> None:
    good = tmp_path / "build-provenance.json"
    good.write_text('{"provider": {"name": "softhsm2"}}')
    assert P.read_build_provenance(good) == {"provider": {"name": "softhsm2"}}
