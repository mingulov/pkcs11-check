from __future__ import annotations

from pathlib import Path

from pkcs11_check import provenance as P


def test_recompute_manifest_pin_corrects_stale_match() -> None:
    # The build-baked matches_manifest_pin is a Docker-cache snapshot; recompute it from
    # the authoritative baked commit + the live manifest (the release builds baked a stale
    # `false` even though the current manifest matches - 2026-06-29 finding F2).
    results = {
        "provenance": {
            "provider": {
                "commit": "abc123",
                "manifest_key": "softhsm2_release",
                "matches_manifest_pin": False,
            }
        }
    }
    manifest = {"sources": {"softhsm2_release": {"commit": "abc123"}}}
    assert P.recompute_manifest_pin(results, manifest) is True
    assert results["provenance"]["provider"]["matches_manifest_pin"] is True


def test_recompute_manifest_pin_reports_genuine_drift() -> None:
    # A real drift (built commit != manifest pin, e.g. kmsp11) stays correctly false.
    results = {"provenance": {"provider": {"commit": "e01c9b", "manifest_key": "k"}}}
    manifest = {"sources": {"k": {"commit": "0ac563"}}}
    assert P.recompute_manifest_pin(results, manifest) is True
    assert results["provenance"]["provider"]["matches_manifest_pin"] is False


def test_recompute_manifest_pin_noop_without_key_or_pin() -> None:
    # No manifest_key baked, or no pin in the manifest -> leave the field untouched.
    results = {"provenance": {"provider": {"commit": "abc"}}}
    assert P.recompute_manifest_pin(results, {"sources": {}}) is False
    assert "matches_manifest_pin" not in results["provenance"]["provider"]


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


def test_test_data_provenance_records_manifest_and_presence(tmp_path: Path) -> None:
    (tmp_path / "wycheproof").mkdir()  # present
    manifest = {
        "wycheproof": {"repo": "C2SP/wycheproof", "commit": "ee7b4f", "archive_sha256": "abc"},
        "acvp": {"repo": "usnistgov/ACVP-Server", "commit": "1234", "archive_sha256": "def"},
        "observed_at": "2026-06-27T00:00:00Z",  # non-package scalar - must be skipped
    }
    got = P.test_data_provenance(manifest, tmp_path)
    assert got == [
        {
            "name": "wycheproof",
            "repo": "C2SP/wycheproof",
            "commit": "ee7b4f",
            "archive_sha256": "abc",
            "present": True,
        },
        {
            "name": "acvp",
            "repo": "usnistgov/ACVP-Server",
            "commit": "1234",
            "archive_sha256": "def",
            "present": False,
        },
    ]


def test_assemble_merges_all_sources(tmp_path: Path) -> None:
    build = tmp_path / "build-provenance.json"
    build.write_text(
        '{"provider": {"name": "softhsm2", "commit": "8d4f1a2"},'
        ' "crypto_backend": {"name": "openssl", "version": "3.6.3"},'
        ' "extra": {"note": "custom"}}'
    )
    (tmp_path / "wycheproof").mkdir()
    manifest = {
        "wycheproof": {"repo": "C2SP/wycheproof", "commit": "ee7b4f", "archive_sha256": "abc"}
    }
    got = P.assemble(
        env={"PKCS11_CHECK_FRAMEWORK_VERSION": "v0.1.6-1-gabc"},
        repo_root=None,
        build_file=build,
        data_manifest=manifest,
        data_dir=tmp_path,
        environment={"interface": "3.0", "slots": 1, "mechanisms": 84},
    )
    assert got["framework"]["version"] == "v0.1.6-1-gabc"
    assert got["provider"] == {"name": "softhsm2", "commit": "8d4f1a2"}
    assert got["crypto_backend"] == {"name": "openssl", "version": "3.6.3"}
    assert got["test_data"][0]["name"] == "wycheproof"
    assert got["environment"] == {"interface": "3.0", "slots": 1, "mechanisms": 84}
    assert got["extra"] == {"note": "custom"}


def test_assemble_omits_absent_sources(tmp_path: Path) -> None:
    got = P.assemble(
        env={"PKCS11_CHECK_FRAMEWORK_VERSION": "v1"},
        repo_root=None,
        build_file=tmp_path / "absent.json",
        data_manifest={},
        data_dir=tmp_path,
        environment=None,
    )
    assert set(got) == {"framework"}  # only framework present; no fabricated keys
