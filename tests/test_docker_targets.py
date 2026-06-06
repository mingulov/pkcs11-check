from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_softhsm_generated_iv_compose_service_is_separate_target() -> None:
    compose = (ROOT / "docker/docker-compose.test.yml").read_text()

    assert "test-softhsm2-generated-iv:" in compose
    assert "dockerfile: docker/softhsm2/Dockerfile.main" in compose
    assert 'SOFTHSM2_APPLY_GENERATED_IV_PATCH: "1"' in compose
    assert "PKCS11_CHECK_ARTIFACT_DIR: /artifacts/softhsm2-generated-iv" in compose
    assert 'PKCS11_CHECK_PIN: "1234"' in compose


def test_softhsm_generated_iv_dockerfile_applies_local_patch() -> None:
    dockerfile = (ROOT / "docker/softhsm2/Dockerfile.generated-iv").read_text()

    assert "git clone --depth 1 --branch 2.7.0" in dockerfile
    assert "COPY docker/softhsm2/patches/" in dockerfile
    assert "git apply --unidiff-zero" in dockerfile
    assert "0001-simulate-aes-gcm-generated-iv.patch" in dockerfile


def test_softhsm_generated_iv_patch_is_newly_authored_for_simulator() -> None:
    patch = (ROOT / "docker/softhsm2/patches/0001-simulate-aes-gcm-generated-iv.patch").read_text()

    assert "Subject: [PATCH] SoftHSM2: simulate AES-GCM generated IV writeback" in patch
    assert "SoftHSM generated-IV simulator" in patch
    assert "ulIvLen == 0" in patch
    assert "ulIvBits == 0" in patch
    assert "CKR_MECHANISM_PARAM_INVALID" in patch


def test_tpm2_background_daemon_does_not_hold_artifact_pipe() -> None:
    script = (ROOT / "docker/tpm2-pkcs11/run-tpm2.sh").read_text()

    assert "swtpm_pid=$!" in script
    assert "--allow-root >/tmp/tpm2-abrmd.log 2>&1 &" in script
    assert "tpm2_abrmd_pid=$!" in script
    assert 'kill -0 "$tpm2_abrmd_pid"' in script


def test_docker_provider_commands_do_not_mask_pkcs11_check_failures() -> None:
    paths = sorted((ROOT / "docker").glob("**/Dockerfile*"))
    paths += sorted((ROOT / "docker").glob("**/*.sh"))

    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in paths
        if any(
            pattern in path.read_text()
            for pattern in (
                "run-pkcs11-check.sh || true",
                "if ! bash /app/docker/run-pkcs11-check.sh",
            )
        )
    ]

    assert offenders == []


def test_docker_test_uses_fetched_user_data_cache_when_repo_data_is_empty() -> None:
    compose = (ROOT / "docker/docker-compose.test.yml").read_text()
    script = (ROOT / "docker/test.sh").read_text()
    runner = (ROOT / "docker/run-pkcs11-check.sh").read_text()

    assert "${PKCS11_CHECK_HOST_DATA_DIR:-../data}:/app/data:ro" in compose
    assert "../data/disabled-tests.txt:/app/disabled-tests.txt:ro" in compose
    assert "P11TEST_DISABLED_TESTS_FILE" in runner
    assert "/app/disabled-tests.txt" in runner
    assert "PKCS11_CHECK_HOST_DATA_DIR" in script
    assert "XDG_DATA_HOME" in script
    assert "pkcs11-check/data" in script
    assert "Using fetched test vector data:" in script


def test_qryptotoken_is_not_an_active_docker_provider() -> None:
    script = (ROOT / "docker/test-all.sh").read_text()
    compose = (ROOT / "docker/docker-compose.test.yml").read_text()

    default_block = script.split("DEFAULT_PROVIDERS=(")[1].split(")", maxsplit=1)[0]
    all_block = script.split("ALL_PROVIDERS=(")[1].split(")", maxsplit=1)[0]

    assert "qryptotoken" not in default_block
    assert "qryptotoken" not in all_block
    assert "test-qryptotoken" not in compose
    assert not (ROOT / "docker/qryptotoken").exists()


def test_default_docker_matrix_uses_tagged_nss_source_not_tip() -> None:
    script = (ROOT / "docker/test-all.sh").read_text()

    default_block = script.split("DEFAULT_PROVIDERS=(")[1].split(")", maxsplit=1)[0]

    assert "nss-pqc" in default_block
    assert "nss-main" not in default_block


def test_nss_source_manifest_distinguishes_packages_tags_and_tip() -> None:
    manifest = (ROOT / "docker/provider-sources.toml").read_text()

    assert "[sources.nss_tip]" not in manifest
    assert "[sources.nss_main_tip]" in manifest
    assert "[sources.nspr_main_tip]" in manifest

    nss_block = manifest.split("[targets.nss]")[1].split("[targets.", maxsplit=1)[0]
    nss_pqc_block = manifest.split("[targets.nss_pqc]")[1].split("[targets.", maxsplit=1)[0]
    nss_main_block = manifest.split("[targets.nss_main]")[1].split("[targets.", maxsplit=1)[0]

    assert 'package_source = "nss_fedora_44"' in nss_block
    assert 'package_tag = "nss-3.123.1-1.fc44.x86_64"' in nss_block
    assert 'result_tag = "Fedora 44 nss-3.123.1-1.fc44 package"' in nss_block
    assert "nss_main_tip" not in nss_block

    assert 'release_source = "nss_3_124_rtm"' in nss_pqc_block
    assert 'supporting_source = "nspr_4_39_rtm"' in nss_pqc_block
    assert 'result_tag = "NSS_3_124_RTM / NSPR_4_39_RTM"' in nss_pqc_block

    assert 'branch_source = "nss_main_tip"' in nss_main_block
    assert 'supporting_source = "nspr_main_tip"' in nss_main_block
    assert 'result_tag = "Mercurial tip comparison only"' in nss_main_block


def test_wolfpkcs11_compose_services_cover_release_and_master_targets() -> None:
    compose = (ROOT / "docker/docker-compose.test.yml").read_text()

    assert "test-wolfpkcs11:" in compose
    assert "test-wolfpkcs11-master:" in compose

    release_block = compose.split("test-wolfpkcs11:")[1].split("test-", maxsplit=1)[0]
    master_block = compose.split("test-wolfpkcs11-master:")[1].split("test-", maxsplit=1)[0]

    assert "dockerfile: docker/wolfpkcs11/Dockerfile" in release_block
    assert 'WOLFSSL_REF: "v5.9.1-stable"' in release_block
    assert 'WOLFPKCS11_REF: "v2.0.0-stable"' in release_block
    assert 'WOLFPKCS11_ENABLE_PQC: "0"' in release_block
    assert "PKCS11_CHECK_ARTIFACT_DIR: /artifacts/wolfpkcs11" in release_block
    assert 'PKCS11_CHECK_SLOT: "0"' in release_block

    assert "dockerfile: docker/wolfpkcs11/Dockerfile" in master_block
    assert 'WOLFSSL_REF: "master"' in master_block
    assert 'WOLFPKCS11_REF: "master"' in master_block
    assert 'WOLFPKCS11_ENABLE_PQC: "1"' in master_block
    assert "PKCS11_CHECK_ARTIFACT_DIR: /artifacts/wolfpkcs11-master" in master_block
    assert 'PKCS11_CHECK_INTERFACE: "3.2"' in master_block
    assert 'PKCS11_CHECK_SLOT: "0"' in master_block


def test_wolfpkcs11_dockerfile_enables_optional_mechanism_families() -> None:
    dockerfile = (ROOT / "docker/wolfpkcs11/Dockerfile").read_text()

    for flag in (
        "--enable-aescfb",
        "--enable-aesccm",
        "--enable-aesecb",
        "--enable-aesctr",
        "--enable-aescts",
        "--enable-aescmac",
        "--enable-aeskeywrap",
        "--enable-pbkdf2",
        "--enable-pkcs11v32",
        "--enable-mldsa",
        "--enable-mlkem",
    ):
        assert flag in dockerfile

    assert "examples/init_token" in dockerfile
    assert "WOLFPKCS11_TOKEN_PATH" in dockerfile


def test_wolfpkcs11_targets_are_tracked_but_not_default_matrix() -> None:
    script = (ROOT / "docker/test-all.sh").read_text()

    default_block = script.split("DEFAULT_PROVIDERS=(")[1].split(")", maxsplit=1)[0]
    all_block = script.split("ALL_PROVIDERS=(")[1].split(")", maxsplit=1)[0]

    assert "wolfpkcs11" not in default_block
    assert "wolfpkcs11-master" not in default_block
    assert "wolfpkcs11" in all_block
    assert "wolfpkcs11-master" in all_block


def test_wolfpkcs11_source_manifest_tracks_release_and_master_refs() -> None:
    manifest = tomllib.loads((ROOT / "docker/provider-sources.toml").read_text())

    assert manifest["sources"]["wolfssl_release"]["selector"] == "v5.9.1-stable"
    assert manifest["sources"]["wolfssl_release"]["kind"] == "git_tag"
    assert manifest["sources"]["wolfssl_master"]["selector"] == "master"
    assert manifest["sources"]["wolfssl_master"]["kind"] == "git_branch"
    assert manifest["sources"]["wolfpkcs11_release"]["selector"] == "v2.0.0-stable"
    assert manifest["sources"]["wolfpkcs11_release"]["kind"] == "git_tag"
    assert manifest["sources"]["wolfpkcs11_master"]["selector"] == "master"
    assert manifest["sources"]["wolfpkcs11_master"]["kind"] == "git_branch"

    release_target = manifest["targets"]["wolfpkcs11"]
    assert release_target["service"] == "test-wolfpkcs11"
    assert release_target["release_source"] == "wolfpkcs11_release"
    assert release_target["branch_source"] == "wolfpkcs11_master"
    assert release_target["supporting_source"] == "wolfssl_release"

    master_target = manifest["targets"]["wolfpkcs11_master"]
    assert master_target["service"] == "test-wolfpkcs11-master"
    assert master_target["branch_source"] == "wolfpkcs11_master"
    assert master_target["supporting_source"] == "wolfssl_master"
