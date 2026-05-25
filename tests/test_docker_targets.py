from __future__ import annotations

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


def test_qryptotoken_is_not_in_default_or_all_provider_matrix() -> None:
    script = (ROOT / "docker/test-all.sh").read_text()

    default_block = script.split("DEFAULT_PROVIDERS=(")[1].split(")", maxsplit=1)[0]
    all_block = script.split("ALL_PROVIDERS=(")[1].split(")", maxsplit=1)[0]

    assert "qryptotoken" not in default_block
    assert "qryptotoken" not in all_block


def test_qryptotoken_build_failure_is_recorded_as_artifact() -> None:
    dockerfile = (ROOT / "docker/qryptotoken/Dockerfile").read_text()
    script = (ROOT / "docker/qryptotoken/run-qryptotoken.sh").read_text()

    assert 'ARG QRYPTOTOKEN_REF="v0.4.1"' in dockerfile
    assert "qryptotoken build failed with exit code" in dockerfile
    assert "/tmp/qryptotoken_build_failed" in dockerfile
    assert "build-status.json" in script
    assert '"status": "build_failed"' in script
