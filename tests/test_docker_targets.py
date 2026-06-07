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


def test_optee_artifact_gate_does_not_require_adaptive_policy_file() -> None:
    script = (ROOT / "docker/optee-pkcs11/run-optee-pkcs11.sh").read_text()

    required_loop = script.split("for required in ", maxsplit=1)[1].split(";", maxsplit=1)[0]

    assert "results.json" in required_loop
    assert "state.json" in required_loop
    assert "quality.json" in required_loop
    assert "report.jsonl" in required_loop
    assert "serial0.log" in required_loop
    assert "serial1.log" in required_loop
    assert "policy.json" not in required_loop


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


def test_corepkcs11_compose_service_uses_latest_release_tag() -> None:
    compose = (ROOT / "docker/docker-compose.test.yml").read_text()

    assert "test-corepkcs11:" in compose

    block = compose.split("test-corepkcs11:")[1].split("test-", maxsplit=1)[0]

    assert "dockerfile: docker/corepkcs11/Dockerfile" in block
    assert 'COREPKCS11_REF: "v3.6.4"' in block
    assert "PKCS11_CHECK_ARTIFACT_DIR: /artifacts/corepkcs11" in block
    assert "PKCS11_CHECK_MODULE: /usr/local/lib/libcorepkcs11_adapter.so" in block
    assert 'PKCS11_CHECK_SLOT: "0"' in block
    assert 'PKCS11_CHECK_PIN: "0000"' in block


def test_corepkcs11_dockerfile_builds_release_with_adapter_and_max_config() -> None:
    dockerfile_path = ROOT / "docker/corepkcs11/Dockerfile"

    assert dockerfile_path.exists()

    dockerfile = dockerfile_path.read_text()

    assert 'ARG COREPKCS11_REF="v3.6.4"' in dockerfile
    assert "https://github.com/FreeRTOS/corePKCS11.git" in dockerfile
    assert "-DSTANDALONE_TEST_BUILD_UNIX=ON" in dockerfile
    assert "-DBUILD_SHARED_LIBS=ON" in dockerfile
    assert "core_pkcs11_config.h" in dockerfile
    assert "libcore_pkcs.so" in dockerfile
    assert "libcorepkcs11_adapter.so" in dockerfile
    assert "COREPKCS11_REAL_MODULE=/usr/local/lib/libcore_pkcs.so" in dockerfile

    config = (ROOT / "docker/corepkcs11/core_pkcs11_config.h").read_text()
    assert "pkcs11configMAX_NUM_OBJECTS" in config
    assert "( ( CK_ULONG ) 128 )" in config
    assert "pkcs11configMAX_SESSIONS" in config
    assert "( ( CK_ULONG ) 32 )" in config
    assert "pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED" in config
    assert "pkcs11configSUPPRESS_ECDSA_MECHANISM" not in config


def test_corepkcs11_adapter_exposes_upstream_and_extra_operational_mechanisms() -> None:
    adapter_path = ROOT / "docker/corepkcs11/corepkcs11_adapter.c"

    assert adapter_path.exists()

    adapter = adapter_path.read_text()

    assert "dlopen(" in adapter
    assert "dlsym(" in adapter
    assert '"C_GetFunctionList"' in adapter
    assert "adapter_funcs = *core_funcs" in adapter
    assert "core_funcs->C_GetMechanismInfo" in adapter
    assert "adapter_get_mechanism_list" in adapter
    assert "adapter_get_mechanism_info" in adapter
    assert "adapter_digest" in adapter
    assert "C_DigestUpdate" in adapter
    assert "C_DigestFinal" in adapter

    for mechanism in (
        "CKM_RSA_PKCS",
        "CKM_RSA_X_509",
        "CKM_ECDSA",
        "CKM_EC_KEY_PAIR_GEN",
        "CKM_SHA256",
        "CKM_SHA256_HMAC",
        "CKM_AES_CMAC",
    ):
        assert mechanism in adapter


def test_corepkcs11_adapter_normalizes_only_upstream_backed_rsa_pkcs_verify() -> None:
    adapter = (ROOT / "docker/corepkcs11/corepkcs11_adapter.c").read_text()

    assert "normalize_core_mechanism_info" in adapter
    assert "CKM_RSA_PKCS" in adapter
    assert "info->flags |= CKF_VERIFY" in adapter
    assert "info->flags |= CKF_ENCRYPT" not in adapter
    assert "info->flags |= CKF_DECRYPT" not in adapter
    assert "info->flags |= CKF_WRAP" not in adapter
    assert "info->flags |= CKF_UNWRAP" not in adapter


def test_corepkcs11_targets_are_tracked_but_not_default_matrix() -> None:
    script = (ROOT / "docker/test-all.sh").read_text()

    default_block = script.split("DEFAULT_PROVIDERS=(")[1].split(")", maxsplit=1)[0]
    all_block = script.split("ALL_PROVIDERS=(")[1].split(")", maxsplit=1)[0]

    assert "corepkcs11" not in default_block
    assert "corepkcs11" in all_block


def test_corepkcs11_source_manifest_tracks_latest_release() -> None:
    manifest = tomllib.loads((ROOT / "docker/provider-sources.toml").read_text())

    source = manifest["sources"]["corepkcs11_release"]
    assert source["kind"] == "git_tag"
    assert source["repo"] == "https://github.com/FreeRTOS/corePKCS11.git"
    assert source["selector"] == "v3.6.4"
    assert source["commit"] == "ccc78afee1716436cca832dd3d9388ead2ba05b0"

    target = manifest["targets"]["corepkcs11"]
    assert target["service"] == "test-corepkcs11"
    assert target["release_source"] == "corepkcs11_release"
    assert target["result_tag"] == "corePKCS11 v3.6.4 MbedTLS software mock"


def test_optee_pkcs11_compose_service_is_heavy_qemu_target() -> None:
    compose = (ROOT / "docker/docker-compose.test.yml").read_text()

    assert "test-optee-pkcs11:" in compose

    block = compose.split("test-optee-pkcs11:")[1].split("test-", maxsplit=1)[0]

    assert "dockerfile: docker/optee-pkcs11/Dockerfile" in block
    assert 'OPTEE_REF: "4.10.0"' in block
    assert "PKCS11_CHECK_ARTIFACT_DIR: /artifacts/optee-pkcs11" in block
    assert "PKCS11_CHECK_MODULE: /usr/lib/libckteec.so" in block
    assert 'PKCS11_CHECK_INTERFACE: "2.40"' in block
    assert 'PKCS11_CHECK_SLOT: "0"' in block
    assert 'PKCS11_CHECK_PIN: "1234"' in block


def test_optee_pkcs11_dockerfile_builds_release_qemu_target() -> None:
    dockerfile_path = ROOT / "docker/optee-pkcs11/Dockerfile"

    assert dockerfile_path.exists()

    dockerfile = dockerfile_path.read_text()

    assert 'ARG OPTEE_REF="4.10.0"' in dockerfile
    assert dockerfile.count('-j"$(nproc)"') >= 2
    assert "\n    repo \\\n" not in dockerfile
    assert "libgnutls28-dev" in dockerfile
    assert "storage.googleapis.com/git-repo-downloads/repo" in dockerfile
    assert "https://github.com/OP-TEE/manifest.git" in dockerfile
    assert "-m qemu_v8.xml" in dockerfile
    assert 'CFG_PKCS11_TA=y' in dockerfile
    assert 'CFG_PKCS11_TA_ALLOW_DIGEST_KEY=y' in dockerfile
    assert 'CFG_PKCS11_TA_AUTH_TEE_IDENTITY=y' in dockerfile
    assert 'CFG_PKCS11_TA_CHECK_VALUE_ATTRIBUTE=y' in dockerfile
    assert 'CFG_PKCS11_TA_RSA_X_509=y' in dockerfile
    assert 'QEMU_VIRTFS_ENABLE=y' in dockerfile
    assert 'QEMU_PSS_ENABLE=y' in dockerfile
    assert 'RUST_ENABLE=n' in dockerfile
    assert 'BR2_PACKAGE_PYTHON3=y' in dockerfile
    assert 'BR2_PACKAGE_PYTHON3_PYEXPAT=y' in dockerfile
    assert 'BR2_PACKAGE_PYTHON3_ZLIB=y' in dockerfile
    assert 'BR2_PACKAGE_OPENSC=y' in dockerfile
    assert "COPY LICENSE-APACHE LICENSE-MIT THIRD_PARTY_LICENSES.md ./" in dockerfile
    assert "COPY src/ src/" in dockerfile
    assert "build-guest-site.sh /opt/pkcs11-check-site" in dockerfile
    assert dockerfile.index("COPY src/ src/") < dockerfile.index(
        "build-guest-site.sh /opt/pkcs11-check-site"
    )
    assert "run-optee-pkcs11.sh" in dockerfile


def test_optee_pkcs11_target_is_heavy_and_not_regular_all() -> None:
    script = (ROOT / "docker/test-all.sh").read_text()

    default_block = script.split("DEFAULT_PROVIDERS=(")[1].split(")", maxsplit=1)[0]
    all_block = script.split("ALL_PROVIDERS=(")[1].split(")", maxsplit=1)[0]
    heavy_block = script.split("HEAVY_PROVIDERS=(")[1].split(")", maxsplit=1)[0]

    assert "optee-pkcs11" not in default_block
    assert "optee-pkcs11" not in all_block
    assert "optee-pkcs11" in heavy_block
    assert "--heavy" in script
    assert "--all-heavy" in script


def test_optee_pkcs11_runtime_keeps_upstream_rust_examples_disabled() -> None:
    script = (ROOT / "docker/optee-pkcs11/run-optee-pkcs11.sh").read_text()

    assert "RUST_ENABLE=n" in script


def test_optee_pkcs11_runtime_reuses_build_feature_flags() -> None:
    script = (ROOT / "docker/optee-pkcs11/run-optee-pkcs11.sh").read_text()

    assert "optee_make_args=(" in script
    for flag in (
        "CFG_PKCS11_TA=y",
        "CFG_PKCS11_TA_ALLOW_DIGEST_KEY=y",
        "CFG_PKCS11_TA_AUTH_TEE_IDENTITY=y",
        "CFG_PKCS11_TA_CHECK_VALUE_ATTRIBUTE=y",
        "CFG_PKCS11_TA_RSA_X_509=y",
        "CFG_PKCS11_TA_HEAP_SIZE=(128 * 1024)",
        "QEMU_VIRTFS_ENABLE=y",
        "QEMU_PSS_ENABLE=y",
        "RUST_ENABLE=n",
        "BR2_PACKAGE_PYTHON3=y",
        "BR2_PACKAGE_PYTHON3_PYEXPAT=y",
        "BR2_PACKAGE_PYTHON3_ZLIB=y",
        "BR2_PACKAGE_OPENSC=y",
    ):
        assert flag in script
    assert '"${optee_make_args[@]}"' in script


def test_optee_pkcs11_expect_matches_plain_root_prompt() -> None:
    script = (ROOT / "docker/optee-pkcs11/optee-pkcs11.exp").read_text()

    assert "-re {# } { return }" in script
    assert "-re {/# }" not in script
    assert "pidof tee-supplicant" in script
    assert "pgrep tee-supplicant" not in script
    assert 'pkcs11-tool --module "\\"\\$PKCS11_CHECK_MODULE\\""' not in script
    assert 'pkcs11-tool --module \\"\\$PKCS11_CHECK_MODULE\\"' in script
    assert "OPTEE_PKCS11_EXIT:\\$?" in script
    assert "OPTEE_PKCS11_EXIT:\\\\$?" not in script


def test_optee_pkcs11_source_manifest_tracks_release_refs() -> None:
    manifest = tomllib.loads((ROOT / "docker/provider-sources.toml").read_text())

    assert manifest["sources"]["optee_manifest_release"]["selector"] == "4.10.0"
    assert manifest["sources"]["optee_manifest_release"]["kind"] == "git_tag"
    assert manifest["sources"]["optee_os_release"]["selector"] == "4.10.0"
    assert manifest["sources"]["optee_client_release"]["selector"] == "4.10.0"
    assert manifest["sources"]["optee_build_release"]["selector"] == "4.10.0"
    assert manifest["sources"]["optee_buildroot_manifest_pin"]["selector"] == "2025.05"
    assert manifest["sources"]["optee_qemu_manifest_pin"]["selector"] == "v10.0.0"

    target = manifest["targets"]["optee_pkcs11"]
    assert target["service"] == "test-optee-pkcs11"
    assert target["release_source"] == "optee_manifest_release"
    assert "optee_os_release" in target["supporting_sources"]
    assert "optee_client_release" in target["supporting_sources"]
    assert (
        target["build_evidence"]
        == "2026-06-07 bash docker/test.sh optee-pkcs11 --timeout 120 -- "
        "src/pkcs11_check/testcases/test_interface.py passed"
    )
