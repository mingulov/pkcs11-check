# Commands Reference

## Standard commands (always use `uv run` prefix)

```bash
uv run pkcs11-check version              # check CLI works
uv run python -m pytest tests/test_python_source_syntax.py tests/test_security_subprocess_regressions.py tests/test_subprocess_result_policy.py  # fast syntax/generated-subprocess gate
uv run python -m pytest tests/           # run meta-tests
uv run ruff check src/ tests/            # lint
uv run ruff format src/ tests/           # format
uv run mypy src/                         # type check
```

> **Never** run bare `ruff`, `mypy`, or `pytest` — they are inside the uv venv.

The fast syntax/generated-subprocess gate covers ordinary Python syntax under
`src/` and `tests/`, plus representative dynamically generated child scripts
used by crash-survival tests. It does not replace provider runs; it prevents
broken local test code from being counted as provider evidence.

## Local builds

```bash
bash local-builds/build.sh kryoptic           # build token
bash local-builds/test.sh kryoptic            # run full suite (~5 min)
bash local-builds/test.sh kryoptic -k test_encrypt -v  # specific tests
bash local-builds/test.sh softhsm2            # system SoftHSM2
bash local-builds/reset.sh kryoptic           # reset token data
```

### Test profiles

```bash
bash local-builds/test.sh softhsm2 -m smoke                              # 27 tests, ~5s
bash local-builds/test.sh softhsm2 -m "not (wycheproof or acvp or cctv or stress or fuzz or slow)"  # ~2300 tests, ~30s
bash local-builds/test.sh softhsm2 -m "wycheproof or acvp or cctv"       # ~72K vectors only
bash local-builds/test.sh softhsm2                                        # full: ~75K tests, ~5min
```

### Fast vs full: long-running test cases (`slow`)

A small set of individually long-running cases (RSA-4096 ops/keygen, DSA/DH
parameter generation, AES large-multiblock, leak/churn/fuzz loops) carry
`@pytest.mark.slow`. They are *not* the high-count vector files (wycheproof/acvp
are thousands of fast cases and stay in the basic run). The `pkcs11-check test`
command has convenience flags:

```bash
uv run pkcs11-check test -m <module> --skip-slow   # basic/fast: -m "not slow"
uv run pkcs11-check test -m <module> --only-slow   # only the long-running cases
uv run pkcs11-check test -m <module>               # full: everything (default)
```

`--skip-slow`/`--only-slow` compose with `--marker` (e.g. `--marker acvp
--skip-slow` → `-m "(acvp) and (not slow)"`). The full profile still runs every
case — `slow` is a *selection* profile, never a way to hide a finding.

### Available providers

OpenSSL 4.0.0 preferred / 3.6.2 fallback, Kryoptic 1.5.1+PQC, SoftHSM2 2.7.0, OpenCryptoki 3.27.0, NSS softoken, pkcs11-mock 2.0.0, tpm2-pkcs11 1.10.0, BouncyHSM 2.1.1, wolfPKCS11 2.0.0-stable/master, corePKCS11 3.6.4, OP-TEE PKCS#11 4.10.0 QEMU target, swtpm 0.10.1, libtpms 0.10.2

### Worktree Kryoptic testing

Kryoptic requires OpenSSL 3.5.0+. In worktrees, use the pre-built module:

```bash
LD_LIBRARY_PATH="$PWD/local-builds/openssl/install/lib64" \
P11TEST_MODULE="$PWD/local-builds/kryoptic/lib/libkryoptic_pkcs11.so" \
P11TEST_PIN=1234 uv run python -m pytest src/pkcs11_check/testcases/<test_file>.py -v
```

## Test vector data

```bash
uv run pkcs11-check fetch-data --status      # show what's present/missing
uv run pkcs11-check fetch-data all           # fetch all sources (~800 MB)
uv run pkcs11-check fetch-data wycheproof    # fetch individual source
uv run pkcs11-check fetch-disabled           # fetch disabled-tests baseline
```

## Docker testing

```bash
bash docker/test.sh softhsm2
bash docker/test.sh softhsm2-generated-iv --match generated_iv -- src/pkcs11_check/testcases/test_aead.py
bash docker/test.sh opencryptoki
bash docker/test.sh wolfpkcs11 -- src/pkcs11_check/testcases/test_interface.py
bash docker/test.sh wolfpkcs11-master -- src/pkcs11_check/testcases/test_interface.py
bash docker/test.sh corepkcs11 -- src/pkcs11_check/testcases/test_interface.py
bash docker/test.sh corepkcs11-main -- src/pkcs11_check/testcases/test_interface.py
bash docker/test.sh optee-pkcs11 -- src/pkcs11_check/testcases/test_interface.py
bash docker/test.sh optee-pkcs11-master -- src/pkcs11_check/testcases/test_interface.py
bash docker/test.sh nss --timeout 30 -- src/pkcs11_check/testcases/test_interface.py
docker compose -f docker/docker-compose.test.yml run --build --rm test-softhsm2
docker compose -f docker/docker-compose.test.yml run --build --rm test-softhsm2-generated-iv
uv run python docker/test_pool.py --dry-run wolfpkcs11 wolfpkcs11-master corepkcs11 corepkcs11-main
uv run python docker/test_pool.py --dry-run --heavy
uv run python docker/test_pool.py --dry-run --all-heavy
uv run python docker/test_pool.py -j 3 optee-pkcs11:3
```

`optee-pkcs11` is a heavy/manual Docker target. The OP-TEE `qemu_v8` tree is
built into the Docker image once; runtime runs boot the prebuilt QEMU/kernel/rootfs
with fresh shared storage and artifacts, so changing shard counts does not
rebuild OP-TEE. It is callable by name and through `bash docker/test-all.sh
--heavy` or `uv run python docker/test_pool.py --heavy`, but it is intentionally
excluded from default Docker runs and ordinary `--all`. `optee-pkcs11-master`
tracks the OP-TEE manifest `master` branch and is included only by `--all-heavy`
or when named explicitly. For a full OP-TEE release pool run, `optee-pkcs11:3 -j
3` splits the test files into three independent QEMU containers. Set
`PKCS11_CHECK_OPTEE_USE_MAKE_CHECK=1` only when debugging the upstream OP-TEE
`make check` path itself.

See [docker-artifacts.md](docker-artifacts.md) for the runner contract and artifact layout.
