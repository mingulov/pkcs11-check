# Commands Reference

## Standard commands (always use `uv run` prefix)

```bash
uv run pkcs11-check version              # check CLI works
uv run python -m pytest tests/           # run meta-tests
uv run ruff check src/ tests/            # lint
uv run ruff format src/ tests/           # format
uv run mypy src/                         # type check
```

> **Never** run bare `ruff`, `mypy`, or `pytest` — they are inside the uv venv.

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

### Available providers

OpenSSL 4.0.0 preferred / 3.6.2 fallback, Kryoptic 1.5.0+PQC, SoftHSM2 2.7.0, OpenCryptoki 3.27.0, NSS softoken, pkcs11-mock 2.0.0, tpm2-pkcs11 1.10.0, BouncyHSM 2.1.0, swtpm 0.10.1, libtpms 0.10.2

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
bash docker/test.sh nss --timeout 30 -- src/pkcs11_check/testcases/test_interface.py
docker compose -f docker/docker-compose.test.yml run --build --rm test-softhsm2
docker compose -f docker/docker-compose.test.yml run --build --rm test-softhsm2-generated-iv
```

See [docker-artifacts.md](docker-artifacts.md) for the runner contract and artifact layout.
