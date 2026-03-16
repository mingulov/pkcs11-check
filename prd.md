### **Product Requirements Document (PRD)**  
**Product Name:** p11test  
**Version:** 0.1.0 (MVP)  
**Date:** March 2026  
**Status:** Ready for implementation  

#### 1. Executive Summary
**p11test** is a modern, CLI-first PKCS#11 test suite (that also installs as a pytest plugin).  
It is the first tool that:
- Automatically negotiates and **forces** any PKCS#11 interface (2.40 / 3.0 / 3.2)
- **Survives segfaults, crashes, and hangs** in the loaded .so / .dll module (the tester itself never dies)
- Controls timeouts, runs multiple parallel sessions, and lets you cancel/close them on demand
- Is fully configurable (TOML + CLI + env vars)
- Works on both 32-bit and 64-bit systems

It builds on the still-maintained `python-pkcs11` library and adds the robustness and full v3.x coverage that was missing from every existing tool.

#### 2. Goals
- Give module/HSM developers, vendors, p11-kit/OpenSC maintainers, and security teams a safe, reliable way to test across all PKCS#11 versions.
- Guarantee the tester never crashes because of a buggy provider.
- Guarantee v3.2 interface is actually used when requested.
- Integrate seamlessly into pytest-based CI while also offering a clean standalone CLI.
- Become the de-facto standard test tool for PKCS#11 in the open-source community.

#### 3. Target Users
- PKCS#11 module & HSM developers (SoftHSM2, YubiHSM, Nitrokey, Thales, nShield, CloudHSM, etc.)
- p11-kit / OpenSC / middleware maintainers
- Security engineers and CI/CD teams
- Anyone who needs to verify real v3.2 + PQC behaviour

#### 4. Scope – MVP (Phase 1)
**In scope:**
- Full interface negotiation + forcing
- Segfault survival + timeouts + multi-session control
- All test categories (see §9)
- 32-bit + 64-bit support
- CLI-first experience + pytest plugin mode

**Out of scope (Phase 1):**
- GUI
- Automatic OASIS XML test-case importer (Phase 2)

#### 5. PKCS#11 Interface Requirements
| Version | Interface Used                  | Mandatory | Forceable via `--interface` |
|---------|---------------------------------|-----------|-----------------------------|
| 2.40    | Classic `C_GetFunctionList`     | Yes       | Yes                         |
| 3.0     | `CK_FUNCTION_LIST_3_0`          | Yes       | Yes                         |
| 3.2     | `CK_FUNCTION_LIST_3_2` (highest priority) | Yes | Yes                         |

- Startup always performs `C_GetInterfaceList` + `C_GetInterface`
- Default = highest available
- `--interface 3.2` forces it and fails fast if not supported
- Every run prints: “✅ Using PKCS#11 interface v3.2 (CK_FUNCTION_LIST_3_2)”

#### 6. Resilience & Stability (critical)
- **Segfault / crash survival**: All PKCS#11 calls execute in isolated subprocesses (`multiprocessing` + `concurrent.futures`). A crash in the module only marks that test as FAILED — the runner and other tests continue.
- **Timeouts**: Configurable per-operation, per-test, and global (defaults: 30 s operation / 120 s test). Hanging calls are killed cleanly.
- **Multiple concurrent sessions**: 
  - `--sessions N` or pytest `-n N` (via pytest-xdist)
  - Daemon mode: `p11test daemon` with subcommands `session list`, `session cancel <id>`, `session close-all`
- **Graceful shutdown**: Ctrl-C / SIGTERM cancels everything cleanly.

#### 7. Configurability
Three-layer config (CLI > TOML > env > defaults).

Example `p11test.toml`:
```toml
module = "/usr/lib64/p11-kit-proxy.so"
slot = 0
pin = "1234"
interface = "3.2"
timeout_operation = 30
timeout_test = 120
safe_mode = true
max_sessions = 8
log_level = "INFO"
output = "json"
```

CLI example:
```bash
p11test test --module mymodule.so --interface 3.2 --sessions 4 --timeout 15
```

#### 8. Technical Stack
- Python 3.11+
- Core library: `python-pkcs11` (v0.9.3+)
- Plugin framework: `pytest`
- Isolation: `multiprocessing`, `concurrent.futures`, `psutil`
- CLI: `typer` + `rich`
- Config: `pydantic-settings` + TOML
- Output: JSON + JUnit XML (native to pytest)
- 32-bit support: native multiarch + Docker `linux/386`

#### 9. Test Coverage (≈200 tests)
1. Library & Interface Management
2. Slot / Token / Session (incl. fork-safe)
3. Object / Key / Attribute management
4. Mechanism discovery (incl. all PQC mechanisms)
5. Encrypt / Decrypt (incl. v3 message-based)
6. Sign / Verify (incl. new v3.2 functions)
7. Digest, MAC, Wrap/Unwrap
8. **PQC-specific** (ML-KEM encapsulate/decapsulate, ML-DSA, SLH-DSA)
9. Profiles & Validation objects (v3.2 only)
10. Concurrency / multi-thread / multi-session stress
11. Error handling & edge cases

Safe mode (default) vs `--destructive` (with explicit warning + confirmation).

#### 10. CLI & pytest Usage
```bash
# Primary CLI (recommended)
p11test test --module /path/to/module.so --interface 3.2 --sessions 4

# Daemon mode
p11test daemon
p11test session list
p11test session cancel 123

# pytest plugin mode (for custom test suites)
pytest tests/ --p11-module=/path/to/module.so --p11-interface=3.2 -n 8
```

#### 11. Non-Functional Requirements
- Tester never crashes because of a bad module
- < 2 s overhead for interface negotiation + isolation setup
- Full 32-bit support (native + Docker)
- Excellent human-readable + machine-readable output
- Works on Linux (primary), macOS, Windows (where python-pkcs11 works)

#### 12. Success Criteria
- Run full test suite against a deliberately segfaulting module → only individual tests fail, runner stays alive
- Force `--interface 3.2` and confirm real v3.2 function table is used
- Support 8 parallel sessions + timeouts without leaks or dangling processes
- Pass cleanly on both 32-bit and 64-bit in CI

