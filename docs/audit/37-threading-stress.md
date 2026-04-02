# Audit 37: Threading, Stress & Resource Exhaustion

**Date:** 2026-04-01
**Files audited:** `test_threading.py`, `test_stress.py`, `test_resource.py`, `test_session_exhaustion.py`, `test_benchmark.py`

## Findings

### Coverage Status

Threading safety tests present. Stress tests run 1000-cycle operations. Resource exhaustion probes handle/session limits. Session exhaustion cleanup tested. Benchmarks measure performance.

### Coverage Gaps

- [GAP] PQC stress tests — no stress/threading tests for ML-KEM encapsulate or ML-DSA sign (potentially slow operations under load).
- [GAP] Concurrent write contention — test_stress.py may test concurrent ops but no explicit database-locking scenario (relevant for SoftHSM2/NSS file-based backends).
- [GAP] Memory leak detection — no test monitors memory usage over repeated operations to detect module-level leaks.
- [NOTED] Benchmark tests use `@pytest.mark.benchmark` — separate from correctness tests, appropriate.

## Statistics

- Issues found: 0 fixed, 3 gaps documented
