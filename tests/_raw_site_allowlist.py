"""Files still containing raw pytest.xfail/fail under testcases/. SHRINKS to empty
as Phase 7 migrates each file to classify(). When empty, the static gate is fully hard."""

ALLOWLIST: set[str] = set()
