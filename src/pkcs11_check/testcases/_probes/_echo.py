"""Test-only probe: echo params + PIN-presence, optionally sleep. Loads no module.

Used exclusively by the runner meta-tests; never shipped against a real PKCS#11 module.
When _P11CHECK_SUBPROCESS_COVERAGE is set this probe writes a deterministic
{"C_Echo": 1} coverage payload so the routing tests can verify that run_probe
routes coverage to the correct accumulator (I6).
"""

from __future__ import annotations

import os
import sys
import time

from pkcs11_check.testcases._probes._emit import write_coverage
from pkcs11_check.testcases._probes.params import ProbeParams


def main() -> None:
    params = ProbeParams.load(sys.argv[1])
    marker = params.extra.get("marker")
    if marker is not None:
        print(f"ECHO_MARKER:{marker}", flush=True)
    print(f"ECHO_PIN_PRESENT:{os.environ.get('_P11CHECK_PIN') is not None}", flush=True)
    sleep = params.extra.get("sleep")
    if sleep:
        time.sleep(float(sleep))
    # Write deterministic coverage so routing tests can assert on accumulator contents (I6).
    write_coverage({"C_Echo": 1}, {})


if __name__ == "__main__":
    main()
