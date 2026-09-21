"""Pin the shipped disabled-tests baseline (H-7).

``data/disabled-tests.txt`` silently removes tests from every run that
auto-discovers it. An edit there -- adding a nodeid, or worse, deleting the
file's contents -- must be a conscious, reviewed act, not an accidental
keystroke that greens the suite by shrinking it. This pin fails closed on any
byte change: review the diff, then update ``PINNED_SHA256`` (and the active
nodeid count below) in the same commit.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from pkcs11_check.core.test_selection import parse_disabled_nodeids

BASELINE_PATH = Path(__file__).resolve().parent.parent / "data" / "disabled-tests.txt"

# sha256 of data/disabled-tests.txt at the time of pinning. Repin procedure:
# git diff data/disabled-tests.txt, confirm every hunk is intended, then set
# this to the new `sha256sum` and update PINNED_ACTIVE_NODEIDS to match.
PINNED_SHA256 = "9bfe89d06db0c021b23e95d2bd81584d4ecf05f6a30875e65e2680b2cb945d6c"
PINNED_ACTIVE_NODEIDS = 0


def test_shipped_disabled_baseline_matches_pinned_sha256() -> None:
    assert BASELINE_PATH.is_file(), (
        f"shipped disabled baseline missing: {BASELINE_PATH} -- the H-7 pin "
        "cannot verify a baseline that is not there; restore the file"
    )
    digest = hashlib.sha256(BASELINE_PATH.read_bytes()).hexdigest()
    assert digest == PINNED_SHA256, (
        f"shipped disabled baseline changed (sha256 {digest}, pinned {PINNED_SHA256}); "
        "review `git diff data/disabled-tests.txt` -- if every hunk is intended, "
        "repin PINNED_SHA256 in tests/test_disabled_baseline_pin.py"
    )


def test_shipped_disabled_baseline_active_nodeid_count() -> None:
    active = parse_disabled_nodeids(BASELINE_PATH.read_text(encoding="utf-8"))
    assert len(active) == PINNED_ACTIVE_NODEIDS, (
        f"shipped disabled baseline now disables {len(active)} nodeids "
        f"(pinned {PINNED_ACTIVE_NODEIDS}); review the diff and repin "
        "PINNED_ACTIVE_NODEIDS alongside PINNED_SHA256"
    )
