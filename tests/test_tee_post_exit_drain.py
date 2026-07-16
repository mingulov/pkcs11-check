"""The post-exit reader-thread drain must be bounded by a short grace, not the full
per-test timeout, so a stuck reader (grandchild holding the pipe) cannot hang the run."""

from __future__ import annotations

import threading
import time

from pkcs11_check.core import file_runner


def test_post_exit_join_is_bounded() -> None:
    stuck = threading.Event()  # never set -> the "reader" blocks forever

    def _never_returns() -> None:
        stuck.wait()

    t = threading.Thread(target=_never_returns, daemon=True)
    t.start()
    try:
        start = time.monotonic()
        # Exercise the helper the runner uses to drain readers after the child exits.
        file_runner._join_readers_bounded([t], grace=0.2)
        elapsed = time.monotonic() - start
        assert elapsed < 1.0, f"drain blocked {elapsed:.2f}s; must be bounded by the grace"
        assert t.is_alive(), "a stuck reader should be abandoned, not required to finish"
    finally:
        stuck.set()
