"""Bounded tee capture: retained output is capped, never dropped silently (F-021).

The tee pump used to retain every byte of child stdout/stderr in memory and
persist full blobs into results/state. Retention is now capped per stream
(1 MiB: first half + last half); anything beyond is drained but not kept, and
the retained text carries an explicit truncation marker with omitted counts.
The diagnostic tail -- the evidence that explains a timeout -- always survives.
"""

from __future__ import annotations

import sys
from pathlib import Path

from pkcs11_check.core.file_runner import _BoundedCapture, _run_subprocess_tee


def test_small_output_retained_verbatim() -> None:
    capture = _BoundedCapture("stdout")
    capture.write(b"hello\n")
    capture.write(b"world\n")
    assert capture.getvalue() == b"hello\nworld\n"


def test_empty_capture() -> None:
    assert _BoundedCapture("stdout").getvalue() == b""


def test_at_cap_no_marker() -> None:
    capture = _BoundedCapture("stdout", max_bytes=16, head_bytes=8)
    capture.write(b"0123456789abcdef")
    assert capture.getvalue() == b"0123456789abcdef"


def test_over_cap_keeps_head_and_tail_with_counts() -> None:
    capture = _BoundedCapture("stdout", max_bytes=16, head_bytes=8)
    capture.write(b"HEADHEAD")
    capture.write(b"mid" * 100)
    capture.write(b"TAILTAIL")
    retained = capture.getvalue()
    assert retained.startswith(b"HEADHEAD")
    assert retained.endswith(b"TAILTAIL")
    assert b"omitted" in retained
    assert b"stdout" in retained
    # 8 head + 8 tail shown of 316 total -> 300 omitted.
    assert b"300" in retained
    assert b"316" in retained
    assert len(retained) <= 16 + 256  # cap + small marker slack


def test_marker_counts_span_many_writes() -> None:
    capture = _BoundedCapture("stderr", max_bytes=10, head_bytes=4)
    for _ in range(50):
        capture.write(b"xy")
    retained = capture.getvalue()
    assert retained.startswith(b"xyxy")
    assert retained.endswith(b"xyxyxy")
    assert b"stderr" in retained
    assert b"90" in retained  # 100 total - 10 shown


def test_tee_capture_bounded_with_tail_preserved(tmp_path: Path) -> None:
    """A chatty child cannot OOM the runner; the tail still explains the end."""
    del tmp_path
    script = (
        "import sys\n"
        "for i in range(60000):\n"
        "    sys.stdout.write('line-%06d padding-padding-padding\\n' % i)\n"
        "sys.stdout.write('FINAL-DIAGNOSTIC-TAIL\\n')\n"
        "sys.stdout.flush()\n"
    )
    rc, out, _err, _observation = _run_subprocess_tee(
        [sys.executable, "-c", script],
        env={"PATH": "/usr/bin:/bin"},
        timeout=60,
    )
    assert rc == 0
    assert len(out.encode("utf-8")) <= 1024 * 1024 + 512
    assert "omitted" in out
    assert "line-000000" in out
    assert "FINAL-DIAGNOSTIC-TAIL" in out
