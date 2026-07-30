"""Tests for packaged mechanism-vector loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def test_load_vectors_uses_shared_json_cache(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    from pkcs11_check.testcases import mechanism_vectors

    vector_file = tmp_path / "aes.json"
    vector_file.write_text('{"vectors": []}\n', encoding="utf-8")
    calls: list[Path] = []

    def fake_load_json_cached(path: str | Path) -> dict[str, Any]:
        calls.append(Path(path))
        return {"vectors": [{"id": "cached"}]}

    monkeypatch.setattr(mechanism_vectors, "_VECTOR_DIR", tmp_path)
    monkeypatch.setattr(mechanism_vectors, "load_json_cached", fake_load_json_cached)

    assert mechanism_vectors.load_vectors("aes.json") == [{"id": "cached"}]
    assert calls == [vector_file]
