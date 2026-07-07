from __future__ import annotations

import importlib
import pkgutil

import pkcs11_check.testcases._probes as probes_pkg


def test_every_probe_module_imports() -> None:
    failures: list[str] = []
    for mod in pkgutil.iter_modules(probes_pkg.__path__):
        name = f"{probes_pkg.__name__}.{mod.name}"
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001 - we want the name + error
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    assert not failures, "broken _probes modules:\n" + "\n".join(failures)
