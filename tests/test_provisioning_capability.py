"""Meta-tests for the one-per-class provisioning capability finding."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.mark.structures import get_unpacked_marks
from _pytest.outcomes import XFailed

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_USER_TYPE_INVALID
from pkcs11_check.testcases import _provisioning as provisioning
from pkcs11_check.testcases import test_provisioning_capability as capability

_OBJECT_CLASSES = ("secret", "private", "public", "cert", "data")


def _raise_user_type_invalid(*args: object, **kwargs: object) -> int:
    raise CkrAssertionError("user role cannot create", int(CKR_USER_TYPE_INVALID))


def test_user_role_prohibition_is_one_visible_finding_per_object_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CKR_USER_TYPE_INVALID create probe xfails once per class; dependents still skip."""
    monkeypatch.setattr("pkcs11_check.raw.recipes.import_secret_key", _raise_user_type_invalid)
    monkeypatch.setattr("pkcs11_check.raw.recipes.import_ec_public_key", _raise_user_type_invalid)
    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _raise_user_type_invalid)
    provisioning._PROFILE_CACHE.clear()
    provisioning.clear_provisioning_events()
    rs = SimpleNamespace(raw=object(), sh=901)

    marks = get_unpacked_marks(capability.test_create_object_available)
    parametrize = next(mark for mark in marks if mark.name == "parametrize")
    assert tuple(parametrize.args[1]) == _OBJECT_CLASSES

    for obj_class in _OBJECT_CLASSES:
        classification.clear()
        with pytest.raises(XFailed):
            capability.test_create_object_available(rs, obj_class)
        records = classification.serialize(classification.get_records())
        assert len(records) == 1
        assert records[0]["reason"] == "honest_deviation"
        assert records[0]["outcome"] == "xfail"

        with pytest.raises(pytest.skip.Exception):
            provisioning.skip_unless_can_create(rs, obj_class)

    events = provisioning.get_provisioning_events()
    assert [(event.obj_class, event.method) for event in events] == [
        (obj_class, "skipped_no_path") for obj_class in _OBJECT_CLASSES
    ]
