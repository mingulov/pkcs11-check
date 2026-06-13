"""Tests that classification records ride to user_properties via the plugin."""

from __future__ import annotations

import pytest

pytest_plugins = ["pytester"]


def test_classification_lands_in_user_properties(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_x="""
        from pkcs11_check import classification as C
        def test_emits():
            try:
                C.classify("nonspec_reject", label="probe", actual="CKR_DEVICE_ERROR")
            except Exception:
                pass
        """
    )
    result = pytester.runpytest_inprocess()
    reports = result.reprec.getreports("pytest_runtest_logreport")
    call = [r for r in reports if r.when == "call"][0]
    props = dict((k, v) for k, v in call.user_properties)
    assert "pkcs11_classification" in props
    assert props["pkcs11_classification"][0]["reason"] == "nonspec_reject"
