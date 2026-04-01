"""Tests for needs_mechanism decorator and skip_unless_mechanism helper."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pkcs11_check.testcases.conftest import needs_mechanism, skip_unless_mechanism


def _mock_session(has: bool) -> MagicMock:
    rs = MagicMock()
    rs.has_mechanism.return_value = has
    return rs


class TestNeedsMechanismDecorator:
    def test_skips_when_mechanism_missing(self) -> None:
        @needs_mechanism("FAKE_MECH")
        def test_func(p11_raw_session):
            raise AssertionError("should not reach here")

        with pytest.raises(pytest.skip.Exception, match="FAKE_MECH not supported"):
            test_func(p11_raw_session=_mock_session(False))

    def test_passes_when_mechanism_present(self) -> None:
        @needs_mechanism("FAKE_MECH")
        def test_func(p11_raw_session):
            return "ok"

        assert test_func(p11_raw_session=_mock_session(True)) == "ok"

    def test_works_with_class_method_missing(self) -> None:
        class T:
            @needs_mechanism("FAKE_MECH")
            def test_m(self, p11_raw_session):
                raise AssertionError("should not reach here")

        with pytest.raises(pytest.skip.Exception, match="FAKE_MECH not supported"):
            T().test_m(p11_raw_session=_mock_session(False))

    def test_works_with_class_method_present(self) -> None:
        class T:
            @needs_mechanism("FAKE_MECH")
            def test_m(self, p11_raw_session):
                return "ok"

        assert T().test_m(p11_raw_session=_mock_session(True)) == "ok"

    def test_passes_through_without_fixture(self) -> None:
        @needs_mechanism("FAKE_MECH")
        def test_func():
            return "ok"

        assert test_func() == "ok"

    def test_preserves_function_name(self) -> None:
        @needs_mechanism("FAKE_MECH")
        def my_test_func(p11_raw_session):
            pass

        assert my_test_func.__name__ == "my_test_func"


class TestSkipUnlessMechanism:
    def test_skips_when_mechanism_missing(self) -> None:
        rs = _mock_session(False)
        with pytest.raises(pytest.skip.Exception, match="AES_GCM not supported"):
            skip_unless_mechanism(rs, "AES_GCM")

    def test_passes_when_mechanism_present(self) -> None:
        rs = _mock_session(True)
        skip_unless_mechanism(rs, "AES_GCM")
