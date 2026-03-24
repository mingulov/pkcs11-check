from __future__ import annotations

import ctypes


def test_get_slot_ids_uses_explicit_token_present_and_two_call_pattern() -> None:
    from pkcs11_check.raw.bootstrap import get_slot_ids
    from pkcs11_check.raw.core import CKR_OK
    from pkcs11_check.raw.types_std import CK_SLOT_ID, CK_SLOT_ID_PTR, CK_ULONG_PTR

    calls: list[int] = []

    class FakeRaw:
        def C_GetSlotList(self, token_present: int, slot_list: CK_SLOT_ID_PTR | None, count: object) -> int:
            calls.append(token_present)
            count_ptr = ctypes.cast(count, CK_ULONG_PTR)
            if slot_list is None:
                count_ptr[0] = 2
                return CKR_OK

            slots_ptr = ctypes.cast(slot_list, CK_SLOT_ID_PTR)
            slots_ptr[0] = CK_SLOT_ID(7)
            slots_ptr[1] = CK_SLOT_ID(9)
            count_ptr[0] = 2
            return CKR_OK

    assert get_slot_ids(FakeRaw(), token_present=False) == [7, 9]
    assert calls == [0, 0]


def test_open_session_returns_handle_and_passes_explicit_flags() -> None:
    from pkcs11_check.raw.bootstrap import open_session
    from pkcs11_check.raw.core import CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK
    from pkcs11_check.raw.types_std import CK_NOTIFY, CK_SESSION_HANDLE_PTR

    seen: list[tuple[int, int, object, object]] = []

    class FakeRaw:
        def C_OpenSession(
            self,
            slot_id: int,
            flags: int,
            application: object,
            notify: object,
            session: object,
        ) -> int:
            seen.append((slot_id, flags, application, notify))
            session_ptr = ctypes.cast(session, CK_SESSION_HANDLE_PTR)
            session_ptr[0] = 41
            return CKR_OK

    handle = open_session(FakeRaw(), slot_id=5, flags=CKF_SERIAL_SESSION | CKF_RW_SESSION)

    assert handle == 41
    assert len(seen) == 1
    assert seen[0][0] == 5
    assert seen[0][1] == CKF_SERIAL_SESSION | CKF_RW_SESSION
    assert seen[0][2] is None
    assert isinstance(seen[0][3], CK_NOTIFY)
    assert not bool(seen[0][3])


def test_login_user_passes_explicit_user_type_and_pin_bytes() -> None:
    from pkcs11_check.raw.bootstrap import login_user
    from pkcs11_check.raw.core import CKR_OK, CKU_CONTEXT_SPECIFIC
    from pkcs11_check.raw.types_std import CK_UTF8CHAR_PTR

    seen: list[tuple[int, int, bytes, int]] = []

    class FakeRaw:
        def C_Login(self, session: int, user_type: int, pin: object, pin_len: int) -> int:
            pin_ptr = ctypes.cast(pin, CK_UTF8CHAR_PTR)
            pin_bytes = bytes(pin_ptr[index] for index in range(pin_len))
            seen.append((session, user_type, pin_bytes, pin_len))
            return CKR_OK

    login_user(FakeRaw(), session=99, user_type=CKU_CONTEXT_SPECIFIC, pin=b"1234")

    assert seen == [(99, CKU_CONTEXT_SPECIFIC, b"1234", 4)]


def test_login_user_accepts_bytearray_pin_input() -> None:
    from pkcs11_check.raw.bootstrap import login_user
    from pkcs11_check.raw.core import CKR_OK, CKU_USER
    from pkcs11_check.raw.types_std import CK_UTF8CHAR_PTR

    seen: list[bytes] = []

    class FakeRaw:
        def C_Login(self, session: int, user_type: int, pin: object, pin_len: int) -> int:
            pin_ptr = ctypes.cast(pin, CK_UTF8CHAR_PTR)
            seen.append(bytes(pin_ptr[index] for index in range(pin_len)))
            return CKR_OK

    login_user(FakeRaw(), session=17, user_type=CKU_USER, pin=bytearray(b"5678"))

    assert seen == [b"5678"]


def test_login_user_accepts_memoryview_pin_input() -> None:
    from pkcs11_check.raw.bootstrap import login_user
    from pkcs11_check.raw.core import CKR_OK, CKU_USER
    from pkcs11_check.raw.types_std import CK_UTF8CHAR_PTR

    seen: list[bytes] = []

    class FakeRaw:
        def C_Login(self, session: int, user_type: int, pin: object, pin_len: int) -> int:
            pin_ptr = ctypes.cast(pin, CK_UTF8CHAR_PTR)
            seen.append(bytes(pin_ptr[index] for index in range(pin_len)))
            return CKR_OK

    login_user(FakeRaw(), session=17, user_type=CKU_USER, pin=memoryview(b"90"))

    assert seen == [b"90"]


def test_login_user_keeps_empty_pin_explicit_instead_of_null() -> None:
    from pkcs11_check.raw.bootstrap import login_user
    from pkcs11_check.raw.core import CKR_OK, CKU_USER

    seen: list[tuple[object, int]] = []

    class FakeRaw:
        def C_Login(self, session: int, user_type: int, pin: object, pin_len: int) -> int:
            seen.append((pin, pin_len))
            return CKR_OK

    login_user(FakeRaw(), session=17, user_type=CKU_USER, pin=b"")

    assert len(seen) == 1
    assert seen[0][0] is not None
    assert seen[0][1] == 0


def test_login_user_tolerates_user_already_logged_in_for_setup_flows() -> None:
    from pkcs11_check.raw.bootstrap import login_user
    from pkcs11_check.raw.core import CKR_USER_ALREADY_LOGGED_IN, CKU_USER

    class FakeRaw:
        def C_Login(self, session: int, user_type: int, pin: object, pin_len: int) -> int:
            return CKR_USER_ALREADY_LOGGED_IN

    login_user(FakeRaw(), session=17, user_type=CKU_USER, pin=b"1234")


def test_login_user_rejects_text_pin_input() -> None:
    import pytest

    from pkcs11_check.raw.bootstrap import login_user
    from pkcs11_check.raw.core import CKU_USER

    class FakeRaw:
        def C_Login(self, session: int, user_type: int, pin: object, pin_len: int) -> int:
            raise AssertionError("should not be called")

    with pytest.raises(TypeError, match="pin must be bytes-like"):
        login_user(FakeRaw(), session=17, user_type=CKU_USER, pin="1234")


def test_login_user_rejects_non_buffer_input() -> None:
    import pytest

    from pkcs11_check.raw.bootstrap import login_user
    from pkcs11_check.raw.core import CKU_USER

    class FakeRaw:
        def C_Login(self, session: int, user_type: int, pin: object, pin_len: int) -> int:
            raise AssertionError("should not be called")

    with pytest.raises(TypeError, match="pin must be bytes-like"):
        login_user(FakeRaw(), session=17, user_type=CKU_USER, pin=None)


def test_close_session_quietly_is_best_effort_for_teardown() -> None:
    from pkcs11_check.raw.bootstrap import close_session_quietly
    from pkcs11_check.raw.core import CKR_SESSION_HANDLE_INVALID

    seen: list[int] = []

    class FakeRaw:
        def C_CloseSession(self, session: int) -> int:
            seen.append(session)
            return CKR_SESSION_HANDLE_INVALID

    close_session_quietly(FakeRaw(), 77)

    assert seen == [77]


def test_raw_package_exports_bootstrap_helpers() -> None:
    from pkcs11_check.raw import close_session_quietly, get_slot_ids, login_user, open_session

    assert get_slot_ids is not None
    assert open_session is not None
    assert login_user is not None
    assert close_session_quietly is not None
