from pkcs11_check import classification as C


def test_record_get_clear_roundtrip():
    C.clear()
    rec = C.Classification(
        reason="nonspec_reject",
        outcome="xfail",
        severity="LOW",
        label="ECDSA:verify",
        actual_ckr="CKR_DEVICE_ERROR",
    )
    C.record(rec)
    got = C.get_records()
    assert len(got) == 1 and got[0].reason == "nonspec_reject"
    C.clear()
    assert C.get_records() == []


def test_serialize_is_json_dicts():
    rec = C.Classification(
        reason="crash",
        outcome="fail",
        severity="HIGH",
        detail={"signal": "SIGSEGV"},
    )
    out = C.serialize([rec])
    assert out[0]["reason"] == "crash" and out[0]["detail"]["signal"] == "SIGSEGV"
    assert out[0]["schema"] == 1
