from pathlib import Path

from pkcs11_check.config import P11TestConfig


def test_key_inject_defaults():
    cfg = P11TestConfig(module=Path("/x.so"))
    assert cfg.key_inject == "off"
    assert cfg.wrap_key_source == "bootstrap"
    assert cfg.wrap_rsa_bits == 2048
    assert cfg.wrap_key_label is None and cfg.wrap_key_value is None


def test_key_inject_override():
    cfg = P11TestConfig(module=Path("/x.so"), key_inject="force-unwrap", wrap_rsa_bits=3072)
    assert cfg.key_inject == "force-unwrap"
    assert cfg.wrap_rsa_bits == 3072
