from pathlib import Path

import pytest
from pydantic import ValidationError

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


@pytest.mark.parametrize("mode", ["off", "unwrap", "force-unwrap"])
def test_key_inject_accepts_known_modes(mode):
    cfg = P11TestConfig(module=Path("/x.so"), key_inject=mode)
    assert cfg.key_inject == mode


@pytest.mark.parametrize("mode", ["of", "unwarp", "UNWRAP", "unwrap ", "", "force_unwrap"])
def test_key_inject_typo_fails_closed(mode):
    """H-12: a bare str let typos fall through to the unwrap path.

    The config layer is the last validator before provisioning; an unknown
    mode must fail here, never silently enable injection.
    """
    with pytest.raises(ValidationError):
        P11TestConfig(module=Path("/x.so"), key_inject=mode)
