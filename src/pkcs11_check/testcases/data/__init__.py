"""Centralized test data paths - single source of truth.

All test files import data paths from here.
"""

from pathlib import Path

DATA_DIR = Path(__file__).parent
WYCHEPROOF_DIR = DATA_DIR / "wycheproof" / "testvectors_v1"
CCTV_DIR = DATA_DIR / "cctv"
ACVP_DIR = DATA_DIR / "acvp" / "gen-val" / "json-files"
X509_LIMBO_DIR = DATA_DIR / "x509-limbo"
KAT_DIR = DATA_DIR  # sha1.json, aes_ecb.json live here
