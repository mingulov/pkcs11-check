#!/usr/bin/env python3
"""Combinatorial attribute template generator for PKCS#11 fuzz testing.

Generates randomized CK_ATTRIBUTE templates and runs C_CreateObject /
C_GenerateKey against a PKCS#11 module. Collects CKR results into a matrix.

Usage:
    uv run python scripts/attr-template-fuzz.py --module /path/to.so --pin 1234 [--count 100]
"""

from __future__ import annotations

import argparse
import random
from collections import Counter

import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import PKCS11Error


# Attribute value generators
def _random_bool() -> bool:
    return random.choice([True, False])


def _random_bytes(max_len: int = 256) -> bytes:
    length = random.randint(0, max_len)
    return random.randbytes(length)


def _random_class() -> int:
    return random.choice([
        ObjectClass.DATA, ObjectClass.CERTIFICATE, ObjectClass.PUBLIC_KEY,
        ObjectClass.PRIVATE_KEY, ObjectClass.SECRET_KEY,
        0xDEADBEEF, 0, 0xFFFFFFFF,
    ])


def _random_keytype() -> int:
    return random.choice([
        KeyType.AES, KeyType.RSA, KeyType.EC, KeyType.DES3,
        0xDEADBEEF, 0, 0xFFFFFFFF,
    ])


# Template generators
def random_data_template() -> dict:
    """Random CKO_DATA template."""
    t: dict = {Attribute.CLASS: ObjectClass.DATA, Attribute.TOKEN: False}
    if random.random() > 0.3:
        t[Attribute.LABEL] = f"fuzz-{random.randint(0, 9999)}"
    if random.random() > 0.3:
        t[Attribute.VALUE] = _random_bytes(1024)
    if random.random() > 0.7:
        t[Attribute.PRIVATE] = _random_bool()
    return t


def random_key_template() -> dict:
    """Random secret key template."""
    t: dict = {
        Attribute.CLASS: ObjectClass.SECRET_KEY,
        Attribute.TOKEN: False,
    }
    if random.random() > 0.3:
        t[Attribute.KEY_TYPE] = _random_keytype()
    if random.random() > 0.3:
        t[Attribute.VALUE] = _random_bytes(32)
    for attr in [Attribute.ENCRYPT, Attribute.DECRYPT, Attribute.SIGN,
                 Attribute.VERIFY, Attribute.WRAP, Attribute.UNWRAP]:
        if random.random() > 0.5:
            t[attr] = _random_bool()
    if random.random() > 0.5:
        t[Attribute.SENSITIVE] = _random_bool()
    if random.random() > 0.5:
        t[Attribute.EXTRACTABLE] = _random_bool()
    return t


def random_bad_template() -> dict:
    """Intentionally malformed template."""
    strategies = [
        lambda: {Attribute.CLASS: 0xDEADBEEF, Attribute.TOKEN: False},
        lambda: {Attribute.TOKEN: False},  # Missing CLASS
        lambda: {Attribute.CLASS: ObjectClass.SECRET_KEY, Attribute.VALUE: b"",
                 Attribute.TOKEN: False},
        lambda: {Attribute.CLASS: ObjectClass.DATA, Attribute.KEY_TYPE: KeyType.AES,
                 Attribute.TOKEN: False},
        lambda: {Attribute.CLASS: _random_class(), Attribute.KEY_TYPE: _random_keytype(),
                 Attribute.VALUE: _random_bytes(64), Attribute.TOKEN: _random_bool()},
    ]
    return random.choice(strategies)()


def main() -> None:
    parser = argparse.ArgumentParser(description="PKCS#11 attribute template fuzzer")
    parser.add_argument("--module", required=True)
    parser.add_argument("--pin", default=None)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--slot", type=int, default=0)
    args = parser.parse_args()

    lib = pkcs11.lib(args.module)
    lib.initialize()

    try:
        slots = lib.get_slots(token_present=True)
        if not slots:
            slots = lib.get_slots()
        token = slots[args.slot].get_token()
        session = token.open(rw=True, user_pin=args.pin)

        results: Counter[str] = Counter()
        generators = [random_data_template, random_key_template, random_bad_template]

        for _ in range(args.count):
            gen = random.choice(generators)
            template = gen()
            try:
                obj = session.create_object(template)
                results["OK"] += 1
                obj.destroy()
            except PKCS11Error as e:
                results[type(e).__name__] += 1
            except (TypeError, ValueError, OverflowError) as e:
                results[f"Python:{type(e).__name__}"] += 1

        print(f"\n=== Attribute Template Fuzz Results ({args.count} templates) ===\n")
        for ckr, count in results.most_common():
            pct = count * 100 / args.count
            print(f"  {ckr:40s} {count:5d} ({pct:.1f}%)")

        print(f"\n  Total: {args.count}, Unique CKR codes: {len(results)}")
        print("  Crashes: 0 (if you see this, no segfaults)")

        session.close()
    finally:
        lib.finalize()


if __name__ == "__main__":
    main()
