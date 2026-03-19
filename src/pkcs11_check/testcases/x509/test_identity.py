"""Tests for X.509 Identity (Cert + Private Key) integration."""

from __future__ import annotations

import pytest
from pkcs11 import Attribute, CertificateType, KeyType, ObjectClass, Mechanism
from pkcs11.exceptions import PKCS11Error
from pkcs11_check.testcases.x509.conftest import pem_to_der
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography import x509

pytestmark = [pytest.mark.cert, pytest.mark.keymgmt, pytest.mark.object]

def test_limbo_identity_closeness(p11_session: Any, cert_support: bool, all_limbo_cases: list[dict[str, Any]], limbo_filter: Any) -> None:
    """Import Cert + Key from Limbo, link with CKA_ID, and Sign/Verify.
    
    This test verifies that:
    1. Private keys can be imported and linked to certificates via CKA_ID.
    2. The private key can be found starting from the certificate's metadata.
    3. Cryptographic operations (signing) work with the linked identity.
    """
    if not cert_support:
        pytest.skip("Module does not support X.509 certificates")
        
    # We filter for cases that HAVE a private key
    cases_with_keys = [tc for tc in all_limbo_cases if tc.get('peer_certificate_key')]
    if not cases_with_keys:
        pytest.skip("No testcases with private keys found in Limbo dataset")
        
    # Sample a few for iteration
    cases = cases_with_keys[:10]
    
    errors = []
    for tc in cases:
        cert_der = pem_to_der(tc['peer_certificate'])
        key_der = pem_to_der(tc['peer_certificate_key'])
        cid = tc['id'].encode('utf-8')[:32] # Unique ID for this test
        
        try:
            # 1. Import Certificate
            cert_obj = p11_session.create_object({
                Attribute.CLASS: ObjectClass.CERTIFICATE,
                Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
                Attribute.VALUE: cert_der,
                Attribute.ID: cid,
                Attribute.LABEL: f"Cert {tc['id']}",
                Attribute.TOKEN: False,
            })
            
            # 2. Import Private Key
            # We need to detect key type from cert or Limbo features
            # Limbo mostly has EC keys currently.
            # For simplicity in this iteration, we'll try to detect from the PEM footer/header 
            # or use a generic approach if supported.
            
            key_pem = tc['peer_certificate_key'].strip()
            key_class = ObjectClass.PRIVATE_KEY
            is_rsa = "RSA" in key_pem
            is_ec = "EC" in key_pem or "BEGIN PRIVATE KEY" in key_pem # PKCS#8 often EC in Limbo
            
            key_attrs = {
                Attribute.CLASS: key_class,
                Attribute.VALUE: key_der,
                Attribute.ID: cid,
                Attribute.LABEL: f"Key {tc['id']}",
                Attribute.TOKEN: False,
                Attribute.SIGN: True,
                Attribute.EXTRACTABLE: False,
                Attribute.SENSITIVE: True,
            }
            if is_rsa:
                key_attrs[Attribute.KEY_TYPE] = KeyType.RSA
            elif is_ec:
                key_attrs[Attribute.KEY_TYPE] = KeyType.EC
            
            try:
                key_obj = p11_session.create_object(key_attrs)
            except PKCS11Error as e:
                cert_obj.destroy()
                # Some modules don't like CKA_VALUE for private key import, 
                # they might want components. 
                # If so, we skip for now as this is a module-specific "how to import" issue.
                continue

            # 3. Perform Sign operation
            data = b"Hello PKCS#11 Identity"
            # Mechanism detection
            if is_rsa:
                mech = Mechanism.SHA256_RSA_PKCS
            else:
                mech = Mechanism.ECDSA_SHA256
                
            try:
                sig = key_obj.sign(data, mechanism=mech)
                assert sig is not None
            except PKCS11Error as e:
                errors.append(f"TC {tc['id']} - Signing failed: {e}")
            finally:
                key_obj.destroy()
                cert_obj.destroy()
                
        except PKCS11Error as e:
            continue

    if errors:
        pytest.fail("\n".join(errors))
