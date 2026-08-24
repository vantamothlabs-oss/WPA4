#!/usr/bin/env python3
"""
WPA4 ML-KEM-1024 size stub (experimental)
-----------------------------------------
Used for OWE, PASN, FILS KE, and EAP-TLS rows.

MegaPlan requirement: raw ML-KEM-1024 ciphertext / public key material
must be exactly 1568 bytes.

This is only a size-enforcing stub. Real ML-KEM will be added later.
"""

MLKEM_SIZE = 1568


class MLKEMError(Exception):
    pass


def mlkem_encaps(public_context: bytes = b"") -> tuple[bytes, bytes]:
    """
    Stub for encapsulation.
    Returns (ciphertext, shared_secret)
    Ciphertext must be exactly 1568 bytes.
    """
    # TODO: Real ML-KEM-1024 encaps
    ciphertext = b"\x05" * MLKEM_SIZE
    shared_secret = b"mlkem-shared-secret"
    return ciphertext, shared_secret


def mlkem_decaps(ciphertext: bytes, public_context: bytes = b"") -> bytes:
    """
    Stub for decapsulation.
    Enforces exact 1568-byte ciphertext size.
    """
    if len(ciphertext) != MLKEM_SIZE:
        raise MLKEMError(
            f"ML-KEM ciphertext must be exactly {MLKEM_SIZE} bytes, "
            f"got {len(ciphertext)}"
        )

    # TODO: Real ML-KEM-1024 decaps
    return b"mlkem-shared-secret"


# ----------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("Running ML-KEM size stub self-test...")

    ct, ss1 = mlkem_encaps()
    assert len(ct) == MLKEM_SIZE
    print(f"✓ Encaps produced {len(ct)}-byte ciphertext")

    ss2 = mlkem_decaps(ct)
    print("✓ Decaps accepted correct size")

    try:
        mlkem_decaps(b"\x00" * 100)
        print("✗ Short ciphertext should have failed")
    except MLKEMError:
        print("✓ Short ciphertext correctly rejected")

    print("ML-KEM size stub self-test passed.")