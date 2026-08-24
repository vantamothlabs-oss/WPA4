#!/usr/bin/env python3
"""
WPA4 Experimental Vendor Specific IE encoder / decoder
-------------------------------------------------------
This is NOT a production encoding.
It uses Element ID 221 + a temporary experimental OUI.
Do NOT use on real networks.
"""

from typing import Optional, Tuple

# Temporary experimental identifiers (change later when ANA assigns real values)
EXPERIMENTAL_OUI = bytes([0x00, 0x56, 0x4D])          # "VM" for VantaMoth (example)
EXPERIMENTAL_OUI_TYPE = 0x01                          # subtype for WPA4-Experimental

# Allowed Information lengths from the MegaPlan
ALLOWED_LENGTHS = {
    32,     # CPace Ya / Yb
    1568,   # raw ML-KEM-1024
    1632,   # OQUAKE Respond
    1690,   # OQUAKE Init
}

class ExperimentalIEError(Exception):
    pass


def encode_experimental_ie(information: bytes, subtype: int = EXPERIMENTAL_OUI_TYPE) -> bytes:
    """
    Build a Vendor Specific (221) IE that carries a WPA4-Experimental payload.

    Format:
        Element ID (1) = 221
        Length (1)     = 3 + 1 + 2 + len(information)   (OUI + type + 2-byte len + data)
        OUI (3)
        OUI Type (1)
        Info Length (2)  big-endian
        Information (N)
    """
    if len(information) not in ALLOWED_LENGTHS:
        raise ExperimentalIEError(
            f"Information length {len(information)} is not allowed. "
            f"Allowed: {sorted(ALLOWED_LENGTHS)}"
        )

    info_len = len(information)
    payload = (
        EXPERIMENTAL_OUI +
        bytes([subtype]) +
        info_len.to_bytes(2, "big") +
        information
    )

    if len(payload) > 255:
        raise ExperimentalIEError("Payload too large for a single 221 IE (max 255 bytes)")

    ie = bytes([221, len(payload)]) + payload
    return ie


def decode_experimental_ie(ie: bytes) -> Tuple[int, bytes]:
    """
    Parse a 221 IE and return (subtype, information).
    Strict fail-closed checks.
    """
    if len(ie) < 2:
        raise ExperimentalIEError("IE too short")

    element_id = ie[0]
    length = ie[1]

    if element_id != 221:
        raise ExperimentalIEError(f"Expected Element ID 221, got {element_id}")

    if length != len(ie) - 2:
        raise ExperimentalIEError("Length field does not match actual IE size")

    if length < 6:  # OUI(3) + type(1) + info_len(2)
        raise ExperimentalIEError("Vendor payload too short")

    oui = ie[2:5]
    subtype = ie[5]
    info_len = int.from_bytes(ie[6:8], "big")
    information = ie[8:]

    if oui != EXPERIMENTAL_OUI:
        raise ExperimentalIEError(f"Unexpected OUI: {oui.hex()}")

    if info_len != len(information):
        raise ExperimentalIEError("Inner Info Length does not match payload size")

    if info_len not in ALLOWED_LENGTHS:
        raise ExperimentalIEError(
            f"Forbidden Information length {info_len}. "
            f"Allowed: {sorted(ALLOWED_LENGTHS)}"
        )

    return subtype, information


# ----------------------------------------------------------------------
# Quick self-test (run this file directly)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("Running experimental IE self-test...")

    # Test CPace size (32 bytes)
    dummy_32 = b"\x00" * 32
    ie32 = encode_experimental_ie(dummy_32)
    sub, info = decode_experimental_ie(ie32)
    assert sub == EXPERIMENTAL_OUI_TYPE
    assert info == dummy_32
    print("✓ 32-byte (CPace) OK")

    # Test OQUAKE Init size (1690) – will fail because 221 max is 255
    try:
        encode_experimental_ie(b"\x00" * 1690)
        print("✗ Should have rejected 1690-byte payload")
    except ExperimentalIEError as e:
        print("✓ Correctly rejected oversized payload:", str(e)[:60] + "...")

    print("\nSelf-test finished.")
    print("Note: Real 1690/1632/1568 payloads cannot fit in a single 221 IE.")
    print("This module is only the experimental wrapper for small test vectors.")
    print("Large payloads will later use the Extended Length path once ANA assigns IDs.")