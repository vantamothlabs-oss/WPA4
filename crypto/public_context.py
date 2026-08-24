#!/usr/bin/env python3
"""
WPA4 public_context binding
---------------------------
Implements the exact rule from the MegaPlan / Security Handoff:

    public_context = EncodePublicContext(sid, U, S) || SSID || RSN_snapshot

- sid, U, S are length-prefixed with 4-byte big-endian (I2OSP style)
- SSID and RSN_snapshot are appended raw (no extra length prefix)
- sid must be the per-association s1∥s2 (never the SSID)
"""

from typing import Optional


class PublicContextError(Exception):
    pass


def _i2osp(value: bytes, length_field_size: int = 4) -> bytes:
    """Length-prefix a byte string with a big-endian unsigned integer."""
    if len(value) >= 2**(8 * length_field_size):
        raise PublicContextError("Value too long for length field")
    return len(value).to_bytes(length_field_size, "big") + value


def encode_public_context(
    sid: bytes,
    sta_mac: bytes,          # U
    bssid: bytes,            # S
    ssid: bytes,
    rsn_snapshot: bytes
) -> bytes:
    """
    Build the public_context exactly as required by the MegaPlan.
    """
    # Fail-closed checks
    if not sid:
        raise PublicContextError("sid is empty – fail-closed")
    if len(sta_mac) != 6:
        raise PublicContextError("STA MAC (U) must be 6 bytes")
    if len(bssid) != 6:
        raise PublicContextError("BSSID (S) must be 6 bytes")
    if not ssid:
        raise PublicContextError("SSID is empty – fail-closed")
    if not rsn_snapshot:
        raise PublicContextError("RSN snapshot is empty – fail-closed")

    # CFRG-style EncodePublicContext(sid, U, S)
    encoded = (
        _i2osp(sid) +
        _i2osp(sta_mac) +
        _i2osp(bssid)
    )

    # Append raw SSID + raw RSN snapshot (no extra I2OSP)
    public_context = encoded + ssid + rsn_snapshot

    return public_context


def verify_public_context_basics(public_context: bytes) -> None:
    """
    Very basic sanity check (not a full parser).
    Used by the harness to catch obvious mistakes.
    """
    if len(public_context) < 4 + 1 + 4 + 6 + 4 + 6:
        raise PublicContextError("public_context too short")


# ----------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("Running public_context self-test...")

    sid = b"s1s2example"           # per-association s1∥s2
    sta = bytes.fromhex("001122334455")
    bssid = bytes.fromhex("aabbccddeeff")
    ssid = b"TestNetwork"
    rsn = bytes.fromhex("30140100000fac040100000fac040100000fac02")  # example RSN

    ctx = encode_public_context(sid, sta, bssid, ssid, rsn)
    print(f"public_context length: {len(ctx)}")
    print(f"First 32 bytes (hex): {ctx[:32].hex()}")

    # Negative tests
    try:
        encode_public_context(b"", sta, bssid, ssid, rsn)
        print("✗ Empty sid should have failed")
    except PublicContextError:
        print("✓ Empty sid correctly rejected")

    try:
        encode_public_context(sid, sta, bssid, b"", rsn)
        print("✗ Empty SSID should have failed")
    except PublicContextError:
        print("✓ Empty SSID correctly rejected")

    print("Self-test finished.")