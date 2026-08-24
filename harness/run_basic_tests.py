#!/usr/bin/env python3
"""
Basic userspace tests for WPA4 experimental modules
"""

import sys
import os

# Make sure we can import from the parent folders
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from encoding.experimental_ie import encode_experimental_ie, decode_experimental_ie, ExperimentalIEError
from crypto.public_context import encode_public_context, PublicContextError


def test_experimental_ie():
    print("=== Testing experimental_ie ===")
    
    # Valid 32-byte payload (CPace size)
    data = b"\x11" * 32
    ie = encode_experimental_ie(data)
    subtype, recovered = decode_experimental_ie(ie)
    
    assert subtype == 0x01
    assert recovered == data
    print("✓ 32-byte encode/decode passed")

    # Oversized payload must fail
    try:
        encode_experimental_ie(b"\x00" * 1690)
        print("✗ Oversized payload should have failed")
        return False
    except ExperimentalIEError:
        print("✓ Oversized payload correctly rejected")

    return True


def test_public_context():
    print("\n=== Testing public_context ===")
    
    sid = b"s1s2-test-vector"
    sta = bytes.fromhex("001122334455")
    bssid = bytes.fromhex("aabbccddeeff")
    ssid = b"VantaMoth-Test"
    rsn = bytes.fromhex("30140100000fac040100000fac040100000fac02")

    ctx = encode_public_context(sid, sta, bssid, ssid, rsn)
    print(f"✓ public_context created, length = {len(ctx)}")

    # Empty sid must fail
    try:
        encode_public_context(b"", sta, bssid, ssid, rsn)
        print("✗ Empty sid should have failed")
        return False
    except PublicContextError:
        print("✓ Empty sid correctly rejected")

    return True


if __name__ == "__main__":
    print("Running WPA4 basic userspace tests...\n")
    
    ok1 = test_experimental_ie()
    ok2 = test_public_context()
    
    if ok1 and ok2:
        print("\n✅ All basic tests passed")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)