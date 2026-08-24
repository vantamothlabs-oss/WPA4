#!/usr/bin/env python3
"""
Basic userspace tests for WPA4 experimental modules
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from encoding.experimental_ie import encode_experimental_ie, decode_experimental_ie, ExperimentalIEError
from crypto.public_context import encode_public_context, PublicContextError
from handshake.personal import PersonalHandshake, State


def test_experimental_ie():
    print("=== Testing experimental_ie ===")
    
    data = b"\x11" * 32
    ie = encode_experimental_ie(data)
    subtype, recovered = decode_experimental_ie(ie)
    
    assert subtype == 0x01
    assert recovered == data
    print("✓ 32-byte encode/decode passed")

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

    try:
        encode_public_context(b"", sta, bssid, ssid, rsn)
        print("✗ Empty sid should have failed")
        return False
    except PublicContextError:
        print("✓ Empty sid correctly rejected")

    return True


def test_personal_handshake():
    print("\n=== Testing Personal handshake stub ===")

    sid = b"s1s2-demo"
    sta = bytes.fromhex("001122334455")
    bssid = bytes.fromhex("aabbccddeeff")
    ssid = b"DemoNetwork"
    rsn = bytes.fromhex("30140100000fac040100000fac040100000fac02")

    sta_hs = PersonalHandshake(is_initiator=True)
    ap_hs = PersonalHandshake(is_initiator=False)

    # Lock + bind
    assert sta_hs.lock_rsn_and_bind(sid, sta, bssid, ssid, rsn)
    assert ap_hs.lock_rsn_and_bind(sid, sta, bssid, ssid, rsn)
    print("✓ Both sides bound public_context")

    # CPace
    ya = sta_hs.start_cpace()
    assert ya is not None and len(ya) == 32
    yb = ap_hs.process_cpace_ya(ya)
    assert yb is not None and len(yb) == 32
    assert sta_hs.finish_cpace(yb)
    print("✓ CPace completed")

    # OQUAKE
    init_msg = sta_hs.start_oquake()
    assert init_msg is not None and len(init_msg) == 1690
    respond_msg = ap_hs.process_oquake_init(init_msg)
    assert respond_msg is not None and len(respond_msg) == 1632
    assert sta_hs.finish_oquake(respond_msg)
    print("✓ OQUAKE completed")

    assert sta_hs.is_finished()
    assert ap_hs.state == State.OQUAKE_DONE
    print("✓ Personal handshake finished successfully")

    return True


if __name__ == "__main__":
    print("Running WPA4 basic userspace tests...\n")
    
    ok1 = test_experimental_ie()
    ok2 = test_public_context()
    ok3 = test_personal_handshake()
    
    if ok1 and ok2 and ok3:
        print("\n✅ All tests passed")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed")
        sys.exit(1)