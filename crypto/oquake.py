#!/usr/bin/env python3
"""
WPA4 OQUAKE stub (experimental)
-------------------------------
Placeholder for the real OQUAKE implementation used in Personal mode.

Sizes from the MegaPlan:
- OQUAKE Init   = 1690 bytes
- OQUAKE Respond = 1632 bytes

This module only provides the correct interface and strict size checking
so the handshake state machines can be developed.
"""

from typing import Tuple


class OQUAKEError(Exception):
    pass


INIT_SIZE = 1690
RESPOND_SIZE = 1632


def oquake_init(public_context: bytes, cpace_isk: bytes) -> Tuple[bytes, bytes]:
    """
    Initiator side – create OQUAKE Init message.
    Returns (init_message, internal_state)
    """
    if not public_context:
        raise OQUAKEError("public_context is required (fail-closed)")
    if not cpace_isk:
        raise OQUAKEError("CPace ISK / shared material is required")

    # TODO: Real OQUAKE Init (KemeleonNR+Tempo / ML-BUA-sKEM-1024) goes here
    init_msg = b"\x03" * INIT_SIZE          # placeholder 1690 bytes
    state = b"oquake-initiator-state"

    return init_msg, state


def oquake_respond(public_context: bytes, cpace_isk: bytes, init_msg: bytes) -> Tuple[bytes, bytes]:
    """
    Responder side – process Init and create Respond message.
    Returns (respond_message, shared_secret)
    """
    if not public_context:
        raise OQUAKEError("public_context is required (fail-closed)")
    if len(init_msg) != INIT_SIZE:
        raise OQUAKEError(f"Init message must be exactly {INIT_SIZE} bytes")

    # TODO: Real OQUAKE Respond
    respond_msg = b"\x04" * RESPOND_SIZE    # placeholder 1632 bytes
    shared = b"oquake-shared-secret"

    return respond_msg, shared


def oquake_initiator_finish(state: bytes, respond_msg: bytes) -> bytes:
    """
    Initiator finishes after receiving the Respond message.
    Returns the final shared secret / key material.
    """
    if len(respond_msg) != RESPOND_SIZE:
        raise OQUAKEError(f"Respond message must be exactly {RESPOND_SIZE} bytes")

    # TODO: Real finish step
    return b"oquake-shared-secret"


# ----------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("Running OQUAKE stub self-test...")

    fake_ctx = b"dummy-public-context"
    fake_isk = b"dummy-cpace-isk"

    init_msg, state = oquake_init(fake_ctx, fake_isk)
    assert len(init_msg) == INIT_SIZE
    print(f"✓ Init message size = {len(init_msg)}")

    respond_msg, shared1 = oquake_respond(fake_ctx, fake_isk, init_msg)
    assert len(respond_msg) == RESPOND_SIZE
    print(f"✓ Respond message size = {len(respond_msg)}")

    shared2 = oquake_initiator_finish(state, respond_msg)
    print("✓ Initiator finish completed")

    print("OQUAKE stub self-test passed (placeholders only).")