#!/usr/bin/env python3
"""
WPA4 CPace stub (experimental)
------------------------------
This is a placeholder for the real CPace implementation.

Real CPace will use RIST255 and produce 32-byte Ya / Yb elements.
For now this module only provides the correct interface and size checks
so the rest of the handshake state machines can be built.
"""

from typing import Tuple
from crypto.public_context import PublicContextError


class CPaceError(Exception):
    pass


def cpace_initiator(public_context: bytes) -> Tuple[bytes, bytes]:
    """
    Initiator side (STA).
    Returns (Ya, intermediate_state)
    
    Ya must be exactly 32 bytes.
    """
    if not public_context:
        raise CPaceError("public_context is required (fail-closed)")

    # TODO: Real CPace implementation using RIST255 goes here
    # For now we return a deterministic dummy 32-byte value
    ya = b"\x01" * 32          # placeholder Ya
    state = b"initiator-state" # placeholder internal state

    return ya, state


def cpace_responder(public_context: bytes, ya: bytes) -> Tuple[bytes, bytes]:
    """
    Responder side (AP).
    Returns (Yb, shared_secret_ish)
    
    Yb must be exactly 32 bytes.
    """
    if not public_context:
        raise CPaceError("public_context is required (fail-closed)")
    if len(ya) != 32:
        raise CPaceError("Ya must be exactly 32 bytes")

    # TODO: Real CPace implementation
    yb = b"\x02" * 32              # placeholder Yb
    shared = b"shared-secret-ish"  # placeholder

    return yb, shared


def cpace_initiator_finish(state: bytes, yb: bytes) -> bytes:
    """
    Initiator finishes after receiving Yb.
    Returns the shared secret / ISK material.
    """
    if len(yb) != 32:
        raise CPaceError("Yb must be exactly 32 bytes")

    # TODO: Real finish step
    return b"shared-secret-ish"


# ----------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("Running CPace stub self-test...")

    fake_ctx = b"dummy-public-context-for-testing"

    ya, state = cpace_initiator(fake_ctx)
    assert len(ya) == 32
    print("✓ Initiator produced 32-byte Ya")

    yb, shared1 = cpace_responder(fake_ctx, ya)
    assert len(yb) == 32
    print("✓ Responder produced 32-byte Yb")

    shared2 = cpace_initiator_finish(state, yb)
    print("✓ Initiator finish completed")

    print("CPace stub self-test passed (placeholders only).")