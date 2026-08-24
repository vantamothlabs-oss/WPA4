#!/usr/bin/env python3
"""
WPA4 Personal handshake state machine (experimental stub)
---------------------------------------------------------
Implements the high-level flow from the MegaPlan:

  1. Lock RSN
  2. Bind public_context (sid = s1∥s2 + U + S + SSID + RSN snapshot)
  3. CPace Ya / Yb
  4. Checkpoint
  5. OQUAKE Init (1690) / Respond (1632)
  6. Derive keys → ready for 4-way

This is still a stub – real crypto will replace the placeholders later.
"""

from enum import Enum, auto
from typing import Optional, Tuple
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto.public_context import encode_public_context, PublicContextError
from crypto.cpace import cpace_initiator, cpace_responder, cpace_initiator_finish, CPaceError
from crypto.oquake import oquake_init, oquake_respond, oquake_initiator_finish, OQUAKEError


class State(Enum):
    START = auto()
    RSN_LOCKED = auto()
    CONTEXT_BOUND = auto()
    CPACE_INITIATED = auto()
    CPACE_DONE = auto()
    OQUAKE_INITIATED = auto()
    OQUAKE_DONE = auto()
    FINISHED = auto()
    FAILED = auto()


class PersonalHandshake:
    def __init__(self, is_initiator: bool = True):
        self.is_initiator = is_initiator
        self.state = State.START
        self.public_context: Optional[bytes] = None
        self.cpace_state = None
        self.oquake_state = None
        self.shared_secret: Optional[bytes] = None
        self.last_error: Optional[str] = None

    def lock_rsn_and_bind(
        self,
        sid: bytes,
        sta_mac: bytes,
        bssid: bytes,
        ssid: bytes,
        rsn_snapshot: bytes
    ) -> bool:
        """Step 1 + 2: Lock RSN and create public_context."""
        if self.state != State.START:
            self._fail("Cannot lock RSN in current state")
            return False

        try:
            self.public_context = encode_public_context(
                sid, sta_mac, bssid, ssid, rsn_snapshot
            )
            self.state = State.CONTEXT_BOUND
            return True
        except PublicContextError as e:
            self._fail(str(e))
            return False

    def start_cpace(self) -> Optional[bytes]:
        """Initiator creates Ya (32 bytes)."""
        if self.state != State.CONTEXT_BOUND or not self.is_initiator:
            self._fail("Cannot start CPace in current state")
            return None

        try:
            ya, self.cpace_state = cpace_initiator(self.public_context)
            self.state = State.CPACE_INITIATED
            return ya
        except CPaceError as e:
            self._fail(str(e))
            return None

    def process_cpace_ya(self, ya: bytes) -> Optional[bytes]:
        """Responder processes Ya and returns Yb."""
        if self.state != State.CONTEXT_BOUND or self.is_initiator:
            self._fail("Cannot process Ya in current state")
            return None

        try:
            yb, shared = cpace_responder(self.public_context, ya)
            self.shared_secret = shared
            self.state = State.CPACE_DONE
            return yb
        except CPaceError as e:
            self._fail(str(e))
            return None

    def finish_cpace(self, yb: bytes) -> bool:
        """Initiator finishes CPace after receiving Yb."""
        if self.state != State.CPACE_INITIATED or not self.is_initiator:
            self._fail("Cannot finish CPace in current state")
            return False

        try:
            self.shared_secret = cpace_initiator_finish(self.cpace_state, yb)
            self.state = State.CPACE_DONE
            return True
        except CPaceError as e:
            self._fail(str(e))
            return False

    def start_oquake(self) -> Optional[bytes]:
        """Initiator creates OQUAKE Init (1690 bytes)."""
        if self.state != State.CPACE_DONE or not self.is_initiator:
            self._fail("Cannot start OQUAKE in current state")
            return None

        try:
            init_msg, self.oquake_state = oquake_init(
                self.public_context, self.shared_secret
            )
            self.state = State.OQUAKE_INITIATED
            return init_msg
        except OQUAKEError as e:
            self._fail(str(e))
            return None

    def process_oquake_init(self, init_msg: bytes) -> Optional[bytes]:
        """Responder processes Init and returns Respond (1632 bytes)."""
        if self.state != State.CPACE_DONE or self.is_initiator:
            self._fail("Cannot process OQUAKE Init in current state")
            return None

        try:
            respond_msg, shared = oquake_respond(
                self.public_context, self.shared_secret, init_msg
            )
            self.shared_secret = shared
            self.state = State.OQUAKE_DONE
            return respond_msg
        except OQUAKEError as e:
            self._fail(str(e))
            return None

    def finish_oquake(self, respond_msg: bytes) -> bool:
        """Initiator finishes OQUAKE."""
        if self.state != State.OQUAKE_INITIATED or not self.is_initiator:
            self._fail("Cannot finish OQUAKE in current state")
            return False

        try:
            self.shared_secret = oquake_initiator_finish(
                self.oquake_state, respond_msg
            )
            self.state = State.OQUAKE_DONE
            return True
        except OQUAKEError as e:
            self._fail(str(e))
            return False

    def is_finished(self) -> bool:
        return self.state == State.OQUAKE_DONE

    def _fail(self, reason: str):
        self.state = State.FAILED
        self.last_error = reason
        print(f"[PersonalHandshake] FAILED: {reason}")


# ----------------------------------------------------------------------
# Very simple demo
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("Running Personal handshake stub demo...\n")

    # Fake inputs
    sid = b"s1s2-demo"
    sta = bytes.fromhex("001122334455")
    bssid = bytes.fromhex("aabbccddeeff")
    ssid = b"DemoNetwork"
    rsn = bytes.fromhex("30140100000fac040100000fac040100000fac02")

    # Create two sides
    sta_hs = PersonalHandshake(is_initiator=True)
    ap_hs = PersonalHandshake(is_initiator=False)

    # Both sides lock + bind
    assert sta_hs.lock_rsn_and_bind(sid, sta, bssid, ssid, rsn)
    assert ap_hs.lock_rsn_and_bind(sid, sta, bssid, ssid, rsn)
    print("✓ Both sides bound public_context")

    # CPace
    ya = sta_hs.start_cpace()
    yb = ap_hs.process_cpace_ya(ya)
    assert sta_hs.finish_cpace(yb)
    print("✓ CPace completed")

    # OQUAKE
    init_msg = sta_hs.start_oquake()
    respond_msg = ap_hs.process_oquake_init(init_msg)
    assert sta_hs.finish_oquake(respond_msg)
    print("✓ OQUAKE completed")

    print("\n✅ Personal handshake stub finished successfully")
    print(f"Final state (STA): {sta_hs.state}")
    print(f"Final state (AP) : {ap_hs.state}")