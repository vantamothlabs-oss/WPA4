#!/usr/bin/env python3
"""
WPA4 KEM-based handshake stub (OWE / PASN / FILS)
-------------------------------------------------
These procedures use raw ML-KEM-1024 (exactly 1568 bytes).
They do NOT use CPace or OQUAKE.

This is a minimal state machine stub so we can later specialize
it for OWE, PASN, and FILS.
"""

from enum import Enum, auto
from typing import Optional
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto.mlkem import mlkem_encaps, mlkem_decaps, MLKEMError, MLKEM_SIZE


class State(Enum):
    START = auto()
    ENCAPSULATED = auto()
    FINISHED = auto()
    FAILED = auto()


class KEMBasedHandshake:
    def __init__(self, is_initiator: bool = True):
        self.is_initiator = is_initiator
        self.state = State.START
        self.shared_secret: Optional[bytes] = None
        self.last_error: Optional[str] = None

    def start(self) -> Optional[bytes]:
        """
        Initiator creates the 1568-byte ML-KEM ciphertext.
        """
        if self.state != State.START or not self.is_initiator:
            self._fail("Cannot start in current state")
            return None

        try:
            ciphertext, self.shared_secret = mlkem_encaps()
            self.state = State.ENCAPSULATED
            return ciphertext
        except MLKEMError as e:
            self._fail(str(e))
            return None

    def process(self, ciphertext: bytes) -> bool:
        """
        Responder processes the 1568-byte ciphertext.
        """
        if self.state != State.START or self.is_initiator:
            self._fail("Cannot process in current state")
            return False

        try:
            self.shared_secret = mlkem_decaps(ciphertext)
            self.state = State.FINISHED
            return True
        except MLKEMError as e:
            self._fail(str(e))
            return False

    def finish(self) -> bool:
        """
        Initiator marks the handshake as finished after sending the ciphertext.
        (In a real protocol more confirmation may be needed.)
        """
        if self.state != State.ENCAPSULATED or not self.is_initiator:
            self._fail("Cannot finish in current state")
            return False

        self.state = State.FINISHED
        return True

    def is_finished(self) -> bool:
        return self.state == State.FINISHED

    def _fail(self, reason: str):
        self.state = State.FAILED
        self.last_error = reason
        print(f"[KEMBasedHandshake] FAILED: {reason}")


# ----------------------------------------------------------------------
# Simple demo
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("Running KEM-based handshake stub demo (OWE/PASN/FILS)...\n")

    initiator = KEMBasedHandshake(is_initiator=True)
    responder = KEMBasedHandshake(is_initiator=False)

    ct = initiator.start()
    assert ct is not None and len(ct) == MLKEM_SIZE
    print(f"✓ Initiator created {len(ct)}-byte ciphertext")

    assert responder.process(ct)
    print("✓ Responder processed ciphertext")

    assert initiator.finish()
    print("✓ Initiator finished")

    assert initiator.is_finished() and responder.is_finished()
    print("\n✅ KEM-based handshake stub completed successfully")