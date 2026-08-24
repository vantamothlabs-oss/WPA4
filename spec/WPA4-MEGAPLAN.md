# WPA4 MegaPlan

Think Tank plan to *create* WPA4. Not an Alliance cert. Not 802.11bt. Not a shipping stack.

Punchline: WPA4 means SAE-ECC is off the air. Dual-mode that still offers WPA3-SAE keeps the WPA3 name. It is a cert we want the Alliance to hang on 802.11bt, not a quantum radio.

## What this is

A design we own. We ride TGbt where it already moved (Extended Length, 11-26/1448r1). We do not mint `00-0F-AC:N`, Element IDs, or capability bits. Creating the family is the work. Refusing classic public-key AKMs *in a WPA4 IE* is how the name stays honest — not a ban on inventing.

## Family (one parameterized set, numbers TBD by IEEE)

|Role|Construction|KEM|Notes|
|-|-|-|-|
|Personal|sequential CPace → OQUAKE|ML-BUA-sKEM-1024 (KemeleonNR+Tempo)|SAE-PK is an *option* (ML-DSA-87), not a row|
|FT-Personal|same PAKE + FT|same|not a second selector|
|Enterprise|EAP-TLS 1.3 + ML-DSA-87|raw ML-KEM-1024|no PEAP/MSCHAPv2|
|FT-Enterprise|same EAP + FT|same||
|FILS|PQC-FILS|(11bt)|FT-FILS is a FILS *parameter*|
|OWE|raw ML-KEM-1024 hybrid|1568|no Kemeleon, no Tempo, no X-Wing|
|PASN|raw ML-KEM-1024 hybrid|1568|KEY-WRAP is a PASN *parameter*|

X-Wing stays Cat 3 and only wraps aPAKE confirmation.

A WPA4 BSS advertises only this family. Classic 1/2/3/4/5/8/9/12–26 stay on a WPA3 SSID if you still need them.

## Handshake (Personal)

2+2 *messages*, then the 4-way (not folded into the Auth count).

* CPace Ya / Yb: 32 B on RIST255, classic 1-octet IE
* OQUAKE Init: Information = 1690 (`s||T||ρ` = 96+1562+32)
* OQUAKE Respond: Information = 1632 (`ct||h` = 1568+64)
* Finish is local
* 1594 is the Kemeleon pk *inside* Init, not an Auth length

RSN locks the row *before* Auth. Bind that row into CPace/OQUAKE `public\\\_context`. Do not discover the row from the blob. A Personal STA that accepts 1568 “because it fit OWE” is the confusion attack.

OWE/PASN/FT are different procedures. Do not paste 2+2 onto those rows.

## Encoding

Ride Extended Length Element (TGbt 11-26/1448r1):

`Element ID | Extended Length Element ID | Length (2 octets) | Information`

* Information is the CFRG/FIPS blob only. No kem-id+row prefix.
* Length must equal `len(Information)` and the already-chosen constant (1690 / 1632 / 1568).
* EID-Ext 165 (PQC Parameter) was *released* — do not reuse it.
* Element ID and Extended Length capability bit are blank until ANA fills them.
* A STA without the capability bit fail-closes.
* No FILS-style 7-piece aggregation. No MMPDU fragmentation of Auth.
* RFC 8110 one-octet DH length cannot encode 1568. Hard fail, not a fragment.

IEEE encode waits on ANA — that is the *badge*, not a project hold.

Vendor Specific (221) is a *sandbox harness tag* only. Its Length is still one octet (255) — 1690/1632/1568 still do not fit a legal 221 IE. A 2-octet length after 221 is our test wrapper, not an Auth element. Do not ship 221 as a production twin of Extended Length (second encoding = downgrade). Production emit stay off until ANA fills the Extended Length EID and the capability bit.

## Identity vs handshake

* Static identity (ML-DSA-87, FIPS 204 = 4627 B) rides ANQP over GAS *before* Auth. Four 1400-byte comebacks. Per-comeback retry, not whole-dialog redo.
* Live PAKE/KEM stays on Auth. Lost GAS fragment: retry that dialog, do not start Auth. Lost CPace: restart CPace. Lost OQUAKE: retry OQUAKE only (checkpoint after Ya/Yb).

## Cipher and threat model

* GCMP-256 required. Already on Wi-Fi 7. Hygiene, not the PQ claim.
* “Quantum-safe” means the AKM survives Shor. Not QKD, not a quantum PHY, not Grover-proof RF.
* Cafe WPA3-Personal SAE is *not* harvest-now (Dragonfly base is the password element). Real HNDL on the air is OWE and EAP-TLS ECDHE. OWE is in the family for that reason.
* Grover on the password dictionary is a category error.
* Clock: NIST 2030 deprecate / 2035 disallow is a *window*, not an Alliance badge.

## Cert line (when IEEE/Alliance catch up)

These (still-unnumbered) AKMs + GCMP-256 + none of the classic public-key selectors in the IE.

Do not print: quantum-safe, HNDL-proof, Cat 5, “AES-256 is PQC.”

## Sandbox (what we actually ran)

Userspace only. No radio, no hwsim, no WPA4 stack.

* Loss model: independent frame loss; 2+2 Auth after GAS identity.
* RFC 8110 / exact-1568 fail-closed (no OWE emit).
* Extended Length draft parser: 1690/1632/1568; 1594 on Init fails; CPace 32 B; no emit while EID is blank.

## public\_context bind

CFRG: `public\\\_context = EncodePublicContext(sid, U, S)` plus app append. CPace uses it as sid; OQUAKE inherits via `secret\\\_context` = CPace ISK.

* U = STA MAC, S = BSSID
* Append SSID + the RSN IE snapshot that locked the row
* sid = per-association `s1∥s2` (already in CPaceOQUAKE). **Not** the SSID — SSID repeats and the proof drops
* Empty or late sid: fail-closed
* Procedure: lock-then-bind-then-Ya. Snapshot RSN at lock. A new Beacon mid-handshake fail-closes, not a rebind
* CPace checkpoint retries OQUAKE under the *same* `public\\\_context`
* If Beacon RSN ≠ bound RSN, keys don’t match. Do not parse the Auth blob to pick a row

## Open (keep going)

1. ANA Element ID + Extended Length capability bit (badge / production emit).
2. Sandbox keeps running userspace checks (harness may tag 221). That is not an encode.
3. hostapd/wpa\_supplicant production path only after (1).

## FILS and PASN (locked)

Three procedures. Do not paste Personal 2+2, 1690/1632, or `public\\\_context` onto roam.

* FILS: Assoc + Fragment 242, reassemble, then exact 1568. Replace the FILS KE (ECDH wrap), not just inner EAP-TLS. Lost piece retries FILS fragments, not a CPace checkpoint. FILS-SK without PFS has no KE — leave it blank.
* PASN: own frames + 1568 on Large Elements. KEY-WRAP is a parameter. Do not reuse 242.
* Same HNDL class as OWE (known-base KE). Cafe-SAE “not harvest-now” does not apply.
* A WPA4 FILS row that still offers the ECDH wrap is the same hole as SAE in the IE.

We do not stop at “draft.” We also do not pretend it encodes before ANA.

## FT roam (locked)

Fourth procedure. Not Personal-with-a-flag. Not a KEM.

* After a WPA4 initial: PMK-R0 → PMK-R1 → PTK is a symmetric KDF (Grover-taxed; GCMP-256 covers it)
* No 2+2, no 1568, no Extended Length, no Fragment 242. Over-the-DS is the same procedure
* R0 only from a WPA4 initial (Personal PAKE or PQ-EAP). SAE/PSK R0 is the SAE-in-the-IE hole on roam
* If R0KH→R1KH wrap is still ECDH, the air being PQ doesn’t matter
* Missing, expired, or wrong-row R0 fail-closes into a *new WPA4 initial* — never SAE, never “FT then 2+2” in one roam
* Bind the initial row into the R0. 802.11 already puts the AKM into PMK-R0Name — when the family is assigned, that *is* the lock. Don’t invent a second tag
* A Personal R0 does not roam as FT-Enterprise



