# WPA4 Experimental Reference

**This is an experimental, non-interoperable open-source implementation of the WPA4 MegaPlan.**

> ⚠️ **Important**  
> - This is **NOT** a Wi-Fi Alliance certified standard  
> - This is **NOT** ready for production networks  
> - This is **NOT** interoperable with real WPA3 or future official WPA4 devices  
> - It currently uses temporary Vendor Specific (221) elements only

## What is this project?

VantaMoth Labs is building a clean, open, post-quantum oriented successor to WPA3 (called WPA4 in this design).  
The goal is to remove classic public-key AKMs (especially SAE-ECC) from a pure WPA4 BSS and use modern constructions (CPace + OQUAKE / ML-KEM-1024, etc.).

This repository contains the locked design documents and working reference stubs for the core pieces.

## Repository Layout

| Folder         | Purpose                                              |
|----------------|------------------------------------------------------|
| `spec/`        | Locked MegaPlan, policy, and security handoff        |
| `encoding/`    | Experimental Vendor IE encoder/decoder               |
| `crypto/`      | public_context, CPace, OQUAKE, ML-KEM stubs          |
| `handshake/`   | Personal + KEM-based state machines                  |
| `harness/`     | Userspace tests                                      |
| `integration/` | Future hostapd / wpa_supplicant patches              |
| `docs/`        | Engineering notes                                    |

## Current Status

- [x] Repository structure
- [x] MegaPlan documents
- [x] Experimental 221 IE encoder/decoder
- [x] public_context binding (lock-then-bind-then-Ya)
- [x] CPace stub (32-byte Ya/Yb)
- [x] OQUAKE stub (1690 Init / 1632 Respond)
- [x] ML-KEM-1024 size stub (1568 bytes)
- [x] Personal handshake state machine
- [x] KEM-based handshake state machine (OWE / PASN / FILS)
- [x] Comprehensive userspace test harness
- [ ] Real cryptographic implementations
- [ ] Extended Length support
- [ ] hostapd / wpa_supplicant integration
- [ ] FT (Fast Transition) support

## How to run the tests

```bash
python harness/run_basic_tests.py
