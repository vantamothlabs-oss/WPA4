\# WPA4 Experimental Reference



\*\*This is an experimental, non-interoperable open-source implementation of the WPA4 MegaPlan.\*\*



> ⚠️ \*\*Important\*\*  

> - This is \*\*NOT\*\* a Wi-Fi Alliance certified standard  

> - This is \*\*NOT\*\* ready for production networks  

> - This is \*\*NOT\*\* interoperable with real WPA3 or future official WPA4 devices  

> - It currently uses temporary Vendor Specific (221) elements only



\## What is this project?



VantaMoth Labs is building a clean, open, post-quantum oriented successor to WPA3 (called WPA4 in this design).  

The goal is to remove classic public-key AKMs (especially SAE-ECC) from a pure WPA4 BSS and use modern constructions (CPace + OQUAKE / ML-KEM-1024, etc.).



This repository contains:

\- The locked design documents (MegaPlan)

\- Reference encoder/decoder for experimental IEs

\- public\_context binding implementation

\- Basic userspace test harness



\## Repository Layout



| Folder         | Purpose                                              |

|----------------|------------------------------------------------------|

| `spec/`        | Locked MegaPlan, policy, and security handoff        |

| `encoding/`    | Experimental Vendor IE encoder/decoder               |

| `crypto/`      | public\_context and future crypto primitives          |

| `handshake/`   | Four independent state machines (coming soon)        |

| `harness/`     | Userspace tests                                      |

| `integration/` | Future hostapd / wpa\_supplicant patches              |

| `docs/`        | Engineering notes                                    |



\## Current Status



\- \[x] Repository structure

\- \[x] MegaPlan documents

\- \[x] Experimental 221 IE encoder/decoder

\- \[x] public\_context binding (lock-then-bind-then-Ya)

\- \[x] Basic userspace tests

\- \[ ] CPace / OQUAKE implementation

\- \[ ] Full handshake state machines

\- \[ ] Extended Length support

\- \[ ] hostapd integration



\## How to run the current tests



```bash

python harness/run\_basic\_tests.py

