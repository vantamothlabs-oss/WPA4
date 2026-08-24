\# WPA4 Experimental Reference



\*\*This is an experimental, non-interoperable open-source implementation of the WPA4 MegaPlan.\*\*



\- It is \*\*NOT\*\* a Wi-Fi Alliance certified standard  

\- It is \*\*NOT\*\* ready for production networks  

\- It is \*\*NOT\*\* interoperable with real WPA3 or future official WPA4 devices  

\- It currently uses temporary Vendor Specific (221) elements only



\## Repository Layout



| Folder         | Purpose                                              |

|----------------|------------------------------------------------------|

| `spec/`        | Locked MegaPlan, policy, and security handoff        |

| `encoding/`    | Experimental Vendor IE encoder/decoder               |

| `crypto/`      | CPace, OQUAKE, ML-KEM, public\_context                |

| `handshake/`   | Four independent state machines                      |

| `harness/`     | Userspace tests and known-answer vectors             |

| `integration/` | Experimental hostapd / wpa\_supplicant patches        |

| `docs/`        | Engineering notes and security sketch                |



\## Status

Userspace reference + harness only. No radio testing yet.

