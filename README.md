<p align="center">
  <img src="docs/assets/yuuko-protocol.png" alt="Yuuko Protocol" />
</p>

<p align="center">
  <strong>A Five Stage Protocol Handling Decentralized Sync and Communication</strong>
</p>

<p align="center">
Yuuko Protocol is a decentralized protocol created for the XRUIOS; it uses "The Holy Mother", an orchestrator, to handle a multitude of datastreams like files, realtime data, messages and even videos alongside syncing.
</p>

<p align="center">
<strong>Cross Platform • Internet, Wifi Direct or Wired • Post Quantum Computing Resistant • No BS</strong>
</p>


<p align="center">
  <a href="https://walker-industries-rnd.github.io/YuukoProtocol/1-welcome" 
     style="font-size: 1.4em; color: #58a6ff; text-decoration: none;">
    <strong>Documentation • Examples • API Reference</strong>
  </a>
</p>


---

## Core Features

- "The Holy Mother" lists, starts and stops apps on other devices and shares their icons; creating and managing application streams automatically is next
- Nintendo Streetpass style communication between devices, minimal bandwidth and high count support: **The Cogitarium**. Made for the SCCN: signed streams passed along a mesh of nearby devices, strangers and all
- WebRTC + Facade (WIP) Based Interaction And Video Streaming (planned)
- Event Sourcing - Trust and Permissions (planned; the signed, tamper-evident audit log is the simple version and is built
- CRDT System - Realtime UI and States (built, any size and any number of documents
- Git Style System - File and Assets (built, any number of files and any size, and it carries on where it stopped
- AES-256-GCM for request/response payloads
- Hard for third-party processes to inject or read traffic
- Designed for local-first scenarios (desktop apps ↔ local LLMs ↔ tools ↔ services)
- No central server required beyond the machine itself


---

## Meet the Team

<div align="center">

| ![john](docs/assets/database_john_default.png) | ![walker](docs/assets/database_walker_default.png) | ![antwan](docs/assets/antwan.png) |
| --- | --- | --- |
| **Jpena173**<br>Backend Support / Development Help<br>[GitHub](https://github.com/jpena173)<br><br>"I cant think of a quote you can leave it alone for now" | **WalkerDev**<br>Founder / Lead Developer<br><br>“Don't be afraid of change—Think of it as something that'll open the door to deeper, more precious feelings for you in the future.”<br>[YouTube](https://www.youtube.com/@walkerdev1) | **Tʜᴇ Rᴇᴀʟ ANTWAN**<br> Artist<br><br>"Time is something no one can escape. It delivers us all to the same end. You can't plug your eyes or cover your eyes."<br> |

</div>

---

### Measured performance (in-process; excludes network)

| Metric                                    | Result                 |
| ----------------------------------------- | ---------------------- |
| Post-quantum handshake + first request    | ~5 ms/peer (one-time)  |
| Warm request round-trip (serial)          | ~40 µs → ~24,700 req/s |
| Throughput (concurrent, 8–32 lanes)       | ~35–36k req/s          |
| Command carrying 1 MB, echoed back        | ~21 ms                 |
| Edit on one device until the other has it | ~2.6 ms                |
| Raw AES-256-GCM enc+dec (64 KB)           | ~233 µs/op → ~280 MB/s |

## Requirements

- The .NET 8 SDK
- [Pariah Cybersecurity](https://github.com/Walker-Industries-RnD/PariahCybersecurity), which is free and open source on our Github. Its DLL and the Eclipse ones it works with are in the `libs` folder of the repo, so there is nothing to install
- Zenoh's native library, which the build downloads for you the first time (about 15 MB)

[Secure Store](https://github.com/Walker-Industries-RnD/Secure-Store/tree/main) is no longer needed.

Check these out!

[The XRUIOS; the project this was made for! ](https://xruios.xyz/)

## Stages

- [x] Zenoh C# Based API Created
- [x] Eclipse-Secured Handshake + Per-Peer Encrypted Sessions (Kyber-1024 + Dilithium5 + AES-256-GCM)
- [x] Multiplexed Lanes (parallel encrypted requests per peer)
- [x] Connected Endpoints Handler
- [x] CRDT Handler (any size, any number)
- [x] Operational Transformation Handler
- [x] Event Sourcing Handler (the audit log, signed and kept by other devices, is the simple version)
- [x] Git Style DAG + Keeper Of Tomes (any number of files, any size, carries on where it stopped)
- [x] Service Handler (The Holy Mother: apps)
- [x] P2P Mesh (Secure): the Cogitarium, strangers with `Nearby`, and paired devices find each other again with `Reconnect`
- [x] Signed, tamper-evident Audit Log that other devices keep the head of




## Security (Implemented)

- **Pairing** → one device shows a code (its address, a one-time token and a temporary certificate), the other types it, and each pins the other's keys
- **Handshake** → Kyber-1024 key exchange with a throw-away key for every handshake (so a stolen identity can't open an old recording), the provider proves who it is by signing the whole exchange with Dilithium5, and the group key is mixed in the group key
- **Session** → AES-256-GCM + per-message nonces, replaced after an hour
- **Link** → TLS 1.3 with certificates both ways under all of it 
- **Everything saved** → encrypted (identity file, device list, reconnect file), and a wrong password or a damaged file is an error, never a quiet fresh start
- Designed to resist classical & quantum adversaries (where Kyber helps)


---


## License & Artwork

**Code**  
[NON-AI MPL 2.0](https://raw.githubusercontent.com/non-ai-licenses/non-ai-licenses/main/NON-AI-MPL-2.0)

This software is licensed under MPL 2.0 **with the following exception**:

**Artwork**  
© Its a ANTWAN — **NO AI training. NO reproduction. NO exceptions.**

<img src="https://github.com/Walker-Industries-RnD/Malicious-Affiliation-Ban/blob/main/WIBan.png?raw=true" align="center" style="margin-left: 20px; margin-bottom: 20px;"/>

> Unauthorized use of the artwork — including copying, distribution, modification, or inclusion in any machine-learning training dataset — is strictly prohibited and will be prosecuted to the fullest extent of the law.
