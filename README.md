# APK:plugin:NMOS

NMOS — the mDNS browse agent, one container.

| | |
|---|---|
| **Recipe** | `Docker/docker-compose.yml` — no Dockerfile: it runs a binary from the shared plugin image built by `APK:plugins:Build` |
| **Source** | `SRC/` (this repository — https://github.com/LikeDotAudio/APK.plugin.protocol.NMOS.git) — bin `apk-nmos`, the mDNS browse agent; built by the shared plugin image |
| **Profile** | `discovery` |
| **Talks to** | the broker only |

A thread in `workers/discovery.rs`. Finds the NMOS APIs on the LAN and publishes them under the bus token `nmos`. Audit §10.2 grouped it with the IS-04 registry agent (one finding at two depths, one table), and PLAN-3316.01 first gave the pair one container; they share nothing in memory, so the registry agent is now its own stack, `APK:plugin:NMOS_CONTROL`, and the two meet only in the bus table, `role` separating their rows. Host networking: mDNS does not cross a bridge.

---

*© 2026 — Written & Maintained by Anthony P. Kuzub. MIT Licence.*
