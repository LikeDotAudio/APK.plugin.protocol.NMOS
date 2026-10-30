# APK:plugin:NMOS

NMOS — the mDNS browse agent, one container; and the unicast DNS-SD walk that finds a registry on another subnet.

| | |
|---|---|
| **Recipe** | `Docker/docker-compose.yml` — no Dockerfile: it runs a binary from the shared plugin image built by `PODS/POD.THICK/DISCOVERY.Engine/Docker/Dockerfile`, extending `plugin-host` in `DISCOVERY.Engine/Docker/plugin-base.yml` |
| **Source** | `SRC/` (this repository — https://github.com/LikeDotAudio/APK.plugin.protocol.NMOS.git) — crate `apkaudio-nmos`, a member of the `DISCOVERY.Engine/SRC` workspace; bin `apk-nmos` |
| **Container** | `Plugin-NMOS`, command `apk-nmos` |
| **Profile** | `discovery` |
| **Network** | host — mDNS does not cross a bridge |
| **Talks to** | the broker only (mDNS is listening, not talking to a device) |
| **Bus token** | `nmos` |

## What it does

`apk-nmos` is `apk_plugin_runner::main!(token = "nmos", run = [run_browse_agent])`
(`src/bin/apk-nmos.rs`). `run_browse_agent` (`src/lib.rs`) browses five mDNS
service types on `local.` and publishes one row per **host:port**:

| Service | Role |
|---|---|
| `_nmos-node._tcp` | Node |
| `_nmos-query._tcp` | Query |
| `_nmos-register._tcp` / `_nmos-registration._tcp` | Registration (one service under its new and legacy names, merged) |
| `_nmos-system._tcp` | System (IS-09) |

Two Node APIs on one host stay two rows; the two Registration names on one port
merge. `api_auth` gets its own column: `required`, `NONE`, or `?` when the TXT
record does not say. `mac` and `vendor` are recovered from a SLAAC IPv6
address through `LIB.MAC_LOOKUP`, and are `-` otherwise.

**Discovery only, by design.** Nothing here registers, enumerates or connects.
The IS-04 registry walk and the IS-05 client are the sibling
`APK:plugin:NMOS_CONTROL`; the two meet only in the `nmos` bus table, where
`role` separates their rows.

`src/unicast.rs` is the second transport: the same PTR/SRV/TXT walk asked of a
**named DNS resolver** for `_nmos-query._tcp.<domain>` (the AMWA `IS-04-04
test_01` case). It builds a Query API URL and opens no HTTP. Today it is reached
only from `examples/unicast_discover.rs`, not from the running agent.

## Topics

```
APK.audio/System/Protocols/nmos/Device/{host}_{port}/{key}   ← retained, QoS 1, written on change
  key ∈ service role api_versions api_proto api_auth priority host port
        addresses mac vendor last_online online_since
```

Presence is the runner's: `presence_protocols = nmos`,
`presence_inactive_after_s = 0` (departures only — mdns-sd resolves a steady
node again only when its record changes, and removes it on a goodbye or lapsed
TTL). The runner also publishes the retained config at
`APK.audio/System/Protocols/nmos/config`, `incoming/state` / `telemetry` /
`api`, and the self test (`src/self_test.rs`).

## Configuration

`SRC/config.ini`, section `[nmos]`: `enabled`, the two presence keys above, and
`domain = local.` — which no code reads: the browse names `local.` in
`NMOS_SERVICES`, and `unicast.rs` takes its domains from `/etc/resolv.conf`. The broker is `MQTT_HOST` / `MQTT_PORT` from the runner.
`SRC/gui/manifest.json` declares the `nmos` console family (tab `5_NMOS`, tree
`7_Device_Consoles`) and `SRC/gui/nmos/nmos.json` is its panel.

## Build, run, test

```sh
# from PODS/POD.THICK/DISCOVERY.Engine/SRC
cargo test -p apkaudio-nmos                                  # 26 tests (2026-10-30)
cargo run -p apkaudio-nmos --example unicast_discover        # every search domain in /etc/resolv.conf
cargo run -p apkaudio-nmos --example unicast_discover -- 127.0.0.1:5100 testsuite.nmos.tv

COMPOSE_PROFILES=discovery docker compose -f PODS/POD.THICK/PLUGINS/PLUGIN.NMOS/Docker/docker-compose.yml up -d --build
```

`apk-nmos` takes no arguments — `--help` starts the agent against the broker.

## Philosophy

- **Discovery only, and the boundary is a contract.** This crate finds; the
  controller crate calls APIs. `unicast.rs` lives here, not in the controller,
  because a DNS walk is discovery (`src/lib.rs` and `src/unicast.rs` headers).
- **Group by what is really one thing.** Rows key on host:port, which keeps two
  nodes on one host apart and merges one registry under two names
  (`src/lib.rs`, "Grouping").
- **Refusal over fabrication.** An absent `api_auth` is `?`, not `false` — a
  registry that never said is not declared open (`auth_label`); a host with a
  privacy address gets `-`, not a guessed MAC.
- **An explicitly supplied Query URL always wins** over a resolved one;
  discovery is a fallback (`src/unicast.rs`, "Precedence").
- **No half-implemented security.** No DNSSEC validation rather than one that
  accepts everything (`src/unicast.rs`).
- **Quiet when nothing changed.** A re-resolve that changes nothing writes
  nothing and prints nothing (`published` map in `run_browse_agent`).
- **Topics from the shared contract.** Host segments go through
  `apkaudio_contracts::topics::sanitize_segment`; presence through
  `apk_plugin_runner::presence`.

Against the doctrine: the device rows are **retained and never cleared** when a
node stops advertising — only the presence document goes inactive. A reader
must take liveness from presence, not from the row being there. Its siblings
PRINTERS, PTP and RAVENNA publish with the retain flag clear instead.

---

*© 2026 — Written & Maintained by Anthony P. Kuzub. MIT Licence.*
