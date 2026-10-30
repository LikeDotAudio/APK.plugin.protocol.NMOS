# PLUGIN.NMOS architecture

Crate `apkaudio-nmos` (`SRC/`, a member of the `DISCOVERY.Engine/SRC` workspace): an mDNS browse
agent run as container `Plugin-NMOS`, and a unicast DNS-SD library used by the NMOS controller.

← [Manual and Artifacts](INDEX.md) · [Repo README](../../README.md)

## Use

```sh
cd PODS/POD.THICK/DISCOVERY.Engine/SRC
cargo test -p apkaudio-nmos                                           # 27 tests
cargo run -p apkaudio-nmos --example unicast_discover                 # resolv.conf search domains
cargo run -p apkaudio-nmos --example unicast_discover -- 127.0.0.1:5100 testsuite.nmos.tv
COMPOSE_PROFILES=discovery docker compose -f PODS/POD.THICK/PLUGINS/PLUGIN.NMOS/Docker/docker-compose.yml up -d
mosquitto_sub -t 'APK.audio/System/Protocols/nmos/Device/#' -v
```

## Files

| File | Role |
|---|---|
| `SRC/src/bin/apk-nmos.rs` | `apk_plugin_runner::main!(token = "nmos", run = [run_browse_agent])` |
| `SRC/src/lib.rs` | `run_browse_agent`, row building, `auth_label`, `summarise_versions` |
| `SRC/src/unicast.rs` | DNS message encode/parse, `Resolver` (UDP, TCP on TC), `browse`, `browse_host_domains`, `select_registry`, `query_api_url` |
| `SRC/src/unicast_tests.rs` | tests against a real loopback DNS socket |
| `SRC/src/self_test.rs` | module `nmos` self test |
| `SRC/examples/unicast_discover.rs` | the walk from a terminal; non-zero exit when nothing is found |
| `SRC/config.ini` | compiled in; `presence_protocols = nmos`, `presence_inactive_after_s = 0` |
| `SRC/gui/manifest.json`, `gui/nmos/nmos.json` | the `nmos` console family (tab `5_NMOS`, tree `7_Device_Consoles`) |

## mDNS browse flow (`run_browse_agent`)

1. One `mdns-sd` browse per service type in `NMOS_SERVICES`; every event goes into one channel.
2. `ServiceResolved` → merge into `services[host:port]` (role, instance, IPv4 addresses, TXT) →
   `presence::seen` → build 13 fields (`service role api_versions api_proto api_auth priority host
   port addresses mac vendor last_online online_since`) → `say` the changed ones under
   `APK.audio/System/Protocols/nmos/Device/{host}_{port}/`.
3. Every 30 s (`RESTATE`), every field still held is said again.
4. `ServiceRemoved` for the last instance at an endpoint → `presence::gone`, forget the row, clear
   its topics.

`mac` / `vendor` come from `LIB.MAC_LOOKUP` when an address is SLAAC IPv6.

## Unicast DNS-SD

`browse(resolver, "_nmos-query._tcp", domain)` walks PTR → SRV + TXT (+ A/AAAA) and returns
`ServiceInstance`s; `select_registry` applies BCP-002-01 (lowest `pri`, then SRV priority, then name;
`pri >= 100` excluded); `query_api_url` builds the URL. The caller is
`apkaudio_nmos_control::registry_agent::discover_query_base` (see PLUGIN.NMOS_CONTROL).
