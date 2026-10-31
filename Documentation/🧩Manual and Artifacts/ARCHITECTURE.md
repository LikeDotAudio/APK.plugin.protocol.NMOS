# PLUGIN.NMOS architecture

Crate `apkaudio-nmos` (`SRC/`, a member of the `DISCOVERY.Engine/SRC` workspace): an mDNS browse
agent run as container `Plugin-NMOS`, and a unicast DNS-SD library used by the NMOS controller.

← [Manual and Artifacts](INDEX.md) · [Repo README](../../README.md)

## Use

```sh
cd PODS/POD.THICK/DISCOVERY.Engine/SRC
cargo test -p apkaudio-nmos                                           # 31 tests
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
| `SRC/config.ini` | compiled in; `presence_protocols = nmos`, `presence_inactive_after_s = 0`, `restate_s = 30` (`Settings::from_ini`) |
| `SRC/gui/manifest.json`, `gui/nmos/nmos.json` | the `nmos` console family (tab `5_NMOS`, tree `7_Device_Consoles`) |

## mDNS browse flow (`run_browse_agent`)

1. One `mdns-sd` browse per service type in `NMOS_SERVICES`; every event goes into one channel.
0. The bus session is the runner's: `Session::new("nmos", "browse").spawn_drained()` (unique client
   id per node and process, credentials, backoff). Every publish is `apk_plugin_runner::unkept`'s
   `say` / `restate` / `forget` — the QoS/retain policy is not decided in this crate.
1. `until_started(ServiceDaemon::new, …)` — a daemon that cannot start is said `unavailable` and
   retried every `restate_s`, never returned on.
2. `ServiceResolved` → `NmosService::absorb` into `services[host:port]` (role, instance, IPv4
   addresses, TXT) → `presence::seen` → `NmosService::row` builds the 13 leaves (`service role
   api_versions api_proto api_auth priority host port addresses mac vendor last_online
   online_since`, never empty) → `say` the changed ones under
   `APK.audio/System/Protocols/nmos/Device/{host}_{port}/` (`topics::protocols`).
3. Every `restate_s` (config.ini, 30 s), every field still held is said again (`unkept::restate`).
4. `ServiceRemoved` for the last instance at an endpoint → `presence::gone`, forget the row,
   `unkept::forget` each of `row_topics(prefix)`.

The row contract is held by tests on the builder itself, not on the source text:
`the_row_is_exactly_the_published_leaves` (fixture registry → exact topic set and values) and
`a_departure_clears_exactly_the_row`.

`mac` / `vendor` come from `LIB.MAC_LOOKUP` when an address is SLAAC IPv6.

## Unicast DNS-SD

`browse(resolver, "_nmos-query._tcp", domain)` walks PTR → SRV + TXT (+ A/AAAA) and returns
`ServiceInstance`s; `select_registry` applies BCP-002-01 (lowest `pri`, then SRV priority, then name;
`pri >= 100` excluded); `query_api_url` builds the URL. The caller is
`apkaudio_nmos_control::registry_agent::discover_query_base` (see PLUGIN.NMOS_CONTROL).
