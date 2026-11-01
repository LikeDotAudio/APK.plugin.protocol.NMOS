# PLUGIN.NMOS delivery

← [Publishing](INDEX.md) · [Repo README](../../README.md)

## Built

No Dockerfile here. `apk-nmos` is compiled into the shared plugin image `apk-plugins:local` from the
`DISCOVERY.Engine/SRC` workspace:

```sh
docker build -f PODS/POD.THICK/DISCOVERY.Engine/Docker/Dockerfile --target plugins -t apk-plugins:local .
```

The same build links `apkaudio_nmos::unicast` into `apk-nmos-control` (PLUGIN.NMOS_CONTROL depends on
this crate by path).

## Tested

By hand: `cargo test -p apkaudio-nmos` (32 tests; the unicast ones use a loopback DNS socket). The
runner answers `outgoing/selftest_run` for module `nmos`. The AMWA suite
(`PODS/POD.protocols/PROTOCOL.discovery.NMOS`) grades the controller, not this agent.

## Shipped

`Docker/docker-compose.yml` extends `plugin-host` (host networking — mDNS does not cross a bridge)
and is `include:`d into compose project `apk-audio`; `Plugin-NMOS` starts on nodes whose roles
include `discovery`. DockTor's `PODS/POD.manager/MANAGER.Docktor/K8/up-stack.sh` rebuilds one stack.
Rows land on the broker; each device presents its own `SRC/gui/nmos` panel, retained at `APK.audio/System/Gui/Panels/nmos-<device>` (`panels = [nmos]`). No live URL of its own.

## Not automated

* CI: `.github/workflows/ci.yml` calls the SDK's `plugin-ci.yml@sdk-v0.9` (pinned to the same tag as the code).
* No registry: the image is built on each node.

## Delivered from the 2026-10-30 audit

Part of the shared plugin image (`apk-plugins:local`, container `Plugin-NMOS`).

- **Row contract test replaces the source greps** — `nothing_the_browse_agent_says_is_kept` and `mdns_failure_is_retried_not_returned` no longer slice `include_str!("lib.rs")`. The row is built by `NmosService::absorb` + `NmosService::row` (pure), and `the_row_is_exactly_the_published_leaves` drives a fixture registry (two names, loopback/link-local dropped, TXT re-advertised empty) and asserts the exact 13 topics and values under `Device/nmos-cpp_local_3210/`; `a_departure_clears_exactly_the_row` holds that no value is empty and the departure clears exactly those topics; the daemon retry is `until_started`, tested with two driven refusals. `cargo test -p apkaudio-nmos` 31 passed.
- **Device topics by the contract** — already `topics::protocols("nmos", ["Device", …])` in `device_prefix()` (c90644f); every row leaf is now built from that prefix by `NmosService::row` / `row_topics`. Verified by `the_device_prefix_is_built_by_the_contract` and the row test (each topic parses as `ParsedTopic::Protocols`).
- **Bus client from the runner** — the hand-built `rumqttc::MqttOptions("apkaudio-nmos")` + credentials + drain thread is `Session::new("nmos", "browse").capacity(32).spawn_drained()` (client id unique per node and process — the fixed id kicked a second node's agent off a shared broker); the local `say` and the raw retained clear are `apk_plugin_runner::unkept::{say, restate, forget}`, agent state via `publications_of`. Workspace build clean (no warnings). Standalone build needs the next SDK tag (publishing tags = needs owner).
- **Identity is host:port** — Kept by design: the key is the mDNS host name + port the endpoint advertises (not an IP); the IS-04 `self` id needs an HTTP GET this discovery-only crate must not make (NMOS_CONTROL keys on the IS-04 device UUID), and a SLAAC-recovered MAC is absent on privacy hosts and could re-key a live row. Written in PRINCIPLES.md.
- **Cross-repo build files** — Kept by design: `extends: …/DISCOVERY.Engine/Docker/plugin-base.yml` and the `members/` symlink are the house plugin pattern (PRINCIPLES.md "Where the code bends a rule"). The compose's copied volume block is now `include: …/plugin-volumes.yml`; `docker compose config` is byte-identical before/after. Standalone CI of the include needs the next SDK tag.
- **README Configuration drift** — already fixed: README says there is no `domain` key, matching `SRC/config.ini`.
- **CI pinned to the SDK tag** — `ci.yml` uses `plugin-ci.yml@sdk-v0.5` (was `@main`).
- **Row schema from the contract** (contracts 7763d73b6, follow-up to PLUGIN.NMOS_CONTROL's shared-table item) — the local `DEVICE_KEYS` is `apkaudio_contracts::nmos_rows::ENDPOINT_KEYS`, and `device_prefix` is `nmos_rows::device_prefix(&nmos_rows::endpoint_id(host, port))`; `the_row_is_a_contract_nmos_row` holds every role this agent writes to `nmos_rows::row_problems` (vectors `contracts/vectors/nmos_rows.json`). `cargo test -p apkaudio-nmos` 32 passed. Standalone build needs the next SDK tag.
- **LIB.MAC_LOOKUP pinned by tag** (owner-authorised tag wave, 2026-10-31) — `apkaudio-maclookup` repinned from `rev = "7ba39dd…"` to `tag = "maclookup-v0.2.0"` (b670f2c), beside the SDK at `sdk-v0.6`; the engine `[patch]`/`members/` design is unchanged. A standalone build now gets the multi-writer cache and `Mac` as well as the runner `Session`/`unkept` this crate adopted: verified by copying the crate alone (no `.cargo` patch, no lock) and running `cargo test` against GitHub — passes, as does the workspace `cargo test -p`.
- **SDK repinned to `sdk-v0.7`** (172e12c) — `SRC/Cargo.toml` takes the runner and contracts, and `.github/workflows/ci.yml` calls `plugin-ci.yml`, at the same tag; it ships `docker/plugin-volumes.yml`, so plugin CI's standalone compose check resolves. Verified 2026-10-31: `git archive HEAD` alone, `cargo test` against GitHub — 32 pass; plugin-ci's compose step reproduced (`plugin-base.yml` + `plugin-volumes.yml` from `sdk-v0.7`, `docker compose config -q`) passes.
- **SDK `sdk-v0.9`, MAC_LOOKUP `maclookup-v0.3.0`, crate 0.2.0** (PLAN-3432.01) — `SRC/Cargo.toml` takes the runner and contracts at `sdk-v0.9` and `apkaudio-maclookup` at `tag = "maclookup-v0.3.0"` (cut on `sdk-v0.9`), so a standalone lock holds one `apkaudio-contracts`; `ci.yml` calls `plugin-ci.yml@sdk-v0.9`; `apkaudio-nmos` 0.1.0 → 0.2.0. PLUGIN.NMOS_CONTROL pins this commit by full `rev` (it pinned af623bc, which still built on `sdk-v0.1`). Verified 2026-10-31: the tree alone (`git archive`, no `.cargo` patch), `cargo test` against GitHub — 32 pass.

## Releases
- **Released `2.0.0`, tag `v2.0.0`** (2026-11-01, ROAD-3452, the owner's V2) — on `sdk-v2.0` (contracts 2.0.0); every manifest says 2.0.0; GitHub release `v2.0.0`.
