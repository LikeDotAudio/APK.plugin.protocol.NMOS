# 🔍 Architecture audit — PLUGIN.NMOS (2026-10-30)

Audited against the APK.audio multi-repo architecture standard: coupling, boundaries, duplication, contracts.
← [Audits](INDEX.md) · Improvements: [🛣Roadmap/IMPROVEMENTS.md](../%F0%9F%9B%A3Roadmap/IMPROVEMENTS.md)

## Bounded context
NMOS *discovery*: browse five `_nmos-*._tcp` mDNS services and publish one bus row per host:port; plus a unicast DNS-SD walk (`unicast.rs`) used by NMOS_CONTROL. Rust crate `apkaudio-nmos` (~2.3k lines in `SRC/src`), member of the `DISCOVERY.Engine/SRC` workspace via symlink; container `Plugin-NMOS`. Sampled: `Cargo.toml`, `config.ini`, `src/bin/apk-nmos.rs`, `src/lib.rs`, the headers of `unicast.rs`/`self_test.rs`, `gui/`, compose, CI; ran `cargo test -p apkaudio-nmos` (28 passed).

## Context map
| Talks to | How (topic / endpoint / file / import) | Relationship |
|---|---|---|
| APK.plugin.SDK (`apk-plugin-runner`, `apkaudio-contracts`) | git dependency `tag = "sdk-v0.5"`; `main!` macro, `presence`, `broker_auth`, `broker_backoff`, `topics::sanitize_segment` | Conformist to the SDK (Shared Kernel) |
| Bus consumers (DockTor, Device Consoles, NMOS_CONTROL) | `APK.audio/System/Protocols/nmos/Device/{host}_{port}/{key}` unkept, restated every 30 s; retained `…/nmos/config`, `incoming/api` etc. via runner | Supplier — Published Language |
| PLUGIN.NMOS_CONTROL | consumes `apkaudio-nmos` by `git … rev = af623bc…` for `unicast::*`; workspace `[patch]` points it back at the local path | Supplier (versioned crate) |
| LIB.MAC_LOOKUP (`apkaudio-maclookup`) | git dependency pinned by `rev` | Customer |
| DISCOVERY.Engine | compose `extends: ../../../DISCOVERY.Engine/Docker/plugin-base.yml`; binary built in its shared plugin image; crate built as workspace member `members/PLUGIN.NMOS -> ../../../PLUGINS/PLUGIN.NMOS/SRC` | Customer–Supplier (file-level) |
| DATABASE.volume.Log-STORAGE | declares the same `apk-audio-logs` bind volume | Shared state (deliberate) |
| Device panels | `gui/manifest.json` family `nmos`; `panels = [nmos]` → `Gui/Panels/nmos-<device>` | Published Language (house rule) |

## Scorecard
| Category | Score (0–3) | Finding |
|---|---|---|
| Coupling & Cohesion | 3 | Clear split with NMOS_CONTROL (meet only in the bus table) and a versioned crate edge; the compose/build reach into DISCOVERY.Engine is the recorded house pattern; CI pinned to `@sdk-v0.5`. |
| Boundary Integrity | 3 | `mdns-sd` is confined to `run_browse_agent`; the bus session is the runner's `Session` and every publish goes through `apk_plugin_runner::unkept`. |
| Duplication Control | 3 | Topics by `topics::protocols`; session, say/restate/forget and the shared volumes all come from the runner / plugin-volumes.yml. |
| Testing & Contracts | 3 | 32 tests incl. 18 unicast cases against the AMWA IS-04-04 shape; the row contract is tested on the builder (exact topics and values), the daemon retry on a driven refusal. |
| Change management | 3 | SDK pinned by tag (code and CI), deps by rev, the NMOS split and the retained→unkept change documented; README matches config.ini. |
Score key: 3 meets the standard · 2 minor gaps · 1 significant gaps · 0 absent / violated.

## Findings
1. **Good — bounded context is sharp.** Discovery only; registration/IS-05 is NMOS_CONTROL. `src/bin/apk-nmos.rs` header and `Cargo.toml` comments record why the two containers share nothing but the `nmos` table.
2. **Good — unreachable is dead.** Rows are QoS 0 unkept and restated every `restate_s`; the only retained publish is the empty `unkept::forget` of a departed row. A daemon that cannot start is reported unavailable and retried, not returned (`until_started`).
3. **Good — versioned crate edge.** NMOS_CONTROL depends on this crate by git `rev`, with a workspace `[patch]` (`DISCOVERY.Engine/SRC/Cargo.toml`) for local builds — the right shape for a cross-repo Rust dependency.

Findings 4–10 of the 2026-10-30 audit are delivered or recorded as kept by design — see [🌍Publishing/DELIVERY.md](../%F0%9F%8C%8DPublishing/DELIVERY.md).
